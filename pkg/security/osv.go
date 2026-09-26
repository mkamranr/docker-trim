package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
)

// Vulnerability data from OSV (https://osv.dev).
//
// This is opt-in behind --osv for two reasons. It is the only part of docker-trim
// that sends anything anywhere: the query carries the name and version of every
// package in the image, which describes that image fairly precisely. And it
// means a report can differ between two runs for reasons that have nothing to
// do with the Dockerfile, which is worth knowing before wiring it into a gate.

// osvEndpoint is a variable rather than a constant so tests can point it at a
// local server: a test suite that depends on a third party's availability
// fails for reasons that have nothing to do with the code.
var (
	osvEndpoint      = "https://api.osv.dev/v1/query"
	osvBatchEndpoint = "https://api.osv.dev/v1/querybatch"
)

const (
	// osvConcurrency is how many queries are in flight at once. OSV is a free
	// public service; this is fast enough for a few hundred packages while
	// staying a considerate client.
	osvConcurrency = 6
	// osvMaxPackages caps a single run. With language dependencies included an
	// image routinely carries hundreds, so this is generous; the batch triage
	// below is what keeps the request count small rather than the cap.
	osvMaxPackages = 5000
	// osvBatchSize is how many packages one querybatch request covers. The API
	// accepts a thousand.
	osvBatchSize = 1000
	// osvUserAgent identifies docker-trim to a free public service.
	osvUserAgent = "docker-trim (https://github.com/mkamranr/docker-trim)"
)

// Vulnerability is one known problem with an installed package.
type Vulnerability struct {
	ID        string  `json:"id"`
	Package   string  `json:"package"`
	Version   string  `json:"version"`
	Ecosystem string  `json:"ecosystem"`
	Severity  string  `json:"severity"`
	Score     float64 `json:"score,omitempty"`
	// ScoreKnown is false when the advisory carried no CVSS vector this could
	// read, in which case Severity is "unknown" rather than a guess.
	ScoreKnown bool   `json:"scoreKnown"`
	Summary    string `json:"summary,omitempty"`
}

// EcosystemReport is what OSV said about one ecosystem within an image.
//
// They are kept apart because conflating them hides the thing that matters: a
// handful of unreachable advisories in a slim base image reads very differently
// from the same number in the application's own dependency tree.
type EcosystemReport struct {
	Ecosystem string `json:"ecosystem"`
	Queried   int    `json:"queried"`
	Total     int    `json:"total"`
	// Roots are the directories the packages were installed into, for a
	// language ecosystem. It is what separates an application's dependencies
	// from the ones its base image happens to ship.
	Roots map[string]int `json:"roots,omitempty"`
}

// VulnerabilityReport is what OSV said about an image.
type VulnerabilityReport struct {
	// Ecosystems is the per-ecosystem breakdown, largest first.
	Ecosystems []EcosystemReport `json:"ecosystems"`
	// Total is the number of distinct advisories affecting this image.
	Total int `json:"total"`
	// BySeverity counts advisories in each band.
	BySeverity map[string]int `json:"bySeverity"`
	// Vulnerabilities is the full list, worst first.
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	// Queried is how many packages were looked up.
	Queried int `json:"queried"`
	// Notes record anything that limits the result.
	Notes []string `json:"notes,omitempty"`
}

// OSVEcosystem maps an image's operating system onto the name OSV uses.
//
// Getting this wrong returns an empty result rather than an error, which would
// look exactly like a clean image. That is the failure worth guarding against
// here, so an unrecognised system is reported instead of queried.
func OSVEcosystem(rep *analyzer.ImageReport) (string, error) {
	id, version := rep.OSID, rep.OSVersionID
	if id == "" {
		return "", fmt.Errorf("the image does not identify its operating system, so its " +
			"packages cannot be looked up")
	}
	switch id {
	case "debian":
		if version == "" {
			return "", fmt.Errorf("the image is Debian but does not say which release")
		}
		return "Debian:" + version, nil
	case "ubuntu":
		if version == "" {
			return "", fmt.Errorf("the image is Ubuntu but does not say which release")
		}
		return "Ubuntu:" + version, nil
	case "alpine":
		if version == "" {
			return "", fmt.Errorf("the image is Alpine but does not say which release")
		}
		// OSV tracks Alpine by minor release, so 3.21.2 is looked up as v3.21.
		parts := strings.Split(version, ".")
		if len(parts) >= 2 {
			version = parts[0] + "." + parts[1]
		}
		return "Alpine:v" + version, nil
	}
	return "", fmt.Errorf("docker-trim does not know how to look up %q packages in OSV; "+
		"Debian, Ubuntu and Alpine are supported", id)
}

// osvRequest is one package lookup.
type osvRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// osvBatchResponse is the reply to querybatch, which reports only which
// advisories exist rather than what they are. Its results are positional.
type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// resolveEcosystem decides which OSV ecosystem a package belongs to.
//
// A language package carries its own; an operating-system package takes the
// image's, because a package version is only vulnerable relative to the
// distribution that built it.
func resolveEcosystem(p analyzer.Package, osEcosystem string) string {
	if p.Ecosystem != "" {
		return p.Ecosystem
	}
	return osEcosystem
}

// osvResponse is the subset of OSV's reply this uses.
type osvResponse struct {
	Vulns []struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
	} `json:"vulns"`
}

// QueryOSV looks up every installed package and reports what is known about it.
//
// It runs in two phases. A querybatch request covers up to a thousand packages
// and says which have any advisory at all; most have none. Only those are then
// asked about individually, which is the only way to get a CVSS vector. On a
// real Node image that is a few dozen requests rather than several hundred.
func QueryOSV(ctx context.Context, rep *analyzer.ImageReport, progress func(string)) (*VulnerabilityReport, error) {
	if progress == nil {
		progress = func(string) {}
	}

	// An unsupported operating system is no longer fatal: the image's language
	// packages can still be scanned, and reporting nothing because the distro
	// was unfamiliar would be the wrong kind of silence.
	osEcosystem, osErr := OSVEcosystem(rep)

	out := &VulnerabilityReport{BySeverity: map[string]int{}}
	var (
		pkgs      []analyzer.Package
		perEco    = map[string]*EcosystemReport{}
		skippedOS int
	)
	for _, p := range rep.Packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		eco := resolveEcosystem(p, osEcosystem)
		if eco == "" {
			skippedOS++
			continue
		}
		if len(pkgs) >= osvMaxPackages {
			out.Notes = append(out.Notes, fmt.Sprintf(
				"Only the first %d packages were looked up, so these counts are a floor.",
				osvMaxPackages))
			break
		}
		pkgs = append(pkgs, p)

		e, ok := perEco[eco]
		if !ok {
			e = &EcosystemReport{Ecosystem: eco, Roots: map[string]int{}}
			perEco[eco] = e
		}
		e.Queried++
		if p.Root != "" {
			e.Roots[p.Root]++
		}
	}
	if skippedOS > 0 && osErr != nil {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%d operating-system packages were not looked up: %v", skippedOS, osErr))
	}
	out.Queried = len(pkgs)
	if len(pkgs) == 0 {
		if osErr != nil {
			return nil, osErr
		}
		return out, nil
	}

	client := &http.Client{Timeout: 60 * time.Second}

	progress(fmt.Sprintf("checking %d packages against OSV", len(pkgs)))
	affected, err := triage(ctx, client, pkgs, osEcosystem)
	if err != nil {
		return nil, err
	}
	if len(affected) == 0 {
		sortEcosystems(out, perEco)
		return out, nil
	}

	progress(fmt.Sprintf("%d have advisories; fetching details", len(affected)))
	found, errs := detail(ctx, client, affected, osEcosystem)

	if len(errs) > 0 {
		if len(errs) >= len(affected) {
			return nil, fmt.Errorf("every OSV lookup failed, the first being: %w", errs[0])
		}
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%d of %d detail lookups failed, so this count is a floor rather than a total. "+
				"The first failure was: %v", len(errs), len(affected), errs[0]))
	}

	// One advisory can affect several packages; count it once.
	seen := map[string]bool{}
	for _, v := range found {
		if seen[v.ID] {
			continue
		}
		seen[v.ID] = true
		out.Vulnerabilities = append(out.Vulnerabilities, v)
		out.BySeverity[v.Severity]++
		if e, ok := perEco[v.Ecosystem]; ok {
			e.Total++
		}
	}
	out.Total = len(out.Vulnerabilities)

	sort.Slice(out.Vulnerabilities, func(i, j int) bool {
		if out.Vulnerabilities[i].Score != out.Vulnerabilities[j].Score {
			return out.Vulnerabilities[i].Score > out.Vulnerabilities[j].Score
		}
		return out.Vulnerabilities[i].ID < out.Vulnerabilities[j].ID
	})
	sortEcosystems(out, perEco)
	return out, nil
}

func sortEcosystems(out *VulnerabilityReport, perEco map[string]*EcosystemReport) {
	for _, e := range perEco {
		out.Ecosystems = append(out.Ecosystems, *e)
	}
	sort.Slice(out.Ecosystems, func(i, j int) bool {
		if out.Ecosystems[i].Total != out.Ecosystems[j].Total {
			return out.Ecosystems[i].Total > out.Ecosystems[j].Total
		}
		return out.Ecosystems[i].Ecosystem < out.Ecosystems[j].Ecosystem
	})
}

// triage asks which packages have any advisory at all, in batches.
func triage(ctx context.Context, client *http.Client, pkgs []analyzer.Package, osEcosystem string) ([]analyzer.Package, error) {
	var affected []analyzer.Package

	for start := 0; start < len(pkgs); start += osvBatchSize {
		end := min(start+osvBatchSize, len(pkgs))
		chunk := pkgs[start:end]

		queries := make([]osvRequest, 0, len(chunk))
		for _, p := range chunk {
			var q osvRequest
			q.Package.Name = p.Name
			q.Package.Ecosystem = resolveEcosystem(p, osEcosystem)
			q.Version = p.Version
			queries = append(queries, q)
		}

		body, err := json.Marshal(map[string]any{"queries": queries})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchEndpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", osvUserAgent)

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("asking OSV which packages are affected: %w", err)
		}
		var parsed osvBatchResponse
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("OSV returned %s for a batch query", resp.Status)
		}
		err = json.NewDecoder(resp.Body).Decode(&parsed)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading OSV's batch reply: %w", err)
		}

		// Results are positional, so a short reply would silently misattribute
		// advisories to the wrong packages.
		if len(parsed.Results) != len(chunk) {
			return nil, fmt.Errorf("OSV returned %d results for %d queries; refusing to guess "+
				"which package each belongs to", len(parsed.Results), len(chunk))
		}
		for i, r := range parsed.Results {
			if len(r.Vulns) > 0 {
				affected = append(affected, chunk[i])
			}
		}
	}
	return affected, nil
}

// detail fetches full advisories, including CVSS, for the affected packages.
func detail(ctx context.Context, client *http.Client, pkgs []analyzer.Package, osEcosystem string) ([]Vulnerability, []error) {
	var (
		mu    sync.Mutex
		found []Vulnerability
		errs  []error
		wg    sync.WaitGroup
		sem   = make(chan struct{}, osvConcurrency)
	)
	for _, p := range pkgs {
		wg.Add(1)
		go func(p analyzer.Package) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			vulns, err := queryOne(ctx, client, resolveEcosystem(p, osEcosystem), p)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			found = append(found, vulns...)
		}(p)
	}
	wg.Wait()
	return found, errs
}

func queryOne(ctx context.Context, client *http.Client, ecosystem string, p analyzer.Package) ([]Vulnerability, error) {
	var req osvRequest
	req.Package.Name = p.Name
	req.Package.Ecosystem = ecosystem
	req.Version = p.Version

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, osvEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", osvUserAgent)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("querying OSV for %s: %w", p.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned %s for %s", resp.Status, p.Name)
	}

	var parsed osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("reading OSV's reply for %s: %w", p.Name, err)
	}

	out := make([]Vulnerability, 0, len(parsed.Vulns))
	for _, v := range parsed.Vulns {
		vuln := Vulnerability{
			ID: v.ID, Package: p.Name, Version: p.Version, Ecosystem: ecosystem,
			Summary: v.Summary, Severity: "unknown",
		}
		// Prefer the highest CVSS vector the advisory carries.
		for _, s := range v.Severity {
			if !strings.HasPrefix(s.Type, "CVSS") {
				continue
			}
			if score, ok := BaseScore(s.Score); ok && score >= vuln.Score {
				vuln.Score, vuln.ScoreKnown = score, true
				vuln.Severity = SeverityOf(score)
			}
		}
		out = append(out, vuln)
	}
	return out, nil
}

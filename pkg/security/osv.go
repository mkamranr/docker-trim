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

	"github.com/mkamranr/dtrim/pkg/analyzer"
)

// Vulnerability data from OSV (https://osv.dev).
//
// This is opt-in behind --osv for two reasons. It is the only part of dtrim
// that sends anything anywhere: the query carries the name and version of every
// package in the image, which describes that image fairly precisely. And it
// means a report can differ between two runs for reasons that have nothing to
// do with the Dockerfile, which is worth knowing before wiring it into a gate.

// osvEndpoint is a variable rather than a constant so tests can point it at a
// local server: a test suite that depends on a third party's availability
// fails for reasons that have nothing to do with the code.
var osvEndpoint = "https://api.osv.dev/v1/query"

const (
	// osvConcurrency is how many queries are in flight at once. OSV is a free
	// public service; this is fast enough for a few hundred packages while
	// staying a considerate client.
	osvConcurrency = 6
	// osvMaxPackages caps a single run. A base image with more packages than
	// this is unusual, and the cap stops a pathological image turning into
	// thousands of requests.
	osvMaxPackages = 600
)

// Vulnerability is one known problem with an installed package.
type Vulnerability struct {
	ID       string  `json:"id"`
	Package  string  `json:"package"`
	Version  string  `json:"version"`
	Severity string  `json:"severity"`
	Score    float64 `json:"score,omitempty"`
	// ScoreKnown is false when the advisory carried no CVSS vector this could
	// read, in which case Severity is "unknown" rather than a guess.
	ScoreKnown bool   `json:"scoreKnown"`
	Summary    string `json:"summary,omitempty"`
}

// VulnerabilityReport is what OSV said about an image.
type VulnerabilityReport struct {
	// Ecosystem is the OSV ecosystem the packages were looked up in.
	Ecosystem string `json:"ecosystem"`
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
	return "", fmt.Errorf("dtrim does not know how to look up %q packages in OSV; "+
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
func QueryOSV(ctx context.Context, rep *analyzer.ImageReport, progress func(string)) (*VulnerabilityReport, error) {
	ecosystem, err := OSVEcosystem(rep)
	if err != nil {
		return nil, err
	}
	if progress == nil {
		progress = func(string) {}
	}

	pkgs := rep.Packages
	out := &VulnerabilityReport{Ecosystem: ecosystem, BySeverity: map[string]int{}}
	if len(pkgs) > osvMaxPackages {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"The image has %d packages; only the %d largest were looked up.", len(pkgs), osvMaxPackages))
		pkgs = pkgs[:osvMaxPackages]
	}
	out.Queried = len(pkgs)
	progress(fmt.Sprintf("looking up %d %s packages in OSV", len(pkgs), ecosystem))

	client := &http.Client{Timeout: 30 * time.Second}
	var (
		mu    sync.Mutex
		found []Vulnerability
		errs  []error
		wg    sync.WaitGroup
		sem   = make(chan struct{}, osvConcurrency)
	)

	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		wg.Add(1)
		go func(p analyzer.Package) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			vulns, err := queryOne(ctx, client, ecosystem, p)
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

	if len(errs) > 0 {
		// A handful of failures is worth reporting without discarding the rest;
		// total failure is an error, because an empty result would otherwise
		// read as a clean image.
		if len(errs) >= out.Queried {
			return nil, fmt.Errorf("every OSV lookup failed, the first being: %w", errs[0])
		}
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%d of %d lookups failed, so this count is a floor rather than a total. "+
				"The first failure was: %v", len(errs), out.Queried, errs[0]))
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
	}
	out.Total = len(out.Vulnerabilities)

	sort.Slice(out.Vulnerabilities, func(i, j int) bool {
		if out.Vulnerabilities[i].Score != out.Vulnerabilities[j].Score {
			return out.Vulnerabilities[i].Score > out.Vulnerabilities[j].Score
		}
		return out.Vulnerabilities[i].ID < out.Vulnerabilities[j].ID
	})
	return out, nil
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
	httpReq.Header.Set("User-Agent", "dtrim (https://github.com/mkamranr/dtrim)")

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
			ID: v.ID, Package: p.Name, Version: p.Version,
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

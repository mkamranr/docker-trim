package dtrim

import (
	"context"
	"fmt"

	"github.com/mkamranr/dtrim/pkg/analyzer"
	"github.com/mkamranr/dtrim/pkg/security"
)

// runOSV looks up the image's packages and folds what it finds into the report.
//
// Vulnerabilities become findings rather than a separate list, so --fail-on
// gates on them without needing a second threshold. A pipeline that refuses a
// Dockerfile shipping a shell should be able to refuse one shipping a critical
// CVE, and it should say so the same way.
// runOSV scans the named image and records the counts.
//
// It runs early, before the Dockerfile is rewritten, because --verify needs a
// "before" to compare its freshly built image against and does its work inside
// that rewrite. It deliberately does not touch findings: see foldVulnerabilities.
func runOSV(ctx context.Context, cfg Config, rep *Report) error {
	if rep.Image == nil {
		return fmt.Errorf("--osv needs an image to look up: add --image")
	}

	vulns, err := scanImage(ctx, cfg, rep.Image)
	if err != nil {
		return err
	}
	rep.Vulnerabilities = vulns
	rep.Result.OriginalCVEs = vulns.Total
	rep.Result.CVEsKnown = true
	return nil
}

// foldVulnerabilities folds the scan into the parts of the report that the
// Dockerfile pass also writes.
//
// It has to run after that pass, which assigns to both rep.Findings and
// rep.Security. Doing this earlier is how --fail-on came to pass images
// carrying critical advisories: they were found, counted, and then overwritten
// before the gate could see them.
func foldVulnerabilities(rep *Report) {
	vulns := rep.Vulnerabilities
	if vulns == nil {
		return
	}

	if rep.Security != nil {
		rep.Security.CVEKnown = true
		rep.Security.OriginalCVEs = vulns.Total
		if rep.Result.RemainingCVEsKnown {
			rep.Security.RemainingCVEs = rep.Result.RemainingCVEs
		}
		// The note explaining that CVE data is unavailable is now false.
		rep.Security.Notes = withoutNote(rep.Security.Notes, "CVE counts are not reported")
	}

	rep.Findings = append(rep.Findings, vulnFindings(vulns)...)

	// An advisory with no readable severity cannot be gated on, and silently
	// dropping it would make --fail-on look more thorough than it is.
	if n := unscored(vulns); n > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"%d of %d advisories carry no CVSS score dtrim could read, so they are listed but "+
				"cannot be matched against --fail-on.", n, vulns.Total))
	}
}

// scanImage looks up one image's packages.
//
// It is separate from the report so the same scan can be run against an image
// dtrim built rather than the one the user named, which is what turns a count
// into a before and after.
func scanImage(ctx context.Context, cfg Config, img *analyzer.ImageReport) (*security.VulnerabilityReport, error) {
	progress := func(string) {}
	if !cfg.Quiet && cfg.Stderr != nil {
		progress = func(msg string) { _, _ = fmt.Fprintf(cfg.Stderr, "[dtrim] %s\n", msg) }
	}
	vulns, err := security.QueryOSV(ctx, img, progress)
	if err != nil {
		return nil, fmt.Errorf("looking up vulnerabilities: %w", err)
	}
	return vulns, nil
}

// compareVulnerabilities scans a second image and records the difference.
//
// The advisories it finds deliberately never become findings. --fail-on gates
// on the image the user named; an advisory present in both images would
// otherwise be counted twice, and one the rewrite removed would still fail the
// build, which punishes the improvement.
func compareVulnerabilities(ctx context.Context, cfg Config, rep *Report, after *analyzer.ImageReport, label string) error {
	if rep.Vulnerabilities == nil {
		return nil // nothing to compare against
	}

	// Checked before scanning rather than after, because an image with nothing
	// to enumerate makes QueryOSV fail rather than return zero — correct when
	// someone asked to scan that image, wrong when it is the far side of a
	// comparison. A scratch image is unreadable, not clean, and the difference
	// matters more here than anywhere else in this tool: the number people
	// would quote is exactly the one that would be wrong.
	if len(after.Packages) == 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"%s has no package inventory dtrim can read, so its advisories could not be "+
				"counted. That is not the same as having none, and no reduction is claimed.", label))
		rep.Result.RemainingCVEsKnown = false
		return nil
	}

	scanned, err := scanImage(ctx, cfg, after)
	if err != nil {
		return err
	}

	rep.VulnerabilitiesAfter = scanned
	rep.Result.RemainingCVEs = scanned.Total
	rep.Result.RemainingCVEsKnown = scanned.Queried > 0
	if scanned.Queried == 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"None of %s's packages could be looked up, so no reduction is claimed.", label))
		return nil
	}
	return nil
}

// vulnFindings turns advisories into findings so one gate covers both.
//
// Only advisories with a severity dtrim could read become findings. One with no
// readable CVSS vector is still counted and listed, but it cannot be placed in
// a band, and inventing a band for it would make --fail-on fire or stay silent
// on a guess.
func vulnFindings(v *security.VulnerabilityReport) []Finding {
	out := make([]Finding, 0, len(v.Vulnerabilities))
	for _, vuln := range v.Vulnerabilities {
		sev := analyzer.Severity(vuln.Severity)
		if sev.Rank() < 0 {
			continue
		}
		// Distribution advisories usually carry no summary, so say something
		// useful rather than repeating the identifier.
		detail := fmt.Sprintf("%s %s is affected. CVSS %.1f.", vuln.Package, vuln.Version, vuln.Score)
		if vuln.Summary != "" {
			detail = vuln.Summary
		}
		out = append(out, Finding{
			RuleID: vuln.ID,
			// The reporter already prints the rule id, which for a
			// vulnerability is the advisory number.
			Title:      fmt.Sprintf("%s %s", vuln.Package, vuln.Version),
			Detail:     detail,
			Severity:   sev,
			Confidence: analyzer.ConfidenceSafe,
		})
	}
	return out
}

func unscored(v *security.VulnerabilityReport) int {
	var n int
	for _, x := range v.Vulnerabilities {
		if !x.ScoreKnown {
			n++
		}
	}
	return n
}

func withoutNote(notes []string, prefix string) []string {
	out := notes[:0:0]
	for _, n := range notes {
		if len(n) >= len(prefix) && n[:len(prefix)] == prefix {
			continue
		}
		out = append(out, n)
	}
	return out
}

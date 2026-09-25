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
func runOSV(ctx context.Context, cfg Config, rep *Report) error {
	if rep.Image == nil {
		return fmt.Errorf("--osv needs an image to look up: add --image")
	}

	progress := func(string) {}
	if !cfg.Quiet && cfg.Stderr != nil {
		progress = func(msg string) { _, _ = fmt.Fprintf(cfg.Stderr, "[dtrim] %s\n", msg) }
	}

	vulns, err := security.QueryOSV(ctx, rep.Image, progress)
	if err != nil {
		return fmt.Errorf("looking up vulnerabilities: %w", err)
	}
	rep.Vulnerabilities = vulns

	rep.Result.OriginalCVEs = vulns.Total
	rep.Result.CVEsKnown = true
	if rep.Security != nil {
		rep.Security.CVEKnown = true
		rep.Security.OriginalCVEs = vulns.Total
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

package dtrim

import (
	"context"
	"strings"
	"testing"

	"github.com/mkamranr/dtrim/pkg/analyzer"
	"github.com/mkamranr/dtrim/pkg/security"
)

func reportWithScan(total int) *Report {
	return &Report{
		Vulnerabilities: &security.VulnerabilityReport{Total: total, Queried: 100},
		Result:          OptimizationResult{OriginalCVEs: total, CVEsKnown: true},
	}
}

// The failure this guards against is the one people would quote. An image with
// nothing to enumerate is unreadable, not clean, and reporting its zero as a
// reduction would turn a parser gap into a security claim.
//
// scratch is the honest case: it genuinely contains nothing, and dtrim still
// must not say the vulnerabilities went away.
func TestCompareVulnerabilities_refuses_to_claim_a_reduction_it_cannot_measure(t *testing.T) {
	rep := reportWithScan(72)
	empty := &analyzer.ImageReport{Reference: "scratch-app:latest"} // no packages

	if err := compareVulnerabilities(context.Background(), Config{}, rep, empty, "The trimmed image"); err != nil {
		t.Fatalf("an unreadable image should not be an error: %v", err)
	}

	if rep.Result.RemainingCVEsKnown {
		t.Error("claimed the remaining count was known for an image with no inventory")
	}
	if rep.VulnerabilitiesAfter != nil {
		t.Error("recorded an after-scan that never happened")
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "not the same as having none") {
		t.Errorf("the limitation was not disclosed: %v", rep.Notes)
	}
	// The original count must survive untouched.
	if rep.Result.OriginalCVEs != 72 {
		t.Errorf("originalCVEs = %d, want 72", rep.Result.OriginalCVEs)
	}
}

// Nothing to compare against means nothing to do, not a crash.
func TestCompareVulnerabilities_does_nothing_without_a_first_scan(t *testing.T) {
	rep := &Report{}
	after := &analyzer.ImageReport{Packages: []analyzer.Package{{Name: "curl", Version: "1"}}}
	if err := compareVulnerabilities(context.Background(), Config{}, rep, after, "x"); err != nil {
		t.Fatal(err)
	}
	if rep.Result.RemainingCVEsKnown || rep.VulnerabilitiesAfter != nil {
		t.Error("a comparison happened with no first scan to compare against")
	}
}

// --fail-on gates on the image the user named. An advisory the rewrite removed
// must not still fail the build, and one present in both must not count twice.
func TestBreaches_ignores_the_compared_image(t *testing.T) {
	rep := &Report{
		Findings: []Finding{
			{RuleID: "CVE-1", Severity: analyzer.SeverityCritical},
			{RuleID: "DT010", Severity: analyzer.SeverityHigh},
		},
		VulnerabilitiesAfter: &security.VulnerabilityReport{
			Total: 500,
			Vulnerabilities: []security.Vulnerability{
				{ID: "CVE-2", Severity: "critical", Score: 9.9},
			},
		},
	}
	got := rep.Breaches(analyzer.SeverityCritical)
	if len(got) != 1 || got[0].RuleID != "CVE-1" {
		t.Errorf("breaches = %+v, want only the named image's advisory", got)
	}
}

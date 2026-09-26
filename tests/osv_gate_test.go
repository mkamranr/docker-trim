//go:build integration

// The security gate, end to end against real advisory data.
//
// Run with: make integration
package tests

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// advisoryPrefixes are the identifier shapes OSV returns for the ecosystems
// dtrim scans.
var advisoryPrefixes = []string{"CVE-", "DEBIAN-", "ALPINE-", "UBUNTU-", "GHSA-", "PYSEC-", "OSV-"}

func isAdvisory(ruleID string) bool {
	for _, p := range advisoryPrefixes {
		if strings.HasPrefix(ruleID, p) {
			return true
		}
	}
	return false
}

type osvReport struct {
	Vulnerabilities struct {
		Total      int            `json:"total"`
		BySeverity map[string]int `json:"bySeverity"`
	} `json:"vulnerabilities"`
	Findings []struct {
		RuleID   string `json:"ruleId"`
		Severity string `json:"severity"`
	} `json:"findings"`
}

// The bug this guards against: advisories were found, counted, and reported in
// the JSON, and then silently dropped from the findings before --fail-on saw
// them. An image with eighteen high-severity advisories printed "PASS nothing
// at high or above" and exited 0.
//
// It only happened when a Dockerfile was analysed in the same run, because
// that path assigned over the findings the scan had appended. Since --osv
// needs --image and --verify needs --file, every combined invocation was
// affected.
//
// The assertions derive what to expect from the scan itself rather than naming
// advisories, so the test cannot go stale as the database changes.
func TestOSV_advisories_survive_a_dockerfile_analysis(t *testing.T) {
	requireDocker(t)

	// A Dockerfile dtrim has nothing high to say about, so only an advisory
	// can trip the gate.
	dir := t.TempDir()
	clean := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(clean, []byte(
		"FROM gcr.io/distroless/static-debian12:nonroot\nCOPY app /app\nCMD [\"/app\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := dtrim(t, "--analyze-only", "-f", clean, "--fail-on", "high"); r.code != 0 {
		t.Fatalf("the fixture Dockerfile is not clean at high severity (exit %d):\n%s", r.code, r.stdout)
	}

	const image = "debian:12-slim"
	if out, err := exec.Command("docker", "pull", "-q", image).CombinedOutput(); err != nil {
		t.Skipf("cannot pull %s: %v\n%s", image, err, out)
	}

	r := dtrim(t, "--analyze-only", "--image", image, "-f", clean, "--osv", "--quiet")
	if r.code != 0 {
		t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	var rep osvReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if rep.Vulnerabilities.Total == 0 {
		t.Skipf("%s currently has no known advisories, so there is nothing to gate on", image)
	}

	// The invariant that broke: advisories were counted but reached no finding.
	var advisories []string
	worst := ""
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	for _, f := range rep.Findings {
		if !isAdvisory(f.RuleID) {
			continue
		}
		advisories = append(advisories, f.RuleID)
		if rank[f.Severity] > rank[worst] {
			worst = f.Severity
		}
	}
	if len(advisories) == 0 {
		t.Fatalf("the scan found %d advisories but none became findings, so --fail-on cannot "+
			"see them; severities: %v", rep.Vulnerabilities.Total, rep.Vulnerabilities.BySeverity)
	}
	if worst == "" {
		t.Skip("no advisory carried a severity dtrim could band, so the gate has nothing to act on")
	}

	// And the gate must actually act on them.
	gated := dtrim(t, "--analyze-only", "--image", image, "-f", clean, "--osv", "--fail-on", worst)
	if gated.code != 1 {
		t.Errorf("exit %d with %d advisories at %s or above, want 1\n%s",
			gated.code, len(advisories), worst, gated.stdout)
	}
	if !strings.Contains(gated.stdout, "FAIL") {
		t.Errorf("the gate did not report a failure:\n%s", gated.stdout)
	}
}

// The Dockerfile's own findings must survive alongside the advisories: the fix
// moved the scan later, and putting it in the wrong place would drop the other
// half instead.
func TestOSV_keeps_dockerfile_findings_too(t *testing.T) {
	requireDocker(t)

	const image = "debian:12-slim"
	if out, err := exec.Command("docker", "pull", "-q", image).CombinedOutput(); err != nil {
		t.Skipf("cannot pull %s: %v\n%s", image, err, out)
	}

	r := dtrim(t, "--analyze-only", "--image", image,
		"-f", fixture("node-express.Dockerfile"), "--osv", "--quiet")
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	var rep osvReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatal(err)
	}

	var rules, advisories int
	for _, f := range rep.Findings {
		if isAdvisory(f.RuleID) {
			advisories++
		} else if strings.HasPrefix(f.RuleID, "DT") {
			rules++
		}
	}
	if rules == 0 {
		t.Error("the Dockerfile's own findings were lost")
	}
	if rep.Vulnerabilities.Total > 0 && advisories == 0 {
		t.Error("the advisories were lost")
	}
}

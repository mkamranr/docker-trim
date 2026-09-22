// Package tests drives the built binary the way a user does.
package tests

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binary string

// TestMain builds dtrim once and runs every test against that binary, so the
// tests exercise the command rather than the library behind it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "dtrim-bin")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	binary = filepath.Join(dir, "dtrim")
	if runtime.GOOS == "windows" {
		// Without the extension, exec.Command cannot find the binary that was
		// just built a line below.
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "..")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic("cannot build dtrim: " + err.Error())
	}
	os.Exit(m.Run())
}

type result struct {
	stdout, stderr string
	code           int
}

func dtrim(t *testing.T, args ...string) result {
	t.Helper()
	cmd := exec.Command(binary, append([]string{"--no-color"}, args...)...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb

	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !asExitError(err, &ee) {
			t.Fatalf("running dtrim: %v", err)
		}
		code = ee.ExitCode()
	}
	return result{stdout: out.String(), stderr: errb.String(), code: code}
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func fixture(name string) string { return filepath.Join("fixtures", name) }

func TestAnalyzeOnly_reports_findings_and_succeeds(t *testing.T) {
	r := dtrim(t, "--analyze-only", "-f", fixture("node-express.Dockerfile"))

	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s%s", r.code, r.stdout, r.stderr)
	}
	for _, want := range []string{"Analyzed", "Node.js", "Findings", "DT010"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output does not mention %q:\n%s", want, r.stdout)
		}
	}
}

// --analyze-only is read-only by contract. If that ever stops being true,
// someone's Dockerfile gets overwritten by a command that promised not to.
func TestAnalyzeOnly_writes_nothing(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(fixture("node-express.Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(target, src, 0o644); err != nil {
		t.Fatal(err)
	}

	before, _ := os.ReadDir(dir)
	r := dtrim(t, "--analyze-only", "--optimize", "-f", target, "-o", filepath.Join(dir, "out"))
	if r.code != 0 {
		t.Fatalf("exit code = %d\n%s%s", r.code, r.stdout, r.stderr)
	}

	after, _ := os.ReadDir(dir)
	if len(after) != len(before) {
		t.Errorf("--analyze-only created files: %d entries before, %d after", len(before), len(after))
	}
	now, _ := os.ReadFile(target)
	if string(now) != string(src) {
		t.Error("--analyze-only modified the input Dockerfile")
	}
}

func TestOptimize_writes_the_trimmed_file(t *testing.T) {
	out := filepath.Join(t.TempDir(), "Dockerfile.trimmed")
	r := dtrim(t, "--optimize", "-f", fixture("go-api.Dockerfile"), "-o", out)

	if r.code != 0 {
		t.Fatalf("exit code = %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no output written: %v", err)
	}
	if !strings.Contains(string(body), "AS builder") {
		t.Errorf("no builder stage in the output:\n%s", body)
	}
	if !strings.Contains(string(body), "distroless/static") {
		t.Errorf("no distroless runtime in the output:\n%s", body)
	}
}

func TestQuiet_emits_only_valid_json(t *testing.T) {
	r := dtrim(t, "--analyze-only", "-f", fixture("python-flask.Dockerfile"), "--quiet")

	if r.code != 0 {
		t.Fatalf("exit code = %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	var rep struct {
		SchemaVersion int    `json:"schemaVersion"`
		Tool          string `json:"tool"`
		Dockerfile    struct {
			Ecosystem string `json:"ecosystem"`
		} `json:"dockerfile"`
		Findings []struct {
			RuleID   string `json:"ruleId"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, r.stdout)
	}
	if rep.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", rep.SchemaVersion)
	}
	if rep.Tool != "dtrim" {
		t.Errorf("tool = %q", rep.Tool)
	}
	if rep.Dockerfile.Ecosystem != "python" {
		t.Errorf("ecosystem = %q, want python", rep.Dockerfile.Ecosystem)
	}
	if len(rep.Findings) == 0 {
		t.Error("no findings in the JSON report")
	}
	// --quiet exists so the output can be piped; progress must not leak in.
	if strings.Contains(r.stdout, "[dtrim]") {
		t.Error("progress output leaked into the JSON on stdout")
	}
}

func TestExitCode_is_two_on_error(t *testing.T) {
	cases := [][]string{
		{"-f", "/nonexistent/Dockerfile"},
		{"-f", fixture("go-api.Dockerfile"), "--base", "nonsense"},
		{"-f", fixture("go-api.Dockerfile"), "--aggressiveness", "reckless"},
	}
	for _, args := range cases {
		r := dtrim(t, args...)
		if r.code != 2 {
			t.Errorf("%v: exit code = %d, want 2\n%s", args, r.code, r.stderr)
		}
		if !strings.HasPrefix(r.stderr, "dtrim: ") {
			t.Errorf("%v: stderr = %q, want it to start with \"dtrim: \"", args, r.stderr)
		}
	}
}

// Flags for features that have not shipped must fail loudly and point at the
// changelog, not silently do nothing.
func TestDeferredFlags_fail_with_a_pointer_to_the_changelog(t *testing.T) {
	for _, args := range [][]string{
		{"-f", fixture("go-api.Dockerfile"), "--tracer", "proc"},
		{"-f", fixture("go-api.Dockerfile"), "--osv"},
	} {
		r := dtrim(t, args...)
		if r.code != 2 {
			t.Errorf("%v: exit code = %d, want 2", args, r.code)
		}
		if !strings.Contains(r.stderr, "CHANGELOG") {
			t.Errorf("%v: stderr does not point at the changelog: %q", args, r.stderr)
		}
	}
}

func TestPositionalArgument_is_read_as_a_dockerfile_when_it_is_one(t *testing.T) {
	r := dtrim(t, "--analyze-only", fixture("rust-cli.Dockerfile"))
	if r.code != 0 {
		t.Fatalf("exit code = %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "Rust") {
		t.Errorf("did not analyze the positional Dockerfile:\n%s", r.stdout)
	}
}

func TestMarkdown_renders_a_pull_request_report(t *testing.T) {
	out := filepath.Join(t.TempDir(), "Dockerfile.trimmed")
	r := dtrim(t, "--optimize", "-f", fixture("go-api.Dockerfile"), "-o", out, "--markdown")

	if r.code != 0 {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{"## dtrim report", "```diff"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("markdown output does not contain %q:\n%s", want, r.stdout)
		}
	}
}

func TestHelp_does_not_advertise_what_is_not_built(t *testing.T) {
	r := dtrim(t, "--help")
	if r.code != 0 {
		t.Fatalf("exit code = %d", r.code)
	}
	// The flags exist so scripts keep working, but the help has to say they
	// are not ready rather than implying they work.
	for _, flag := range []string{"--trace", "--tracer", "--osv"} {
		idx := strings.Index(r.stdout, flag)
		if idx < 0 {
			t.Errorf("%s missing from help", flag)
			continue
		}
		line := r.stdout[idx:]
		if end := strings.IndexByte(line, '\n'); end > 0 {
			line = line[:end]
		}
		if !strings.Contains(line, "0.2") {
			t.Errorf("help for %s does not say it is planned for 0.2: %q", flag, line)
		}
	}
}

func TestVersion_prints_something(t *testing.T) {
	r := dtrim(t, "--version")
	if r.code != 0 || !strings.Contains(r.stdout, "dtrim") {
		t.Errorf("--version: code=%d output=%q", r.code, r.stdout)
	}
}

// --fail-on is what makes dtrim usable as a CI gate, so the three exit codes
// have to stay distinct: a pipeline needs to tell "your Dockerfile ships a
// shell" from "dtrim could not run".
func TestFailOn_exit_codes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no threshold never fails", []string{"--analyze-only", "-f", fixture("node-express.Dockerfile")}, 0},
		{"threshold above what was found", []string{"--analyze-only", "-f", fixture("node-express.Dockerfile"), "--fail-on", "critical"}, 0},
		{"threshold met", []string{"--analyze-only", "-f", fixture("node-express.Dockerfile"), "--fail-on", "high"}, 1},
		{"threshold below what was found", []string{"--analyze-only", "-f", fixture("node-express.Dockerfile"), "--fail-on", "info"}, 1},
		{"clean file passes", []string{"--analyze-only", "-f", fixture("already-multistage.Dockerfile"), "--fail-on", "critical"}, 0},
		{"still a gate under --quiet", []string{"--analyze-only", "-f", fixture("node-express.Dockerfile"), "--fail-on", "high", "--quiet"}, 1},
		{"a bad severity is a tool error", []string{"--analyze-only", "-f", fixture("go-api.Dockerfile"), "--fail-on", "nonsense"}, 2},
		{"a missing file is a tool error", []string{"--analyze-only", "-f", "no/such/file", "--fail-on", "info"}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dtrim(t, c.args...); got.code != c.want {
				t.Errorf("exit code = %d, want %d\n%s%s", got.code, c.want, got.stdout, got.stderr)
			}
		})
	}
}

func TestFailOn_names_the_rules_responsible(t *testing.T) {
	r := dtrim(t, "--analyze-only", "-f", fixture("node-express.Dockerfile"), "--fail-on", "high", "--no-diff")

	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1", r.code)
	}
	if !strings.Contains(r.stdout, "FAIL") {
		t.Errorf("no FAIL line:\n%s", r.stdout)
	}
	// Someone reading a red pipeline should not have to re-run anything to
	// find out which rule tripped it.
	for _, rule := range []string{"DT010", "DT011"} {
		if !strings.Contains(r.stdout, rule) {
			t.Errorf("the FAIL line does not name %s:\n%s", rule, r.stdout)
		}
	}
}

func TestFailOn_says_so_when_it_passes(t *testing.T) {
	r := dtrim(t, "--analyze-only", "-f", fixture("already-multistage.Dockerfile"), "--fail-on", "critical", "--no-diff")
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0", r.code)
	}
	if !strings.Contains(r.stdout, "PASS") {
		t.Errorf("a passing gate should say so:\n%s", r.stdout)
	}
}

// Fixing a finding removes it from the file you are about to build, so it must
// not keep failing the pipeline.
func TestFailOn_ignores_findings_that_were_fixed(t *testing.T) {
	out := filepath.Join(t.TempDir(), "Dockerfile.trimmed")
	analyzed := dtrim(t, "--analyze-only", "-f", fixture("go-api.Dockerfile"), "--fail-on", "medium")
	optimized := dtrim(t, "--optimize", "-f", fixture("go-api.Dockerfile"), "-o", out, "--fail-on", "medium", "--no-diff")

	if analyzed.code != 1 {
		t.Fatalf("the unfixed file should trip a medium gate, got exit %d", analyzed.code)
	}
	if optimized.code != 0 {
		t.Errorf("after rewriting, the medium findings are gone, so the gate should pass; got exit %d\n%s",
			optimized.code, optimized.stdout)
	}
}

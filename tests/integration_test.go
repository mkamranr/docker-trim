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

// TestMain builds docker-trim once and runs every test against that binary, so the
// tests exercise the command rather than the library behind it.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "docker-trim-bin")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	binary = filepath.Join(dir, "docker-trim")
	if runtime.GOOS == "windows" {
		// Without the extension, exec.Command cannot find the binary that was
		// just built a line below.
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "..")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic("cannot build docker-trim: " + err.Error())
	}
	os.Exit(m.Run())
}

type result struct {
	stdout, stderr string
	code           int
}

func dockerTrim(t *testing.T, args ...string) result {
	t.Helper()
	cmd := exec.Command(binary, append([]string{"--no-color"}, args...)...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb

	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !asExitError(err, &ee) {
			t.Fatalf("running docker-trim: %v", err)
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
	r := dockerTrim(t, "--analyze-only", "-f", fixture("node-express.Dockerfile"))

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
	r := dockerTrim(t, "--analyze-only", "--optimize", "-f", target, "-o", filepath.Join(dir, "out"))
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
	r := dockerTrim(t, "--optimize", "-f", fixture("go-api.Dockerfile"), "-o", out)

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
	r := dockerTrim(t, "--analyze-only", "-f", fixture("python-flask.Dockerfile"), "--quiet")

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
	if rep.SchemaVersion != 2 {
		t.Errorf("schemaVersion = %d, want 2", rep.SchemaVersion)
	}
	if rep.Tool != "docker-trim" {
		t.Errorf("tool = %q", rep.Tool)
	}
	if rep.Dockerfile.Ecosystem != "python" {
		t.Errorf("ecosystem = %q, want python", rep.Dockerfile.Ecosystem)
	}
	if len(rep.Findings) == 0 {
		t.Error("no findings in the JSON report")
	}
	// --quiet exists so the output can be piped; progress must not leak in.
	if strings.Contains(r.stdout, "[docker-trim]") {
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
		r := dockerTrim(t, args...)
		if r.code != 2 {
			t.Errorf("%v: exit code = %d, want 2\n%s", args, r.code, r.stderr)
		}
		if !strings.HasPrefix(r.stderr, "docker-trim: ") {
			t.Errorf("%v: stderr = %q, want it to start with \"docker-trim: \"", args, r.stderr)
		}
	}
}

// A backend that has not shipped must say so and name one that has, rather than
// failing with something generic or silently doing nothing. ptrace shipped, so
// only ebpf is left; validation happens before any image is touched, which is
// why this needs no Docker.
func TestUnimplementedBackends_name_one_that_works(t *testing.T) {
	r := dockerTrim(t, "--image", "busybox:latest", "--tracer", "ebpf")
	if r.code != 2 {
		t.Errorf("--tracer ebpf: exit code = %d, want 2", r.code)
	}
	if !strings.Contains(r.stderr, "not implemented") {
		t.Errorf("--tracer ebpf: stderr = %q", r.stderr)
	}
	if !strings.Contains(r.stderr, "proc") {
		t.Errorf("--tracer ebpf does not point at a backend that works: %q", r.stderr)
	}
}

// Both implemented backends have to be accepted by flag validation, which runs
// before anything touches Docker.
func TestImplementedBackends_pass_validation(t *testing.T) {
	for _, backend := range []string{"proc", "ptrace"} {
		r := dockerTrim(t, "--image", "docker-trim-no-such-image:v0", "--tracer", backend)
		// It should fail on the missing image, not on the backend name.
		if strings.Contains(r.stderr, "not implemented") {
			t.Errorf("--tracer %s was rejected as unimplemented: %q", backend, r.stderr)
		}
	}
}

// Tracing needs something to run, and saying which flag is missing is more
// useful than a generic validation error.
func TestTracerWithoutAnImage_says_which_flag_is_missing(t *testing.T) {
	r := dockerTrim(t, "-f", fixture("go-api.Dockerfile"), "--tracer", "proc")
	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2", r.code)
	}
	if !strings.Contains(r.stderr, "--image") {
		t.Errorf("stderr does not name the missing flag: %q", r.stderr)
	}
}

func TestTraceWithoutABackend_says_which_flag_is_missing(t *testing.T) {
	r := dockerTrim(t, "--image", "busybox:latest", "--trace", "echo hi")
	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2", r.code)
	}
	if !strings.Contains(r.stderr, "--tracer") {
		t.Errorf("stderr does not name the missing flag: %q", r.stderr)
	}
}

func TestPositionalArgument_is_read_as_a_dockerfile_when_it_is_one(t *testing.T) {
	r := dockerTrim(t, "--analyze-only", fixture("rust-cli.Dockerfile"))
	if r.code != 0 {
		t.Fatalf("exit code = %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "Rust") {
		t.Errorf("did not analyze the positional Dockerfile:\n%s", r.stdout)
	}
}

func TestMarkdown_renders_a_pull_request_report(t *testing.T) {
	out := filepath.Join(t.TempDir(), "Dockerfile.trimmed")
	r := dockerTrim(t, "--optimize", "-f", fixture("go-api.Dockerfile"), "-o", out, "--markdown")

	if r.code != 0 {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{"## docker-trim report", "```diff"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("markdown output does not contain %q:\n%s", want, r.stdout)
		}
	}
}

// The help must describe what is actually built, in both directions: it must
// not claim a working feature is future work, and must not advertise one that
// is missing.
//
// This is deliberately derived from the help text rather than from a list kept
// here. Three separate hand-written versions of this test went stale as
// features shipped, each time asserting that something already working was
// still planned.
func TestHelp_describes_what_is_actually_built(t *testing.T) {
	r := dockerTrim(t, "--help")
	if r.code != 0 {
		t.Fatalf("exit code = %d", r.code)
	}

	// Flags whose help admits they are unbuilt, and the value to try.
	deferred := map[string]string{}
	implemented := map[string]string{}
	for _, line := range strings.Split(r.stdout, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "--") && !strings.HasPrefix(line, "-") {
			continue
		}
		flag := flagName(line)
		if flag == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "not implemented") || strings.Contains(lower, "planned") {
			deferred[flag] = line
		} else {
			implemented[flag] = line
		}
	}

	// Anything the help calls unbuilt must actually refuse, naming an
	// alternative rather than failing obscurely.
	for flag := range deferred {
		if flag != "--tracer" {
			continue
		}
		res := dockerTrim(t, "--image", "busybox:latest", "--tracer", "ebpf")
		if res.code != 2 || !strings.Contains(res.stderr, "not implemented") {
			t.Errorf("%s says a backend is planned, but it does not refuse: code=%d %q",
				flag, res.code, res.stderr)
		}
	}

	// And nothing that works may still be described as future work.
	for _, flag := range []string{"--trace", "--osv", "--prune-unused", "--fail-on", "--verify"} {
		if line, stale := deferred[flag]; stale {
			t.Errorf("%s is implemented, but its help still defers it: %q", flag, line)
		}
	}
}

// flagName pulls the long flag out of a cobra help line such as
// "  -t, --trace string   Command to run ...".
func flagName(line string) string {
	i := strings.Index(line, "--")
	if i < 0 {
		return ""
	}
	rest := line[i:]
	if j := strings.IndexAny(rest, " \t"); j > 0 {
		return rest[:j]
	}
	return rest
}

func TestVersion_prints_something(t *testing.T) {
	r := dockerTrim(t, "--version")
	if r.code != 0 || !strings.Contains(r.stdout, "docker-trim") {
		t.Errorf("--version: code=%d output=%q", r.code, r.stdout)
	}
}

// --fail-on is what makes docker-trim usable as a CI gate, so the three exit codes
// have to stay distinct: a pipeline needs to tell "your Dockerfile ships a
// shell" from "docker-trim could not run".
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
			if got := dockerTrim(t, c.args...); got.code != c.want {
				t.Errorf("exit code = %d, want %d\n%s%s", got.code, c.want, got.stdout, got.stderr)
			}
		})
	}
}

func TestFailOn_names_the_rules_responsible(t *testing.T) {
	r := dockerTrim(t, "--analyze-only", "-f", fixture("node-express.Dockerfile"), "--fail-on", "high", "--no-diff")

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
	r := dockerTrim(t, "--analyze-only", "-f", fixture("already-multistage.Dockerfile"), "--fail-on", "critical", "--no-diff")
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
	analyzed := dockerTrim(t, "--analyze-only", "-f", fixture("go-api.Dockerfile"), "--fail-on", "medium")
	optimized := dockerTrim(t, "--optimize", "-f", fixture("go-api.Dockerfile"), "-o", out, "--fail-on", "medium", "--no-diff")

	if analyzed.code != 1 {
		t.Fatalf("the unfixed file should trip a medium gate, got exit %d", analyzed.code)
	}
	if optimized.code != 0 {
		t.Errorf("after rewriting, the medium findings are gone, so the gate should pass; got exit %d\n%s",
			optimized.code, optimized.stdout)
	}
}

// docker-trim is named exactly like a Docker CLI plugin, so it should behave
// like one: dropped into ~/.docker/cli-plugins it becomes `docker trim`.
//
// Docker asks a candidate plugin for this one hidden command to learn what it
// is, and reports anything that cannot answer as invalid. Since the name
// invites people to put it there, refusing to answer would be a confusing way
// to greet them.
func TestPluginMetadata_answers_dockers_question(t *testing.T) {
	// Invoked bare, exactly as Docker does it: the shared helper adds
	// --no-color, which this subcommand has no reason to accept.
	out, err := exec.Command(binary, "docker-cli-plugin-metadata").CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var meta map[string]string
	if err := json.Unmarshal(out, &meta); err != nil {
		t.Fatalf("the metadata is not valid JSON: %v\n%s", err, out)
	}
	// Docker requires these; the others are courtesy.
	for _, key := range []string{"SchemaVersion", "Vendor", "Version", "ShortDescription"} {
		if meta[key] == "" {
			t.Errorf("%s is empty: %v", key, meta)
		}
	}
	if meta["SchemaVersion"] != "0.1.0" {
		t.Errorf("SchemaVersion = %q, want 0.1.0", meta["SchemaVersion"])
	}
	// It must not clutter the help of a tool most people run directly.
	if h := dockerTrim(t, "--help"); strings.Contains(h.stdout, "docker-cli-plugin-metadata") {
		t.Error("the plugin command is advertised in --help")
	}
}

// Docker passes the subcommand it matched as the first argument, so
// `docker trim --analyze-only -f x` arrives as `docker-trim trim --analyze-only
// -f x`. Left in place it parses as a positional argument, and dtrim went
// looking for an image called "trim".
func TestPluginInvocation_drops_the_subcommand_docker_passes(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(df, []byte("FROM alpine:3.21\nCMD [\"/bin/true\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// As Docker invokes it: the plugin name first, and the marker set. The
	// name Docker passes never carries the .exe that the binary does on
	// Windows, which is how this first broke there.
	cmd := exec.Command(binary, "trim", "--no-color", "--analyze-only", "-f", df, "--no-diff")
	cmd.Env = append(os.Environ(),
		"DOCKER_CLI_PLUGIN_ORIGINAL_CLI_COMMAND=/usr/local/bin/docker")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running as a plugin failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "trim:latest") || strings.Contains(string(out), "No such image") {
		t.Errorf("the plugin subcommand was parsed as an image reference:\n%s", out)
	}
	if !strings.Contains(string(out), "Analyzed") {
		t.Errorf("the Dockerfile was not analysed:\n%s", out)
	}

	// Without the marker it is someone typing the name, and a positional
	// argument means what it says.
	plain := dockerTrim(t, "--analyze-only", "-f", df, "--no-diff")
	if plain.code != 0 {
		t.Errorf("direct invocation broke: exit %d\n%s", plain.code, plain.stderr)
	}
}

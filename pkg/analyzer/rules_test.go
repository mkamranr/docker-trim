package analyzer

import (
	"strings"
	"testing"
)

func parseString(t *testing.T, src string) *Analysis {
	t.Helper()
	a, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return a
}

// ids collapses findings to the set of rule IDs that fired.
func ids(f []Finding) map[string]int {
	m := map[string]int{}
	for _, x := range f {
		m[x.RuleID]++
	}
	return m
}

func TestLint_flags_the_expected_rules_on_the_node_fixture(t *testing.T) {
	got := ids(Lint(parseFixture(t, "node-express.Dockerfile")))

	for _, want := range []string{"DT001", "DT002", "DT006", "DT007", "DT010", "DT011", "DT012"} {
		if got[want] == 0 {
			t.Errorf("rule %s did not fire; fired: %v", want, got)
		}
	}
}

func TestLint_flags_pip_and_dev_tools_on_the_python_fixture(t *testing.T) {
	got := ids(Lint(parseFixture(t, "python-flask.Dockerfile")))

	for _, want := range []string{"DT001", "DT002", "DT004", "DT010", "DT011"} {
		if got[want] == 0 {
			t.Errorf("rule %s did not fire; fired: %v", want, got)
		}
	}
	// gcc, g++, curl, vim and netcat-openbsd are all shipped to production.
	if got["DT011"] < 5 {
		t.Errorf("DT011 fired %d times, want one per dev tool (>=5)", got["DT011"])
	}
}

func TestLint_stays_quiet_on_an_already_optimised_file(t *testing.T) {
	got := ids(Lint(parseFixture(t, "already-multistage.Dockerfile")))

	// The fixture cleans apt lists, uses --no-install-recommends and
	// --no-cache-dir, and sets a non-root USER.
	for _, quiet := range []string{"DT001", "DT002", "DT004", "DT010"} {
		if got[quiet] != 0 {
			t.Errorf("rule %s fired %d times on an already-optimised file", quiet, got[quiet])
		}
	}
}

func TestFix_adds_no_install_recommends_and_cleans_apt_lists(t *testing.T) {
	a := parseString(t, "FROM debian:12\nRUN apt-get update && apt-get install -y curl\n")

	fixed, remaining := FixAll(a, ConfidenceSafe)
	if len(fixed) == 0 {
		t.Fatal("no fixes applied")
	}

	got := JoinCommand(a.Stages[0].Instructions[1].Args)
	if !strings.Contains(got, "--no-install-recommends") {
		t.Errorf("fixed RUN = %q, want --no-install-recommends", got)
	}
	if !strings.Contains(got, "rm -rf /var/lib/apt/lists/*") {
		t.Errorf("fixed RUN = %q, want the apt lists cleanup", got)
	}
	if r := ids(remaining); r["DT001"] != 0 || r["DT002"] != 0 {
		t.Errorf("DT001/DT002 still reported after fixing: %v", r)
	}
}

func TestFix_is_idempotent(t *testing.T) {
	const src = "FROM debian:12\nRUN apt-get update && apt-get install -y curl\nRUN pip install flask\nRUN apk add jq\nRUN npm install\n"

	a := parseString(t, src)
	FixAll(a, ConfidenceAggressive)
	first := renderArgs(a)

	FixAll(a, ConfidenceAggressive)
	second := renderArgs(a)

	if first != second {
		t.Errorf("second fix pass changed the file:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func renderArgs(a *Analysis) string {
	var b strings.Builder
	for si := range a.Stages {
		for _, ins := range a.Stages[si].Instructions {
			b.WriteString(ins.Keyword + " " + JoinCommand(ins.Args) + "\n")
		}
	}
	return b.String()
}

func TestFix_respects_the_aggressiveness_gate(t *testing.T) {
	const src = "FROM debian:12\nRUN npm install\n"

	safe := parseString(t, src)
	FixAll(safe, ConfidenceSafe)
	if strings.Contains(renderArgs(safe), "cache clean") {
		t.Error("DT006 is a likely-confidence rule and must not fire at --aggressiveness safe")
	}

	likely := parseString(t, src)
	FixAll(likely, ConfidenceLikely)
	if !strings.Contains(renderArgs(likely), "cache clean") {
		t.Error("DT006 should fire at --aggressiveness likely")
	}
}

func TestFix_clears_raw_so_the_emitter_rerenders_changed_instructions(t *testing.T) {
	a := parseString(t, "FROM debian:12\nRUN apt-get update && apt-get install -y curl\nRUN echo untouched\n")
	FixAll(a, ConfidenceSafe)

	if got := a.Stages[0].Instructions[1].Raw; got != "" {
		t.Errorf("changed instruction kept Raw = %q, want it cleared", got)
	}
	if got := a.Stages[0].Instructions[2].Raw; got == "" {
		t.Error("untouched instruction lost its Raw source")
	}
}

func TestDT004_stays_quiet_when_pip_no_cache_dir_is_set_in_the_environment(t *testing.T) {
	a := parseString(t, "FROM python:3.12-slim\nENV PIP_NO_CACHE_DIR=1\nRUN pip install flask\n")
	if got := ids(Lint(a))["DT004"]; got != 0 {
		t.Errorf("DT004 fired %d times despite PIP_NO_CACHE_DIR=1", got)
	}
}

func TestDT009_accepts_a_pinned_tag_and_a_digest(t *testing.T) {
	cases := map[string]int{
		"FROM node:18\n":     0,
		"FROM node\n":        1,
		"FROM node:latest\n": 1,
		"FROM node@sha256:" + strings.Repeat("a", 64) + "\n": 0,
		"FROM registry.example.com:5000/app:2.1\n":           0,
		"FROM scratch\n": 0,
	}
	for src, want := range cases {
		a := parseString(t, src+"CMD [\"true\"]\n")
		if got := ids(Lint(a))["DT009"]; got != want {
			t.Errorf("%q: DT009 fired %d times, want %d", strings.TrimSpace(src), got, want)
		}
	}
}

func TestDT013_flags_a_baked_secret_but_not_a_bare_build_arg(t *testing.T) {
	baked := parseString(t, "FROM alpine\nENV API_KEY=abc123\nCMD [\"true\"]\n")
	if got := ids(Lint(baked))["DT013"]; got == 0 {
		t.Error("DT013 did not fire for ENV API_KEY=abc123")
	}

	bare := parseString(t, "ARG GITHUB_TOKEN\nFROM alpine\nCMD [\"true\"]\n")
	if got := ids(Lint(bare))["DT013"]; got != 0 {
		t.Errorf("DT013 fired %d times for a valueless ARG, which is the correct pattern", got)
	}
}

func TestDT010_accepts_a_non_root_user(t *testing.T) {
	a := parseString(t, "FROM alpine\nUSER 10001:10001\nCMD [\"true\"]\n")
	if got := ids(Lint(a))["DT010"]; got != 0 {
		t.Errorf("DT010 fired %d times despite a non-root USER", got)
	}

	rooted := parseString(t, "FROM alpine\nUSER root\nCMD [\"true\"]\n")
	if got := ids(Lint(rooted))["DT010"]; got == 0 {
		t.Error("DT010 did not fire for an explicit USER root")
	}
}

func TestDT003_flags_a_lone_apt_get_update(t *testing.T) {
	split := parseString(t, "FROM debian:12\nRUN apt-get update\nRUN apt-get install -y curl\n")
	if got := ids(Lint(split))["DT003"]; got == 0 {
		t.Error("DT003 did not fire for apt-get update in its own RUN")
	}

	joined := parseString(t, "FROM debian:12\nRUN apt-get update && apt-get install -y curl\n")
	if got := ids(Lint(joined))["DT003"]; got != 0 {
		t.Errorf("DT003 fired %d times when update and install share a RUN", got)
	}
}

// Every rule must declare metadata, and no two may claim the same ID.
func TestRegistry_ids_are_unique_and_documented(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range registry() {
		if r.ID() == "" || !strings.HasPrefix(r.ID(), "DT") {
			t.Errorf("rule %T has id %q, want a DTnnn id", r, r.ID())
		}
		if seen[r.ID()] {
			t.Errorf("duplicate rule id %s", r.ID())
		}
		seen[r.ID()] = true
		if r.Title() == "" {
			t.Errorf("rule %s has no title", r.ID())
		}
		if r.Confidence().Rank() > 2 {
			t.Errorf("rule %s has an unknown confidence %q", r.ID(), r.Confidence())
		}
	}
}

// The manifest-first pattern is what DT007 asks for, so a file that already
// does it must not be told to do it. docker-trim's own Dockerfile is this shape.
func TestDT007_stays_quiet_when_dependencies_are_installed_before_the_source_copy(t *testing.T) {
	good := parseString(t, "FROM golang:1.24-alpine\nWORKDIR /src\n"+
		"COPY go.mod go.sum ./\nRUN go mod download\nCOPY . .\nRUN go build -o /out .\n")
	if got := ids(Lint(good))["DT007"]; got != 0 {
		t.Errorf("DT007 fired %d times on the manifest-first pattern it recommends", got)
	}

	bad := parseString(t, "FROM golang:1.24-alpine\nWORKDIR /src\n"+
		"COPY . .\nRUN go mod download\nRUN go build -o /out .\n")
	if got := ids(Lint(bad))["DT007"]; got == 0 {
		t.Error("DT007 did not fire when the source is copied before dependencies are fetched")
	}
}

func TestIsDependencyInstall_separates_fetching_deps_from_building(t *testing.T) {
	yes := [][]string{
		{"npm", "ci"}, {"npm", "install"}, {"yarn", "install"}, {"pip", "install", "-r", "r.txt"},
		{"go", "mod", "download"}, {"poetry", "install"}, {"bundle", "install"}, {"cargo", "fetch"},
	}
	no := [][]string{
		{"go", "build", "-o", "/out"}, {"cargo", "build", "--release"}, {"npm", "run", "build"},
		{"apt-get", "install", "-y", "curl"}, {"echo", "pip", "install"},
	}
	for _, cmd := range yes {
		if !isDependencyInstall(cmd) {
			t.Errorf("%v should count as a dependency install", cmd)
		}
	}
	for _, cmd := range no {
		if isDependencyInstall(cmd) {
			t.Errorf("%v should not count as a dependency install", cmd)
		}
	}
}

func TestSeverity_ranks_worst_highest(t *testing.T) {
	order := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Errorf("%s does not rank above %s", order[i], order[i-1])
		}
	}
	if Severity("nonsense").Rank() >= 0 {
		t.Error("an unknown severity must not rank alongside real ones")
	}
}

func TestParseSeverity(t *testing.T) {
	for _, ok := range []string{"info", "low", "medium", "high", "critical"} {
		if _, err := ParseSeverity(ok); err != nil {
			t.Errorf("ParseSeverity(%q) = %v", ok, err)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Error("ParseSeverity accepted a severity that does not exist")
	}
}

func TestLint_sorts_the_worst_findings_first(t *testing.T) {
	f := Lint(parseFixture(t, "node-express.Dockerfile"))
	for i := 1; i < len(f); i++ {
		if f[i].Severity.Rank() > f[i-1].Severity.Rank() {
			t.Fatalf("finding %d (%s) outranks the one before it (%s)", i, f[i].Severity, f[i-1].Severity)
		}
	}
}

// Google's distroless and Chainguard's images set a non-root user in the image
// itself and say so in the tag. Flagging them would mean flagging the exact
// arrangement docker-trim recommends, which is how a tool teaches people to ignore it.
func TestDT010_accepts_a_base_image_that_already_drops_privileges(t *testing.T) {
	quiet := []string{
		"FROM gcr.io/distroless/static-debian12:nonroot\nCOPY app /app\nCMD [\"/app\"]\n",
		"FROM gcr.io/distroless/nodejs20-debian12:nonroot\nCMD [\"/app/s.js\"]\n",
		"FROM cgr.dev/chainguard/static:latest-nonroot\nCOPY app /app\nCMD [\"/app\"]\n",
	}
	for _, src := range quiet {
		if got := ids(Lint(parseString(t, src)))["DT010"]; got != 0 {
			t.Errorf("DT010 fired on a base that already runs as non-root:\n%s", src)
		}
	}

	loud := []string{
		// The same image family without the nonroot tag runs as root.
		"FROM gcr.io/distroless/static-debian12:latest\nCOPY app /app\nCMD [\"/app\"]\n",
		"FROM debian:12\nCMD [\"/app\"]\n",
	}
	for _, src := range loud {
		if got := ids(Lint(parseString(t, src)))["DT010"]; got == 0 {
			t.Errorf("DT010 stayed quiet for an image that does run as root:\n%s", src)
		}
	}
}

// An explicit USER root is a deliberate escalation and must still be reported,
// even when the base image would otherwise have dropped privileges.
func TestDT010_reports_an_explicit_user_root_over_a_nonroot_base(t *testing.T) {
	src := "FROM gcr.io/distroless/static-debian12:nonroot\nUSER root\nCMD [\"/app\"]\n"
	if got := ids(Lint(parseString(t, src)))["DT010"]; got == 0 {
		t.Error("DT010 did not fire for an explicit USER root")
	}
}

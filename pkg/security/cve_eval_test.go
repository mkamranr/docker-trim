package security

import (
	"strings"
	"testing"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
)

// The ruleset is embedded at build time, so a malformed file would panic at
// first use rather than fail a build.
func TestEmbeddedRuleset_parses_and_is_complete(t *testing.T) {
	if len(rules) == 0 {
		t.Fatal("the embedded ruleset is empty")
	}
	for name, e := range rules {
		if e.Name != name {
			t.Errorf("entry keyed %q has name %q", name, e.Name)
		}
		if e.Class == "" || e.Why == "" {
			t.Errorf("%s: missing class or explanation", name)
		}
		if e.Weight <= 0 {
			t.Errorf("%s: weight %d, want a positive contribution", name, e.Weight)
		}
		if _, ok := classNouns[e.Class]; !ok {
			t.Errorf("%s: class %q has no display name in classNouns", name, e.Class)
		}
	}
	for _, must := range []string{"bash", "curl", "apt-get", "gcc", "sudo"} {
		if _, ok := rules[must]; !ok {
			t.Errorf("the ruleset does not cover %q", must)
		}
	}
}

func parse(t *testing.T, src string) *analyzer.Analysis {
	t.Helper()
	a, err := analyzer.Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEvaluateDockerfile_counts_a_debian_base_as_carrying_a_shell(t *testing.T) {
	s := EvaluateDockerfile(parse(t, "FROM debian:12\nCMD [\"true\"]\n"))

	byClass := s.ByClass()
	if len(byClass["shell"]) == 0 {
		t.Error("a debian base carries a shell and that was not counted")
	}
	if len(byClass["package-manager"]) == 0 {
		t.Error("a debian base carries apt and that was not counted")
	}
	if !s.RunsAsRoot {
		t.Error("no USER was set, so the image runs as root")
	}
}

func TestEvaluateDockerfile_scores_distroless_far_lower_than_debian(t *testing.T) {
	debian := EvaluateDockerfile(parse(t,
		"FROM debian:12\nRUN apt-get install -y curl git gcc\nCMD [\"/app\"]\n"))
	distroless := EvaluateDockerfile(parse(t,
		"FROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot\nCMD [\"/app\"]\n"))

	if distroless.Score >= debian.Score {
		t.Errorf("distroless scored %d, debian %d: the minimal base must score lower",
			distroless.Score, debian.Score)
	}
	if distroless.RunsAsRoot {
		t.Error("USER nonroot was set but the image is still counted as running as root")
	}
	if len(distroless.Items) != 0 {
		t.Errorf("distroless carries no shell or package manager, but got %v", distroless.Items)
	}
}

func TestCompare_lists_what_the_rewrite_removed(t *testing.T) {
	before := EvaluateDockerfile(parse(t,
		"FROM debian:12\nRUN apt-get install -y curl git gcc\nCMD [\"/app\"]\n"))
	after := EvaluateDockerfile(parse(t,
		"FROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot\nCMD [\"/app\"]\n"))

	a := Compare(before, &after)
	removed := map[string]bool{}
	for _, it := range a.Removed {
		removed[it.Name] = true
	}
	for _, want := range []string{"curl", "git", "gcc", "bash", "apt-get"} {
		if !removed[want] {
			t.Errorf("%q was not reported as removed; removed: %v", want, a.Removed)
		}
	}
	if a.CVEKnown {
		t.Error("CVEKnown must be false until docker-trim can actually measure one")
	}
	if !strings.Contains(strings.Join(a.Notes, " "), "not reported") {
		t.Errorf("the report does not say CVE counts are unavailable: %v", a.Notes)
	}
}

func TestSummary_reads_naturally(t *testing.T) {
	before := EvaluateDockerfile(parse(t,
		"FROM debian:12\nRUN apt-get install -y curl gcc\nCMD [\"/app\"]\n"))
	after := EvaluateDockerfile(parse(t,
		"FROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot\nCMD [\"/app\"]\n"))

	got := Compare(before, &after).Summary()
	for _, bad := range []string{"0 unused", "1 shells", "2 shell,", "networks"} {
		if strings.Contains(got, bad) {
			t.Errorf("summary reads badly (%q): %s", bad, got)
		}
	}
	if !strings.HasPrefix(got, "Removed ") {
		t.Errorf("summary = %q", got)
	}
}

func TestCompare_says_unchanged_when_nothing_moved(t *testing.T) {
	s := EvaluateDockerfile(parse(t, "FROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot\nCMD [\"/a\"]\n"))
	if got := Compare(s, &s).Summary(); got != "unchanged" {
		t.Errorf("summary = %q, want \"unchanged\"", got)
	}
}

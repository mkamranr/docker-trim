//go:build corpus

// A survey of docker-trim against real Dockerfiles.
//
// The rest of the test suite uses fixtures this project wrote, which is a
// friendly corpus: it contains the shapes docker-trim was designed for and none of
// the ones nobody thought of. This runs the same guarantees against files
// written by strangers, and reports what fraction of them docker-trim can actually
// handle.
//
// It is not a pass/fail gate. It prints a survey, and fails only on the things
// that are always bugs: a panic, or output that does not parse.
//
//	DOCKER_TRIM_CORPUS=tests/corpus go test -tags corpus ./tests/ -run Corpus -v
package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
	"github.com/mkamranr/docker-trim/pkg/synthesizer"
)

type outcome struct {
	file string
	// what happened
	parseErr    error
	reparseErr  error
	lossy       bool
	panicked    string
	ecosystem   string
	stages      int
	restructure bool
	declined    string
	findings    int
}

func TestCorpus(t *testing.T) {
	dir := os.Getenv("DOCKER_TRIM_CORPUS")
	if dir == "" {
		t.Skip("set DOCKER_TRIM_CORPUS to a directory of real Dockerfiles")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no files in %s", dir)
	}

	// Every base, because a crash or a bad emit may only happen on one of them.
	for _, base := range []synthesizer.Base{
		synthesizer.BaseDistroless, synthesizer.BaseAlpine, synthesizer.BaseScratch,
	} {
		var results []outcome
		for _, f := range files {
			if info, err := os.Stat(f); err != nil || info.IsDir() {
				continue
			}
			results = append(results, survey(f, base))
		}
		t.Logf("=== --base %s ===", base)
		report(t, results)
	}
}

// survey runs every guarantee docker-trim claims against one file.
func survey(path string, base synthesizer.Base) (res outcome) {
	res.file = filepath.Base(path)

	// A panic is always a bug, and one bad file must not stop the survey.
	defer func() {
		if r := recover(); r != nil {
			res.panicked = fmt.Sprint(r)
		}
	}()

	src, err := os.ReadFile(path)
	if err != nil {
		res.parseErr = err
		return res
	}

	a, err := analyzer.ParseFile(path)
	if err != nil {
		res.parseErr = err
		return res
	}
	res.stages = len(a.Stages)
	res.ecosystem = string(synthesizer.DetectEcosystem(a))

	// Claim 1: a file docker-trim has not changed comes back byte for byte.
	if got := synthesizer.Render(a); got != string(src) {
		res.lossy = true
	}

	// Claim 2: whatever docker-trim emits is a Dockerfile.
	plan := synthesizer.Optimize(a, synthesizer.Options{
		Base:           base,
		Aggressiveness: analyzer.ConfidenceLikely,
	})
	res.restructure = plan.Restructured
	res.declined = plan.Plan.Reason
	res.findings = len(plan.Remaining)

	out := synthesizer.Render(a)
	if _, err := analyzer.Parse(strings.NewReader(out)); err != nil {
		res.reparseErr = err
	}
	return res
}

func report(t *testing.T, results []outcome) {
	var (
		parseFailed  []outcome
		reparseBad   []outcome
		lossy        []outcome
		panicked     []outcome
		restructured int
		declines     = map[string]int{}
		ecosystems   = map[string]int{}
	)
	for _, r := range results {
		switch {
		case r.panicked != "":
			panicked = append(panicked, r)
			continue
		case r.parseErr != nil:
			parseFailed = append(parseFailed, r)
			continue
		}
		if r.reparseErr != nil {
			reparseBad = append(reparseBad, r)
		}
		if r.lossy {
			lossy = append(lossy, r)
		}
		ecosystems[r.ecosystem]++
		if r.restructure {
			restructured++
		} else {
			declines[declineReason(r.declined)]++
		}
	}

	total := len(results)
	t.Logf("surveyed %d real Dockerfiles", total)
	t.Logf("  parsed              %d (%.0f%%)", total-len(parseFailed)-len(panicked),
		pct(total-len(parseFailed)-len(panicked), total))
	t.Logf("  restructured        %d (%.0f%%)", restructured, pct(restructured, total))
	t.Logf("  declined            %d (%.0f%%)", total-restructured-len(parseFailed)-len(panicked),
		pct(total-restructured-len(parseFailed)-len(panicked), total))

	t.Log("  ecosystems detected:")
	for _, k := range sortedKeysOf(ecosystems) {
		t.Logf("    %-10s %d", k, ecosystems[k])
	}
	t.Log("  reasons for declining:")
	for _, k := range sortedKeysOf(declines) {
		t.Logf("    %3d  %s", declines[k], k)
	}

	// These are always bugs, whatever the file looked like.
	for _, r := range panicked {
		t.Errorf("PANIC on %s: %s", r.file, r.panicked)
	}
	for _, r := range reparseBad {
		t.Errorf("EMITTED UNPARSEABLE OUTPUT for %s: %v", r.file, r.reparseErr)
	}
	for _, r := range lossy {
		t.Errorf("LOSSY ROUND TRIP for %s: rendering an unmodified file changed it", r.file)
	}

	// A parse failure may be the file's fault rather than docker-trim's, so these are
	// reported without failing.
	for _, r := range parseFailed {
		t.Logf("  could not parse %s: %v", r.file, r.parseErr)
	}
}

// declineReason collapses a reason to its first sentence, so the survey groups
// them instead of printing one line per file.
func declineReason(r string) string {
	if r == "" {
		return "(no reason given)"
	}
	if i := strings.Index(r, ". "); i > 0 {
		return r[:i]
	}
	return strings.TrimSuffix(r, ".")
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

func sortedKeysOf(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

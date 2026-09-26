package tests

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
	"github.com/mkamranr/docker-trim/pkg/synthesizer"
)

// update rewrites the golden files instead of comparing against them.
//
// Regenerating is not the same as reviewing. A golden diff is docker-trim telling
// you the Dockerfile it emits has changed; read every line of it before
// running with -update, because these files are the record of what the tool
// actually produces.
var update = flag.Bool("update", false, "rewrite the golden files in tests/golden")

// bases is the set of rewrites recorded for each fixture.
var bases = []synthesizer.Base{
	synthesizer.BaseDistroless,
	synthesizer.BaseAlpine,
	synthesizer.BaseScratch,
}

func TestGolden(t *testing.T) {
	entries, err := os.ReadDir("fixtures")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".Dockerfile") {
			continue
		}
		for _, base := range bases {
			name := strings.TrimSuffix(e.Name(), ".Dockerfile") + "." + string(base)
			t.Run(name, func(t *testing.T) {
				a, err := analyzer.ParseFile(filepath.Join("fixtures", e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				res := synthesizer.Optimize(a, synthesizer.Options{Base: base, Aggressiveness: analyzer.ConfidenceLikely})
				got := header(res) + synthesizer.Render(a)

				path := filepath.Join("golden", name+".trimmed")
				if *update {
					if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
						t.Fatal(err)
					}
					return
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("no golden file: %v\nrun `go test ./tests -update` and review the result", err)
				}
				if got != string(want) {
					t.Errorf("output changed.\n--- want ---\n%s\n--- got ---\n%s", want, got)
				}
			})
		}
	}
}

// header records the decision alongside the file, so a golden diff shows both
// what changed and why docker-trim chose it.
func header(res *synthesizer.Result) string {
	var b strings.Builder
	b.WriteString("# ecosystem: " + string(res.Plan.Ecosystem) + "\n")
	b.WriteString("# restructured: ")
	if res.Restructured {
		b.WriteString("yes\n# builder: " + res.Plan.Builder + "\n# runtime: " + res.Plan.Runtime + "\n")
	} else {
		b.WriteString("no\n# reason: " + res.Plan.Reason + "\n")
	}
	for _, w := range res.Plan.Warnings {
		b.WriteString("# warning: " + w + "\n")
	}
	b.WriteString("# ---\n")
	return b.String()
}

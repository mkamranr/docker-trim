package synthesizer

import (
	"strings"
	"testing"

	"github.com/mkamranr/dtrim/pkg/analyzer"
)

// The failure this feature exists to prevent: a rewrite that is dramatically
// smaller, builds cleanly, and then dies the first time the program shells out.
// Nothing static can see it; the trace can.
func TestCheckRuntimeCoverage_flags_a_shell_that_distroless_will_not_have(t *testing.T) {
	plan := Plan{
		Supported: true,
		Runtime:   distrolessStatic,
		Artifacts: []Artifact{{From: "/src/bin/app", To: "/src/bin/app"}},
	}
	gaps := checkRuntimeCoverage(plan, &analyzer.TraceManifest{
		UsedBinaries: []string{"/src/bin/app", "/bin/sh", "/usr/bin/curl"},
	})

	if len(gaps) != 2 {
		t.Fatalf("gaps = %+v, want the shell and curl", gaps)
	}
	var names []string
	for _, g := range gaps {
		names = append(names, g.Binary)
		if !strings.Contains(g.Explain(), g.Binary) {
			t.Errorf("the explanation does not name the binary: %q", g.Explain())
		}
	}
	if strings.Join(names, ",") != "/bin/sh,/usr/bin/curl" {
		t.Errorf("gaps = %v", names)
	}
}

// The artifact being copied is present by definition, and so is anything
// underneath a copied directory. Warning about those would be noise, and noise
// is how a warning gets ignored.
func TestCheckRuntimeCoverage_accepts_what_is_being_copied(t *testing.T) {
	plan := Plan{
		Supported: true,
		Runtime:   distrolessStatic,
		Artifacts: []Artifact{{From: "/app", To: "/app"}},
	}
	gaps := checkRuntimeCoverage(plan, &analyzer.TraceManifest{
		UsedBinaries: []string{"/app/server", "/app/bin/worker"},
	})
	if len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none: everything is under the copied directory", gaps)
	}
}

func TestCheckRuntimeCoverage_knows_what_each_base_provides(t *testing.T) {
	cases := []struct {
		name    string
		runtime string
		binary  string
		wantGap bool
	}{
		{"scratch has nothing", "scratch", "/bin/sh", true},
		{"distroless has no shell", distrolessStatic, "/bin/sh", true},
		{"distroless/nodejs has node", "gcr.io/distroless/nodejs20-debian12:nonroot", "/nodejs/bin/node", false},
		{"distroless/nodejs has no shell", "gcr.io/distroless/nodejs20-debian12:nonroot", "/bin/sh", true},
		{"distroless/python has python3", "gcr.io/distroless/python3-debian12:nonroot", "/usr/bin/python3", false},
		{"alpine has busybox sh", "alpine:3.21", "/bin/sh", false},
		{"alpine has busybox wget", "alpine:3.21", "/usr/bin/wget", false},
		{"alpine has no bash", "alpine:3.21", "/bin/bash", true},
		{"alpine has no curl", "alpine:3.21", "/usr/bin/curl", true},
		// Staying on the same Debian base changes nothing, so nothing is lost.
		{"a slim base keeps its userland", "python:3.12-slim", "/bin/sh", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := Plan{Supported: true, Runtime: c.runtime}
			gaps := checkRuntimeCoverage(plan, &analyzer.TraceManifest{UsedBinaries: []string{c.binary}})
			if got := len(gaps) > 0; got != c.wantGap {
				t.Errorf("%s on %s: gap = %v, want %v", c.binary, c.runtime, got, c.wantGap)
			}
		})
	}
}

func TestCheckRuntimeCoverage_is_silent_without_a_trace(t *testing.T) {
	plan := Plan{Supported: true, Runtime: distrolessStatic}
	if gaps := checkRuntimeCoverage(plan, nil); gaps != nil {
		t.Errorf("gaps = %+v, want none without evidence", gaps)
	}
	if gaps := checkRuntimeCoverage(plan, &analyzer.TraceManifest{}); gaps != nil {
		t.Errorf("gaps = %+v, want none from an empty trace", gaps)
	}
	// A plan that is not going to restructure cannot introduce a gap.
	if gaps := checkRuntimeCoverage(Plan{Supported: false, Runtime: "scratch"},
		&analyzer.TraceManifest{UsedBinaries: []string{"/bin/sh"}}); gaps != nil {
		t.Errorf("gaps = %+v, want none when nothing is being restructured", gaps)
	}
}

// The gap has to reach the caller, not just exist internally.
func TestOptimize_surfaces_runtime_gaps_as_warnings(t *testing.T) {
	a := parseFixture(t, "go-api.Dockerfile")
	res := Optimize(a, Options{
		Base:           BaseDistroless,
		Aggressiveness: analyzer.ConfidenceLikely,
		Trace:          &analyzer.TraceManifest{UsedBinaries: []string{"/bin/sh"}},
	})

	if len(res.RuntimeGaps) == 0 {
		t.Fatal("a traced shell on a distroless runtime produced no gap")
	}
	if !strings.Contains(res.RuntimeGaps[0].Explain(), "/bin/sh") {
		t.Errorf("the gap does not name the binary: %q", res.RuntimeGaps[0].Explain())
	}
	// Gaps get their own block in the report, so duplicating them into the
	// plan's warnings would show the same problem twice.
	if strings.Contains(strings.Join(res.Plan.Warnings, " "), "/bin/sh") {
		t.Errorf("the gap was duplicated into the plan warnings: %v", res.Plan.Warnings)
	}
}

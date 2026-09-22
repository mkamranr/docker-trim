//go:build integration

// Reduction bands. These build real images with Docker and measure them, which
// is the only way a size claim in the README is worth anything.
//
// Run with: make integration
package tests

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mkamranr/dtrim/pkg/analyzer"
	"github.com/mkamranr/dtrim/pkg/synthesizer"
	"github.com/mkamranr/dtrim/pkg/tracer"
)

// bands are the minimum size reductions dtrim must achieve on each sample
// project. They are floors, not targets: the README quotes these numbers, and
// this test is what stops the README from drifting into fiction.
//
// Lower one only with a measurement and a note saying what changed.
var bands = map[string]float64{
	"goapp":   95.0, // a Go binary on distroless/static is almost all base image
	"pyapp":   40.0, // Python's saving is the build toolchain, not the interpreter
	"nodeapp": 50.0,
}

func TestReductionBands(t *testing.T) {
	if os.Getenv("DTRIM_INTEGRATION") == "" {
		t.Skip("set DTRIM_INTEGRATION=1 to run tests that build real images")
	}
	ctx := context.Background()
	if err := tracer.Available(ctx); err != nil {
		t.Skipf("no usable Docker engine: %v", err)
	}

	for name, floor := range bands {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join("projects", name)
			if _, err := os.Stat(dir); err != nil {
				t.Skipf("sample project %s is not present", dir)
			}

			a, err := analyzer.ParseFile(filepath.Join(dir, "Dockerfile"))
			if err != nil {
				t.Fatal(err)
			}
			res := synthesizer.Optimize(a, synthesizer.BaseDistroless, analyzer.ConfidenceLikely)
			if !res.Restructured {
				t.Fatalf("declined to restructure %s: %s", name, res.Plan.Reason)
			}

			trimmedPath := filepath.Join(dir, "Dockerfile.trimmed")
			if err := os.WriteFile(trimmedPath, []byte(synthesizer.Render(a)), 0o644); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Remove(trimmedPath) }()

			origTag := fmt.Sprintf("dtrim-band-%s:orig", name)
			trimTag := fmt.Sprintf("dtrim-band-%s:trim", name)
			defer tracer.Remove(ctx, origTag, trimTag)

			originalSize, err := tracer.Build(ctx, tracer.BuildRequest{
				Dockerfile: filepath.Join(dir, "Dockerfile"), Context: dir, Tag: origTag})
			if err != nil {
				t.Fatalf("the sample project does not build: %v", err)
			}
			trimmedSize, err := tracer.Build(ctx, tracer.BuildRequest{
				Dockerfile: trimmedPath, Context: dir, Tag: trimTag})
			if err != nil {
				t.Fatalf("the trimmed Dockerfile does not build, which is a dtrim bug: %v", err)
			}

			// Trimming must never make an image bigger.
			if trimmedSize > originalSize {
				t.Fatalf("trimmed image is larger: %d > %d bytes", trimmedSize, originalSize)
			}

			got := (1 - float64(trimmedSize)/float64(originalSize)) * 100
			t.Logf("%s: %d -> %d bytes, -%.1f%%", name, originalSize, trimmedSize, got)
			if got < floor {
				t.Errorf("reduction %.1f%% is below the %.1f%% floor the README quotes", got, floor)
			}

			// Smaller and broken is not an improvement.
			smoke := tracer.Smoke(ctx, trimTag, 15*time.Second)
			if !smoke.Started {
				t.Errorf("the trimmed image does not run: %s\n%s", smoke.Reason, smoke.Output)
			}
		})
	}
}

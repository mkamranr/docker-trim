package dtrim

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mkamranr/dtrim/pkg/analyzer"
	"github.com/mkamranr/dtrim/pkg/security"
	"github.com/mkamranr/dtrim/pkg/synthesizer"
)

// SchemaVersion is the version of the JSON report. It changes only when an
// existing field changes meaning or disappears, so a consumer can pin to it.
const SchemaVersion = 1

// Report is everything a run produced. It is what --quiet serialises and what
// the terminal reporter renders.
type Report struct {
	SchemaVersion int    `json:"schemaVersion"`
	Tool          string `json:"tool"`

	Dockerfile *DockerfileReport     `json:"dockerfile,omitempty"`
	Image      *analyzer.ImageReport `json:"image,omitempty"`
	Security   *security.Assessment  `json:"security,omitempty"`
	Result     OptimizationResult    `json:"optimization"`
	// Verification is present only when --verify actually built both images,
	// which is the only way a size in this report is a measurement.
	Verification *Verification `json:"verification,omitempty"`
	Findings     []Finding     `json:"findings"`
	Fixed        []Finding     `json:"fixed,omitempty"`
	Notes        []string      `json:"notes,omitempty"`
}

// DockerfileReport describes the file that was analyzed and what dtrim did
// with it.
type DockerfileReport struct {
	Path string `json:"path"`
	// Output is where the trimmed file was written, empty if nothing was.
	Output string `json:"output,omitempty"`
	// Ecosystem is the toolchain dtrim recognised.
	Ecosystem string `json:"ecosystem"`
	// Stages is the stage count of the input.
	Stages int `json:"stages"`
	// Restructured reports whether a builder stage was introduced.
	Restructured bool `json:"restructured"`
	// BuilderBase and RuntimeBase describe the rewrite, when there was one.
	BuilderBase string `json:"builderBase,omitempty"`
	RuntimeBase string `json:"runtimeBase,omitempty"`
	// Reason explains a declined rewrite.
	Reason string `json:"reason,omitempty"`
	// Original and Trimmed are the file contents, for the diff writer.
	Original string `json:"-"`
	Trimmed  string `json:"-"`
	// Warnings are things the author needs to know before building the result.
	Warnings []string `json:"warnings,omitempty"`
}

// Run executes the pipeline described in the PRD: parse and analyze, inspect
// the image, rewrite, score the attack surface, and report.
//
// It never writes anything when cfg.AnalyzeOnly is set, and it never reports a
// size it did not measure: without --verify the OptimizationResult carries
// Measured=false and the reporter labels the numbers as estimates.
func Run(ctx context.Context, cfg Config) (*Report, error) {
	start := time.Now()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	rep := &Report{SchemaVersion: SchemaVersion, Tool: "dtrim"}

	if cfg.Image != "" {
		img, err := analyzer.InspectImage(ctx, cfg.Image)
		if err != nil {
			return nil, err
		}
		rep.Image = img
		rep.Notes = append(rep.Notes, img.Notes...)

		surface := security.EvaluateImage(img)
		assessment := security.Compare(surface, nil)
		rep.Security = &assessment
		rep.Result.OriginalSizeBytes = img.TotalSize
	}

	if cfg.File != "" {
		if err := runDockerfile(ctx, cfg, rep); err != nil {
			return nil, err
		}
	}

	rep.Result.Duration = time.Since(start)
	rep.Result.DurationMS = rep.Result.Duration.Milliseconds()
	if rep.Result.OriginalSizeBytes > 0 && rep.Result.TrimmedSizeBytes > 0 {
		rep.Result.ReductionRatio = 1 - float64(rep.Result.TrimmedSizeBytes)/float64(rep.Result.OriginalSizeBytes)
	}
	return rep, nil
}

func runDockerfile(ctx context.Context, cfg Config, rep *Report) error {
	original, err := os.ReadFile(cfg.File)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", cfg.File, err)
	}
	a, err := analyzer.ParseFile(cfg.File)
	if err != nil {
		return err
	}

	before := security.EvaluateDockerfile(a)
	stages := len(a.Stages)

	df := &DockerfileReport{
		Path:     cfg.File,
		Stages:   stages,
		Original: string(original),
	}
	rep.Dockerfile = df

	// --analyze-only is read-only by contract: report what is there and stop.
	if cfg.AnalyzeOnly || !cfg.Optimize {
		df.Ecosystem = string(synthesizer.DetectEcosystem(a))
		rep.Findings = analyzer.Lint(a)
		if rep.Security == nil {
			assessment := security.Compare(before, nil)
			rep.Security = &assessment
		}
		return nil
	}

	res := synthesizer.Optimize(a, cfg.Base, cfg.Aggressiveness)
	trimmed := synthesizer.Render(a)

	df.Ecosystem = string(res.Plan.Ecosystem)
	df.Restructured = res.Restructured
	df.Reason = res.Plan.Reason
	df.Warnings = res.Plan.Warnings
	df.Trimmed = trimmed
	if res.Restructured {
		df.BuilderBase = res.Plan.Builder
		df.RuntimeBase = res.Plan.Runtime
	}

	rep.Fixed = res.Fixed
	rep.Findings = res.Remaining
	rep.Notes = append(rep.Notes, res.Notes...)
	rep.Result.RemovedPackagesCount = len(res.Fixed)

	after := security.EvaluateDockerfile(a)
	assessment := security.Compare(before, &after)
	rep.Security = &assessment
	rep.Result.RemovedPackagesCount = assessment.RemovedPackages

	if err := writeOutput(cfg, trimmed, string(original), df); err != nil {
		return err
	}
	if cfg.Verify {
		if err := verify(ctx, cfg, rep); err != nil {
			return err
		}
	}
	return nil
}

// writeOutput writes the trimmed Dockerfile, unless it is identical to the
// input, in which case there is nothing to write and saying so is more useful
// than leaving a duplicate file behind.
func writeOutput(cfg Config, trimmed, original string, df *DockerfileReport) error {
	if trimmed == original {
		return nil
	}
	out := cfg.Output
	if out == "" {
		out = "Dockerfile.trimmed"
	}
	if dir := filepath.Dir(out); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("cannot create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(out, []byte(trimmed), 0o644); err != nil {
		return fmt.Errorf("cannot write %s: %w", out, err)
	}
	df.Output = out
	return nil
}

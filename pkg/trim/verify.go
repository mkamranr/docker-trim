package trim

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
	"github.com/mkamranr/docker-trim/pkg/tracer"
)

// smokeWindow is how long a trimmed image is watched before it is accepted as
// working.
//
// It was five seconds, which was not enough: a Python service spent longer
// than that walking its import graph before dying on a missing module, and the
// check called the broken image good. Fifteen seconds covers a heavy import
// chain. Surviving the window is evidence of not having crashed, not proof of
// correctness, and the report says so.
const smokeWindow = 15 * time.Second

// Verification records what building both images actually showed.
type Verification struct {
	OriginalSizeBytes int64              `json:"originalSizeBytes"`
	TrimmedSizeBytes  int64              `json:"trimmedSizeBytes"`
	Smoke             tracer.SmokeResult `json:"smoke"`
}

// verify builds the original and the trimmed Dockerfile against the same
// context and measures both.
//
// This is what turns an estimate into a number worth publishing. Everything
// docker-trim prints as a measurement comes from here; without it, sizes stay
// labelled as estimates.
func verify(ctx context.Context, cfg Config, rep *Report) error {
	df := rep.Dockerfile
	if df == nil || df.Output == "" {
		rep.Notes = append(rep.Notes,
			"Nothing changed, so there was no trimmed image to build and --verify had nothing to measure.")
		return nil
	}
	if err := tracer.Available(ctx); err != nil {
		return fmt.Errorf("--verify needs a working Docker engine: %w", err)
	}

	buildContext := cfg.Context
	if buildContext == "" {
		buildContext = filepath.Dir(cfg.File)
	}

	id := tracer.ShortHash(cfg.File + df.Trimmed)
	origTag := "docker-trim-verify-original:" + id
	trimTag := "docker-trim-verify-trimmed:" + id
	defer tracer.Remove(context.WithoutCancel(ctx), origTag, trimTag)

	// Docker's own build output is long and drowns the report. Show it only
	// when asked; otherwise say what is happening in one line, because these
	// builds take minutes and silence looks like a hang.
	var progress io.Writer
	status := io.Discard
	if !cfg.Quiet {
		status = cfg.Stderr
		if cfg.Verbose {
			progress = cfg.Stderr
		}
	}

	_, _ = fmt.Fprintf(status, "[docker-trim] Building the original image to measure it...\n")
	originalSize, err := tracer.Build(ctx, tracer.BuildRequest{
		Dockerfile: cfg.File, Context: buildContext, Tag: origTag, Progress: progress})
	if err != nil {
		return fmt.Errorf("the original Dockerfile does not build, so there is nothing to compare against: %w", err)
	}

	_, _ = fmt.Fprintf(status, "[docker-trim] Building the trimmed image...\n")
	trimmedSize, err := tracer.Build(ctx, tracer.BuildRequest{
		Dockerfile: df.Output, Context: buildContext, Tag: trimTag, Progress: progress})
	if err != nil {
		return fmt.Errorf("the trimmed Dockerfile does not build. This is a docker-trim bug: please "+
			"open a bad-rewrite issue with %s attached.\n%w", df.Output, err)
	}

	_, _ = fmt.Fprintf(status, "[docker-trim] Starting the trimmed image to check it still runs...\n")
	smoke := tracer.Smoke(ctx, trimTag, smokeWindow)

	// While the image still exists: the cleanup defer registered above removes
	// it the moment this function returns, so there is nowhere later to do it.
	if cfg.OSV && rep.Vulnerabilities != nil {
		_, _ = fmt.Fprintf(status, "[docker-trim] Checking what the rewrite removed...\n")
		after, err := analyzer.InspectImage(ctx, trimTag)
		if err != nil {
			rep.Notes = append(rep.Notes,
				"The trimmed image could not be inspected, so no vulnerability reduction is "+
					"claimed: "+err.Error())
		} else if err := compareVulnerabilities(ctx, cfg, rep, after, "The trimmed image"); err != nil {
			return err
		}
	}

	rep.Result.OriginalSizeBytes = originalSize
	rep.Result.TrimmedSizeBytes = trimmedSize
	rep.Result.Measured = true
	rep.Verification = &Verification{
		OriginalSizeBytes: originalSize,
		TrimmedSizeBytes:  trimmedSize,
		Smoke:             smoke,
	}
	if !smoke.Started {
		// A service that needs a database or a queue exits on its own when
		// neither is reachable, and that says nothing about the packaging.
		// Point at both possibilities rather than crying bug.
		rep.Notes = append(rep.Notes,
			"The trimmed image built but exited: "+smoke.Reason+". If it needs a database or "+
				"another service that is not running here, that is expected. If the logs show a "+
				"missing module, a missing shared library or a missing interpreter, the rewrite "+
				"is at fault: please open a bad-rewrite issue.")
		if smoke.Output != "" {
			rep.Notes = append(rep.Notes, "Last lines from the container: "+smoke.Output)
		}
	}
	return nil
}

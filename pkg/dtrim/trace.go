package dtrim

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mkamranr/dtrim/pkg/analyzer"
	"github.com/mkamranr/dtrim/pkg/tracer"
)

// runTrace watches the image run and attributes what it touched back to the
// packages that installed those files.
func runTrace(ctx context.Context, cfg Config, rep *Report) error {
	backend, err := tracer.New(cfg.Tracer)
	if err != nil {
		return err
	}

	opts := tracer.DefaultOptions()
	opts.Image = cfg.Image
	if cfg.TraceTimeout > 0 {
		opts.Timeout = cfg.TraceTimeout
	}
	if cfg.Trace != "" {
		// A shell is how people write a test command, and splitting on spaces
		// would break the first one containing a pipe or a quoted argument.
		opts.Command = []string{"/bin/sh", "-c", cfg.Trace}
	}
	if !cfg.Quiet && cfg.Stderr != nil {
		opts.Progress = func(msg string) { _, _ = fmt.Fprintf(cfg.Stderr, "[dtrim] %s\n", msg) }
	}

	result, err := backend.Trace(ctx, opts)
	if err != nil {
		return err
	}

	usage := analyzer.AttributeUsage(rep.Image, result.Manifest)
	usage.Notes = append(usage.Notes, coverageNotes(result, cfg)...)

	rep.Trace = &TraceReport{
		Backend:    string(result.Backend),
		Command:    opts.Command,
		Manifest:   result.Manifest,
		Usage:      usage,
		Samples:    result.Samples,
		Processes:  result.Processes,
		ExitCode:   result.ExitCode,
		TimedOut:   result.TimedOut,
		DurationMS: result.Duration.Milliseconds(),
	}
	rep.Result.RemovedPackagesCount = len(usage.Unused)
	return nil
}

// coverageNotes say how far this trace should be trusted.
//
// The number that matters is not how many packages went untouched but how much
// of the program ran. A container that exited immediately, or one traced
// without a workload, has demonstrated nothing, and the report has to say so
// rather than letting a reader treat "unused" as "safe to delete".
func coverageNotes(r *tracer.Result, cfg Config) []string {
	var notes []string

	if cfg.Trace == "" {
		notes = append(notes,
			"No workload was given, so this trace only covers what the container does on "+
				"startup. Pass --trace with a command that exercises the application before "+
				"treating anything here as unused.")
	}
	// Sampling coverage only means something for the sampler.
	if r.Backend == tracer.BackendProc && r.Samples <= 2 {
		notes = append(notes, fmt.Sprintf(
			"The container was sampled only %d times, so almost nothing was observed. Treat "+
				"the unused list as meaningless at this coverage.", r.Samples))
	}
	// Sampling races with a short-lived process. A library loaded late in a
	// command that lives half a second may appear in no sample at all, so the
	// same trace run twice can disagree. Saying so is the difference between
	// evidence and a number that looks authoritative. ptrace has no such race,
	// so the warning would be false there.
	if r.Backend == tracer.BackendProc && !r.TimedOut && r.Duration > 0 && r.Duration < time.Second {
		notes = append(notes, fmt.Sprintf(
			"The traced command ran for only %s, which is short enough that sampling will have "+
				"missed things: a library loaded late may appear in no sample, and running this "+
				"trace again can produce a different list. Give it a longer workload before "+
				"acting on what it says.", r.Duration.Round(time.Millisecond)))
	}
	if r.ExitCode != 0 && !r.TimedOut {
		notes = append(notes, fmt.Sprintf(
			"The traced command exited with code %d. If it failed early, it did not reach the "+
				"code paths that use the packages reported as unused.", r.ExitCode))
	}
	switch r.Backend {
	case tracer.BackendPtrace:
		notes = append(notes,
			"Every execve and openat was observed, and only calls that succeeded were counted, "+
				"so nothing was missed within this run. What the run itself did not exercise is "+
				"still invisible: dtrim reports what to consider removing and leaves the "+
				"decision to you.")
	default:
		notes = append(notes,
			"Sampling /proc sees every binary that ran and every library that loaded, and can "+
				"miss a file opened and closed between two samples. --tracer ptrace misses "+
				"nothing, at the cost of needing CAP_SYS_PTRACE. Either way this is evidence, "+
				"not proof: dtrim reports what to consider removing and leaves the decision to you.")
	}
	return notes
}

// TraceSummary is the one-line description used in the report.
func (t *TraceReport) TraceSummary() string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%d files", len(t.Manifest.AccessedFiles)))
	parts = append(parts, fmt.Sprintf("%d binaries", len(t.Manifest.UsedBinaries)))
	parts = append(parts, fmt.Sprintf("%d shared libraries", len(t.Manifest.SharedLibs)))
	return strings.Join(parts, ", ")
}

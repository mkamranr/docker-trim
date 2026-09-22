package dtrim

import (
	"fmt"
	"io"
)

// TracerBackend selects how runtime tracing observes the container.
//
// Only "none" does anything in v0.1; the others are accepted and rejected with
// a pointer at the changelog so scripts written today keep working when the
// tracer lands. See docs/tracing.md for why the /proc sampler is the default
// backend rather than eBPF.
type TracerBackend string

// The runtime tracing backends. Only TracerNone does anything in this release;
// see docs/tracing.md.
const (
	TracerNone   TracerBackend = "none"
	TracerProc   TracerBackend = "proc"
	TracerPtrace TracerBackend = "ptrace"
	TracerEBPF   TracerBackend = "ebpf"
)

// ParseTracer validates the --tracer value.
func ParseTracer(s string) (TracerBackend, error) {
	switch TracerBackend(s) {
	case TracerNone, TracerProc, TracerPtrace, TracerEBPF:
		return TracerBackend(s), nil
	}
	return "", fmt.Errorf("unknown tracer %q: want none, proc, ptrace or ebpf", s)
}

// Config is everything the pipeline needs. It carries no CLI dependency, so the
// library can be driven from Go directly; see docs/library.md.
type Config struct {
	// File is the Dockerfile to parse and optimize (--file).
	File string
	// Image is a built image tag to inspect (--image), or the positional
	// argument when one is given.
	Image string
	// Trace is the command to run inside the container while tracing (--trace).
	Trace string
	// Base is the target minimal runtime base (--base).
	Base Base
	// Output is where the optimized Dockerfile is written (--output).
	Output string
	// Optimize turns on rewriting. Without it dtrim reports and writes nothing.
	Optimize bool
	// AnalyzeOnly forces a read-only run even if Optimize is set.
	AnalyzeOnly bool
	// Quiet suppresses progress output and emits the JSON report instead.
	Quiet bool
	// Verify builds the original and trimmed Dockerfiles and measures both.
	Verify bool
	// Aggressiveness gates which rules may auto-fix.
	Aggressiveness Confidence
	// Tracer selects the runtime tracing backend.
	Tracer TracerBackend
	// OSV enriches the report with real CVE data from api.osv.dev.
	OSV bool
	// Context is the build context directory. Defaults to the Dockerfile's
	// directory.
	Context string
	// FailOn makes dtrim exit non-zero when a finding of this severity or
	// worse survives. Empty means never fail on findings, which is the
	// default: a report is not an error unless you asked for it to be.
	FailOn Severity
	// NoColor disables ANSI colour regardless of TTY detection.
	NoColor bool
	// Verbose streams the underlying build output rather than a status line.
	Verbose bool

	// Stdout and Stderr default to os.Stdout / os.Stderr when nil.
	Stdout io.Writer
	Stderr io.Writer
}

// DefaultConfig returns the defaults from the PRD's flag matrix (section 3).
func DefaultConfig() Config {
	return Config{
		File:           "Dockerfile",
		Base:           BaseDistroless,
		Output:         "Dockerfile.trimmed",
		Aggressiveness: ConfidenceLikely,
		Tracer:         TracerNone,
	}
}

// Validate reports configuration that cannot produce a useful run.
func (c *Config) Validate() error {
	if c.File == "" && c.Image == "" {
		return fmt.Errorf("nothing to analyze: pass --file, --image, or a positional Dockerfile/image argument")
	}
	if _, err := ParseBase(string(c.Base)); err != nil {
		return err
	}
	if _, err := ParseTracer(string(c.Tracer)); err != nil {
		return err
	}
	if c.FailOn != "" && c.FailOn.Rank() < 0 {
		return fmt.Errorf("unknown --fail-on severity %q: want info, low, medium, high or critical", c.FailOn)
	}
	switch c.Aggressiveness {
	case ConfidenceSafe, ConfidenceLikely, ConfidenceAggressive:
	default:
		return fmt.Errorf("unknown aggressiveness %q: want safe, likely or aggressive", c.Aggressiveness)
	}
	if c.AnalyzeOnly && c.Verify {
		return fmt.Errorf("--analyze-only and --verify conflict: verification has to build images")
	}
	if c.Trace != "" && c.Tracer == TracerNone {
		return fmt.Errorf("--trace needs a --tracer backend; runtime tracing lands in 0.2 (see CHANGELOG)")
	}
	if c.Tracer != TracerNone {
		return fmt.Errorf("--tracer %s is not implemented in this release; runtime tracing is planned for 0.2 (see CHANGELOG)", c.Tracer)
	}
	return nil
}

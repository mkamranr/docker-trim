package dtrim

import (
	"fmt"
	"io"
	"time"

	"github.com/mkamranr/dtrim/pkg/tracer"
)

// TracerBackend selects how runtime tracing observes the container. See
// docs/tracing.md for why the /proc sampler is the default rather than eBPF.
type TracerBackend = tracer.Backend

// The runtime tracing backends.
const (
	TracerNone   = tracer.BackendNone
	TracerProc   = tracer.BackendProc
	TracerPtrace = tracer.BackendPtrace
	TracerEBPF   = tracer.BackendEBPF
)

// ParseTracer validates the --tracer value.
func ParseTracer(s string) (TracerBackend, error) { return tracer.ParseBackend(s) }

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
	// Compare names a second image to measure against, so the report can say
	// what a rewrite actually removed rather than only what the first one has.
	Compare string
	// TraceTimeout caps how long a traced container runs. A server never exits
	// on its own, so tracing one always ends here.
	TraceTimeout time.Duration
	// Context is the build context directory. Defaults to the Dockerfile's
	// directory.
	Context string
	// PruneUnused drops packages a trace never saw used from the install
	// commands that name them.
	PruneUnused bool
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
		TraceTimeout:   30 * time.Second,
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
		return fmt.Errorf("--trace needs a tracing backend: add --tracer proc")
	}
	if c.Compare != "" && !c.OSV {
		return fmt.Errorf("--compare measures the difference in vulnerabilities, so it needs --osv")
	}
	if c.Compare != "" && c.Image == "" {
		return fmt.Errorf("--compare needs a first image to measure against: add --image")
	}
	if c.OSV && c.Image == "" {
		return fmt.Errorf("--osv looks up the packages in a built image: add --image")
	}
	if c.PruneUnused && c.Tracer == TracerNone {
		return fmt.Errorf("--prune-unused needs evidence: add --tracer proc or --tracer ptrace, " +
			"and --trace with a command that exercises the application")
	}
	if c.Tracer != TracerNone {
		if c.Image == "" {
			return fmt.Errorf("--tracer needs an image to run: add --image")
		}
		if _, err := tracer.New(c.Tracer); err != nil {
			return err
		}
	}
	return nil
}

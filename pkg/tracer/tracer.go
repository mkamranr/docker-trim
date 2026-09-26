package tracer

import (
	"context"
	"fmt"
	"time"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
)

// Backend names a way of observing a running container.
type Backend string

const (
	// BackendNone does not trace at all.
	BackendNone Backend = "none"
	// BackendProc samples /proc from inside the container. It needs no added
	// capabilities, which is what makes it work everywhere.
	BackendProc Backend = "proc"
	// BackendPtrace decodes execve and openat exactly, missing nothing. Needs
	// CAP_SYS_PTRACE and an unconfined seccomp profile, and slows the traced
	// program down.
	BackendPtrace Backend = "ptrace"
	// BackendEBPF attaches kernel probes. Planned; needs a privileged sidecar
	// and a kernel exposing BTF.
	BackendEBPF Backend = "ebpf"
)

// ParseBackend validates a --tracer value.
func ParseBackend(s string) (Backend, error) {
	switch Backend(s) {
	case BackendNone, BackendProc, BackendPtrace, BackendEBPF:
		return Backend(s), nil
	}
	return "", fmt.Errorf("unknown tracer %q: want none, proc, ptrace or ebpf", s)
}

// Options describe one trace run.
type Options struct {
	// Image is the target to trace.
	Image string
	// Command overrides what runs inside the container. Empty means the
	// image's own entrypoint and command, which is what you want when the
	// question is "what does this container need in order to start".
	Command []string
	// Interval is how often /proc is sampled.
	Interval time.Duration
	// Settle keeps tracing for this long after the command exits.
	Settle time.Duration
	// Timeout caps the whole run. A server never exits on its own, so tracing
	// one always ends here.
	Timeout time.Duration
	// Progress receives status lines when non-nil.
	Progress func(string)
}

// Result is a trace plus what it says about coverage.
//
// Coverage matters as much as the manifest: a trace that took two samples of a
// process that exited immediately has seen almost nothing, and a report that
// presents that as "these are the files this image needs" would be lying.
type Result struct {
	Manifest analyzer.TraceManifest `json:"manifest"`
	// Samples is how many times /proc was walked.
	Samples int `json:"samples"`
	// Processes is how many distinct pids were seen.
	Processes int `json:"processes"`
	// Duration is how long the traced command ran.
	Duration time.Duration `json:"-"`
	// ExitCode is what the traced command returned.
	ExitCode int `json:"exitCode"`
	// TimedOut reports that the command was still running when the timeout
	// arrived, which for a server is the normal outcome.
	TimedOut bool `json:"timedOut"`
	// Backend records which backend produced this.
	Backend Backend `json:"backend"`
}

// Tracer observes a container and reports what it touched.
type Tracer interface {
	// Trace runs the container and returns what it used.
	Trace(ctx context.Context, opts Options) (*Result, error)
	// Backend names the implementation.
	Backend() Backend
}

// New returns the tracer for a backend, or an error explaining why that backend
// is not available here.
func New(b Backend) (Tracer, error) {
	switch b {
	case BackendProc:
		return procTracer{}, nil
	case BackendPtrace:
		return ptraceTracer{}, nil
	case BackendEBPF:
		return nil, fmt.Errorf("the eBPF backend is not implemented yet, and needs a kernel " +
			"exposing /sys/kernel/btf/vmlinux; use --tracer proc (see docs/tracing.md)")
	case BackendNone:
		return nil, fmt.Errorf("no tracer selected")
	}
	return nil, fmt.Errorf("unknown tracer %q", b)
}

// DefaultOptions fills in the timings.
func DefaultOptions() Options {
	return Options{
		Interval: 50 * time.Millisecond,
		Settle:   250 * time.Millisecond,
		Timeout:  30 * time.Second,
	}
}

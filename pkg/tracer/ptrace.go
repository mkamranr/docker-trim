package tracer

import (
	"context"
	"fmt"
	"strings"
)

// ptraceTracer stops the traced process at every syscall boundary and records
// the ones that matter.
//
// Where the /proc sampler takes snapshots and can miss anything that happens
// between two of them, this misses nothing by construction: every execve and
// every openat is observed, and observed on the way out, so a failed open is
// never counted as a use.
//
// The price is privileges and speed. The container needs CAP_SYS_PTRACE and an
// unconfined seccomp profile, which not every environment will grant, and every
// traced syscall costs two context switches. That is why this is opt-in rather
// than the default. See docs/tracing.md.
type ptraceTracer struct{}

func (ptraceTracer) Backend() Backend { return BackendPtrace }

// ptraceDockerFlags are what the kernel needs before one process may trace
// another inside a container.
//
// The default seccomp profile blocks ptrace outright, so allowing the
// capability alone is not enough. Both are scoped to the throwaway container
// dtrim builds for the trace and never touch the image being analysed.
var ptraceDockerFlags = []string{
	"--cap-add=SYS_PTRACE",
	"--security-opt", "seccomp=unconfined",
}

func (t ptraceTracer) Trace(ctx context.Context, opts Options) (*Result, error) {
	if err := Available(ctx); err != nil {
		return nil, fmt.Errorf("tracing needs a working Docker engine: %w", err)
	}
	if opts.Image == "" {
		return nil, fmt.Errorf("no image to trace")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultOptions().Timeout
	}
	progress := opts.Progress
	if progress == nil {
		progress = func(string) {}
	}

	command := opts.Command
	if len(command) == 0 {
		cfg, err := imageCommand(ctx, opts.Image)
		if err != nil {
			return nil, err
		}
		command = cfg
	}
	if len(command) == 0 {
		return nil, fmt.Errorf("%s declares no entrypoint or command, so there is nothing to "+
			"trace. Pass --trace with the command to run", opts.Image)
	}
	opts.Command = command

	progress("building an instrumented copy of " + opts.Image)
	tag, err := buildInstrumented(ctx, opts.Image, opts, BackendPtrace)
	if err != nil {
		return nil, err
	}
	defer Remove(context.WithoutCancel(ctx), tag)

	progress(fmt.Sprintf("running %s under ptrace for up to %s",
		strings.Join(command, " "), opts.Timeout))

	res, err := runTraced(ctx, tag, opts, BackendPtrace, ptraceDockerFlags)
	if err != nil {
		return nil, fmt.Errorf("%w\n\nIf the container could not be traced, this environment "+
			"may not permit ptrace even with CAP_SYS_PTRACE. Use --tracer proc, which needs no "+
			"privileges at all", err)
	}
	return res, nil
}

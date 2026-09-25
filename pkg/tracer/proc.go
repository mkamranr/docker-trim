package tracer

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// procTracer samples /proc from inside the container.
type procTracer struct{}

func (procTracer) Backend() Backend { return BackendProc }

// Trace builds a copy of the image with the sensor wrapping its entrypoint,
// runs it, and reads the manifest back out of the container's logs.
//
// The manifest travels through stderr behind a marker rather than through a
// file or a bind mount, because the image may run as a user who cannot write
// anywhere and a mount would need a writable host path. A marker costs nothing
// and works the same everywhere.
func (t procTracer) Trace(ctx context.Context, opts Options) (*Result, error) {
	if err := Available(ctx); err != nil {
		return nil, fmt.Errorf("tracing needs a working Docker engine: %w", err)
	}
	if opts.Image == "" {
		return nil, fmt.Errorf("no image to trace")
	}
	if opts.Interval <= 0 {
		opts.Interval = 50 * time.Millisecond
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
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
	tag, err := buildInstrumented(ctx, opts.Image, opts, BackendProc)
	if err != nil {
		return nil, err
	}
	defer Remove(context.WithoutCancel(ctx), tag)

	progress(fmt.Sprintf("running %s under the sampler for up to %s",
		strings.Join(command, " "), opts.Timeout))
	// No extra privileges: reading your own /proc needs none, which is what
	// makes this backend work on Docker Desktop and on hardened runners.
	return runTraced(ctx, tag, opts, BackendProc, nil)
}

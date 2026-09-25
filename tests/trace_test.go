//go:build integration

// Tracing against a real container. Run with: make integration
package tests

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mkamranr/dtrim/pkg/analyzer"
	"github.com/mkamranr/dtrim/pkg/tracer"
)

func requireDocker(t *testing.T) context.Context {
	t.Helper()
	if os.Getenv("DTRIM_INTEGRATION") == "" {
		t.Skip("set DTRIM_INTEGRATION=1 to run tests that build real images")
	}
	ctx := context.Background()
	if err := tracer.Available(ctx); err != nil {
		t.Skipf("no usable Docker engine: %v", err)
	}
	return ctx
}

func buildImage(t *testing.T, tag, dockerfile string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/Dockerfile", []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("docker", "build", "-q", "-t", tag, dir).CombinedOutput()
	if err != nil {
		t.Fatalf("building %s: %v\n%s", tag, err, out)
	}
	t.Cleanup(func() { tracer.Remove(context.Background(), tag) })
}

// The sampler has to see the interpreter, the libraries it loads, and the
// modules it opens on demand. The dynamically loaded ones are the hard part:
// nothing in the Dockerfile mentions them.
func TestProcTracer_sees_binaries_and_dynamically_loaded_libraries(t *testing.T) {
	ctx := requireDocker(t)
	const tag = "dtrim-trace-it:python"
	// The import has to stay resident long enough to be sampled. A command that
	// imports and exits immediately is a coin flip: on a fast runner the whole
	// dlopen phase can fall between two samples, which is the limitation
	// docs/tracing.md documents rather than a bug to assert away. Holding the
	// modules open tests the capability without racing, and is what a real
	// workload looks like anyway.
	buildImage(t, tag, "FROM python:3.12-slim\n"+
		"CMD [\"python\",\"-c\",\"import json,ssl,sqlite3,time;print('ok');time.sleep(2)\"]\n")

	tr, err := tracer.New(tracer.BackendProc)
	if err != nil {
		t.Fatal(err)
	}
	opts := tracer.DefaultOptions()
	opts.Image = tag
	opts.Timeout = 60 * time.Second

	res, err := tr.Trace(ctx, opts)
	if err != nil {
		t.Fatalf("tracing failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("the traced command exited %d", res.ExitCode)
	}
	if res.Samples < 1 {
		t.Error("the sampler never ran")
	}
	joined := strings.Join(res.Manifest.AccessedFiles, "\n")
	// The interpreter and the libraries it links against are mapped for the
	// whole life of the process, so every sample sees them.
	for _, want := range []string{"python3.12", "libc.so"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the trace missed %q; it saw:\n%s", want, joined)
		}
	}
	// Modules loaded on demand are the interesting case: nothing in the
	// Dockerfile mentions them, so only running the container reveals them.
	// They stay mapped for the two seconds this command sleeps, so every sample
	// sees them.
	for _, want := range []string{"_ssl", "_sqlite3"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the trace missed the dynamically loaded %q; it saw:\n%s", want, joined)
		}
	}
	if len(res.Manifest.UsedBinaries) == 0 {
		t.Error("no binary was recorded")
	}
	if len(res.Manifest.SharedLibs) == 0 {
		t.Error("no shared library was recorded")
	}
}

// Sampling races with a short-lived process, so dtrim has to report how long
// the command ran: without it, a user cannot tell a thorough trace from one
// that saw two frames of a forty-millisecond process.
func TestProcTracer_reports_how_long_the_command_ran(t *testing.T) {
	ctx := requireDocker(t)
	const tag = "dtrim-trace-it:duration"
	buildImage(t, tag, "FROM busybox:1.37\nCMD [\"sleep\",\"2\"]\n")

	tr, _ := tracer.New(tracer.BackendProc)
	opts := tracer.DefaultOptions()
	opts.Image = tag
	opts.Timeout = 60 * time.Second

	res, err := tr.Trace(ctx, opts)
	if err != nil {
		t.Fatalf("tracing failed: %v", err)
	}
	if res.Duration < 1500*time.Millisecond {
		t.Errorf("duration = %s, want roughly the two seconds the command slept", res.Duration)
	}
	// A two-second command at the default interval should yield plenty of
	// samples; if it does not, the sampler is not running as often as claimed.
	if res.Samples < 10 {
		t.Errorf("samples = %d over %s, want many more", res.Samples, res.Duration)
	}
}

// The wrapper must not change what the container does: same exit code, same
// output. A sensor that alters behaviour is worse than no sensor.
func TestProcTracer_is_transparent_to_the_container(t *testing.T) {
	ctx := requireDocker(t)
	const tag = "dtrim-trace-it:exit"
	buildImage(t, tag, "FROM busybox:1.37\nCMD [\"sh\",\"-c\",\"echo hello from the app; exit 7\"]\n")

	tr, _ := tracer.New(tracer.BackendProc)
	opts := tracer.DefaultOptions()
	opts.Image = tag
	opts.Timeout = 60 * time.Second

	res, err := tr.Trace(ctx, opts)
	if err != nil {
		t.Fatalf("tracing failed: %v", err)
	}
	if res.ExitCode != 7 {
		t.Errorf("exit code = %d, want the container's own 7", res.ExitCode)
	}
}

// A server never exits, so tracing one always ends at the timeout. That is the
// normal path, not an error.
func TestProcTracer_stops_a_long_running_container_and_still_reports(t *testing.T) {
	ctx := requireDocker(t)
	const tag = "dtrim-trace-it:server"
	buildImage(t, tag, "FROM busybox:1.37\nCMD [\"sh\",\"-c\",\"while true; do sleep 1; done\"]\n")

	tr, _ := tracer.New(tracer.BackendProc)
	opts := tracer.DefaultOptions()
	opts.Image = tag
	opts.Timeout = 3 * time.Second

	start := time.Now()
	res, err := tr.Trace(ctx, opts)
	if err != nil {
		t.Fatalf("tracing failed: %v", err)
	}
	if !res.TimedOut {
		t.Error("a container that never exits should be reported as timed out")
	}
	if elapsed := time.Since(start); elapsed > 90*time.Second {
		t.Errorf("the timeout was not respected: took %s", elapsed)
	}
	if len(res.Manifest.UsedBinaries) == 0 {
		t.Error("a stopped container still has to yield a manifest")
	}
}

// The whole point: a trace plus a package inventory says what is not being used.
func TestTrace_attributes_unused_packages(t *testing.T) {
	ctx := requireDocker(t)
	const tag = "dtrim-trace-it:toolchain"
	buildImage(t, tag, "FROM debian:bookworm-slim\n"+
		"RUN apt-get update && apt-get install -y --no-install-recommends vim-tiny curl "+
		"&& rm -rf /var/lib/apt/lists/*\n"+
		"CMD [\"/bin/echo\",\"hello\"]\n")

	rep, err := analyzer.InspectImageWithOwnership(ctx, tag)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Packages) == 0 {
		t.Fatal("no package inventory")
	}

	tr, _ := tracer.New(tracer.BackendProc)
	opts := tracer.DefaultOptions()
	opts.Image = tag
	opts.Timeout = 60 * time.Second
	res, err := tr.Trace(ctx, opts)
	if err != nil {
		t.Fatalf("tracing failed: %v", err)
	}

	u := analyzer.AttributeUsage(rep, res.Manifest)
	unused := map[string]bool{}
	for _, p := range u.Unused {
		unused[p.Name] = true
	}
	// echo touches neither, so both should be reported as never touched.
	for _, want := range []string{"vim-tiny", "curl"} {
		if !unused[want] {
			t.Errorf("%q was installed and never used, but was not reported as unused", want)
		}
	}
	// And the things that boot the image must never be on that list.
	for _, never := range []string{"libc6", "base-files", "ca-certificates", "tzdata"} {
		if unused[never] {
			t.Errorf("%q was reported as removable; removing it breaks the image", never)
		}
	}
	if u.RemovableBytes <= 0 {
		t.Error("no removable bytes reported despite unused packages")
	}
}

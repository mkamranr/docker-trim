//go:build integration

// Tracing against a real container. Run with: make integration
package tests

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkamranr/dtrim/pkg/analyzer"
	"github.com/mkamranr/dtrim/pkg/synthesizer"
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

// The reason ptrace exists: it stops at every syscall, so the same command
// traced twice produces the same answer. The sampler does not, and cannot.
func TestPtraceTracer_is_deterministic_where_sampling_is_not(t *testing.T) {
	ctx := requireDocker(t)
	const tag = "dtrim-trace-it:determinism"
	// Short enough that the sampler races with it, which is the point.
	buildImage(t, tag, "FROM python:3.12-slim\nCMD [\"python\",\"-c\",\"import json,ssl,sqlite3;print('ok')\"]\n")

	tr, err := tracer.New(tracer.BackendPtrace)
	if err != nil {
		t.Fatal(err)
	}
	opts := tracer.DefaultOptions()
	opts.Image = tag
	opts.Timeout = 60 * time.Second

	const runs = 3
	var counts []int
	for i := 0; i < runs; i++ {
		res, err := tr.Trace(ctx, opts)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("run %d: the traced command exited %d", i, res.ExitCode)
		}
		counts = append(counts, len(res.Manifest.AccessedFiles))

		// Every module is opened, whether or not it stays resident, so all of
		// them are observed every time. The sampler catches these only when the
		// timing happens to work out.
		joined := strings.Join(res.Manifest.AccessedFiles, "\n")
		for _, want := range []string{"_ssl", "_sqlite3", "python3.12"} {
			if !strings.Contains(joined, want) {
				t.Errorf("run %d missed %q, which ptrace cannot legitimately miss", i, want)
			}
		}
	}
	for i := 1; i < runs; i++ {
		if counts[i] != counts[0] {
			t.Errorf("file counts differ across runs: %v. ptrace observes every syscall, "+
				"so the same command has to produce the same answer", counts)
			break
		}
	}
}

// ptrace records a path only once the syscall has returned successfully, so a
// file the program looked for and did not find is never counted as used.
func TestPtraceTracer_ignores_files_that_were_not_there(t *testing.T) {
	ctx := requireDocker(t)
	const tag = "dtrim-trace-it:missing"
	buildImage(t, tag, "FROM busybox:1.37\n"+
		"CMD [\"sh\",\"-c\",\"cat /definitely/not/here 2>/dev/null; cat /etc/hostname >/dev/null\"]\n")

	tr, _ := tracer.New(tracer.BackendPtrace)
	opts := tracer.DefaultOptions()
	opts.Image = tag
	opts.Timeout = 60 * time.Second

	res, err := tr.Trace(ctx, opts)
	if err != nil {
		t.Fatalf("tracing failed: %v", err)
	}
	joined := strings.Join(res.Manifest.AccessedFiles, "\n")
	if strings.Contains(joined, "/definitely/not/here") {
		t.Error("a failed open was recorded as a used file")
	}
	if !strings.Contains(joined, "/etc/hostname") {
		t.Errorf("the successful open was not recorded:\n%s", joined)
	}
}

// A shell that forks is the normal shape of a --trace workload, and getting the
// syscall entry and exit pairing wrong silently drops the child's file access.
func TestPtraceTracer_follows_forked_children(t *testing.T) {
	ctx := requireDocker(t)
	const tag = "dtrim-trace-it:fork"
	buildImage(t, tag, "FROM python:3.12-slim\n"+
		"CMD [\"/bin/sh\",\"-c\",\"python -c 'import sqlite3'\"]\n")

	tr, _ := tracer.New(tracer.BackendPtrace)
	opts := tracer.DefaultOptions()
	opts.Image = tag
	opts.Timeout = 60 * time.Second

	res, err := tr.Trace(ctx, opts)
	if err != nil {
		t.Fatalf("tracing failed: %v", err)
	}
	if res.Processes < 2 {
		t.Errorf("processes = %d, want the shell and the python it spawned", res.Processes)
	}
	joined := strings.Join(res.Manifest.AccessedFiles, "\n")
	// These belong to the child. Seeing the shell but not its child is the
	// signature of broken entry/exit pairing after a fork.
	for _, want := range []string{"_sqlite3", "libsqlite3"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the forked child's use of %q was not observed:\n%s", want, joined)
		}
	}
}

// Whatever the backend, the wrapper must not change what the container does.
func TestPtraceTracer_is_transparent_to_the_container(t *testing.T) {
	ctx := requireDocker(t)
	const tag = "dtrim-trace-it:ptexit"
	buildImage(t, tag, "FROM busybox:1.37\nCMD [\"sh\",\"-c\",\"echo hello; exit 9\"]\n")

	tr, _ := tracer.New(tracer.BackendPtrace)
	opts := tracer.DefaultOptions()
	opts.Image = tag
	opts.Timeout = 60 * time.Second

	res, err := tr.Trace(ctx, opts)
	if err != nil {
		t.Fatalf("tracing failed: %v", err)
	}
	if res.ExitCode != 9 {
		t.Errorf("exit code = %d, want the container's own 9", res.ExitCode)
	}
}

// The failure dtrim is most capable of causing, and the reason the tracer feeds
// the synthesizer: an image that is dramatically smaller, builds cleanly, and
// dies the first time the program shells out. Static analysis cannot see it.
//
// This builds the broken image on purpose and confirms both that it is broken
// and that dtrim said so in advance.
func TestTrace_warns_before_a_rewrite_breaks_the_program(t *testing.T) {
	ctx := requireDocker(t)
	dir := t.TempDir()

	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/shellout\n\ngo 1.24\n")
	write("main.go", "package main\n\nimport (\n\t\"fmt\"\n\t\"os/exec\"\n)\n\n"+
		"func main() {\n\tout, err := exec.Command(\"/bin/sh\", \"-c\", \"echo ok\").Output()\n"+
		"\tfmt.Println(string(out), err)\n}\n")
	write("Dockerfile", "FROM golang:1.25-alpine\nWORKDIR /src\nCOPY . .\n"+
		"RUN go build -o /src/bin/app .\nCMD [\"/src/bin/app\"]\n")

	const tag = "dtrim-trace-it:shellout"
	out, err := exec.Command("docker", "build", "-q", "-t", tag, dir).CombinedOutput()
	if err != nil {
		t.Fatalf("building the fixture: %v\n%s", err, out)
	}
	t.Cleanup(func() { tracer.Remove(context.Background(), tag) })

	// Trace it, then plan the rewrite with what the trace found.
	tr, _ := tracer.New(tracer.BackendPtrace)
	topts := tracer.DefaultOptions()
	topts.Image = tag
	topts.Timeout = 60 * time.Second
	res, err := tr.Trace(ctx, topts)
	if err != nil {
		t.Fatalf("tracing: %v", err)
	}

	a, err := analyzer.ParseFile(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	plan := synthesizer.Optimize(a, synthesizer.Options{
		Base:           synthesizer.BaseDistroless,
		Aggressiveness: analyzer.ConfidenceLikely,
		Trace:          &res.Manifest,
	})

	if !plan.Restructured {
		t.Fatalf("declined to restructure: %s", plan.Plan.Reason)
	}
	if len(plan.RuntimeGaps) == 0 {
		t.Fatal("the program shells out and the runtime has no shell, but dtrim did not say so")
	}
	var named bool
	for _, g := range plan.RuntimeGaps {
		if strings.Contains(g.Binary, "sh") {
			named = true
		}
	}
	if !named {
		t.Errorf("the gaps do not name a shell: %+v", plan.RuntimeGaps)
	}

	// Now prove the warning was right, rather than taking dtrim's word for it.
	trimmedPath := filepath.Join(dir, "Dockerfile.trimmed")
	if err := os.WriteFile(trimmedPath, []byte(synthesizer.Render(a)), 0o644); err != nil {
		t.Fatal(err)
	}
	const trimTag = "dtrim-trace-it:shellout-trimmed"
	t.Cleanup(func() { tracer.Remove(context.Background(), trimTag) })
	if _, err := tracer.Build(ctx, tracer.BuildRequest{
		Dockerfile: trimmedPath, Context: dir, Tag: trimTag}); err != nil {
		t.Fatalf("the trimmed Dockerfile does not build: %v", err)
	}

	logs, _ := exec.Command("docker", "run", "--rm", trimTag).CombinedOutput()
	if !strings.Contains(string(logs), "no such file") {
		t.Errorf("the trimmed image ran fine, so the warning was a false positive:\n%s", logs)
	}
}

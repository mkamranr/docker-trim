// Package tracer runs containers on behalf of dtrim: building images to
// measure them today, and observing a running container to learn which files
// it actually touches in a later release.
//
// The PRD calls this file the "Docker API runner". It drives the `docker` CLI
// rather than the engine API for builds, deliberately: Docker Desktop and
// every modern Linux install route `docker build` through BuildKit, while the
// engine API's build endpoint needs a session to do the same. Shelling out
// gets the same builder the user gets, with the same cache and the same
// output, and `docker` is by definition present when someone is verifying a
// Docker build. Image inspection stays pure Go; see analyzer.InspectImage.
package tracer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// BuildRequest describes one image to build.
type BuildRequest struct {
	// Dockerfile is the path to the file to build.
	Dockerfile string
	// Context is the build context directory.
	Context string
	// Tag is the name to give the built image.
	Tag string
	// Progress receives build output lines when non-nil.
	Progress io.Writer
}

// ErrDockerMissing is returned when the docker CLI is not on PATH.
var ErrDockerMissing = errors.New("docker command not found on PATH")

// Available reports whether a usable Docker engine is reachable.
func Available(ctx context.Context) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return ErrDockerMissing
	}
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker is installed but the engine is not reachable: %s",
			strings.TrimSpace(string(out)))
	}
	return nil
}

// Build builds an image and returns its size in bytes as the engine reports it.
func Build(ctx context.Context, req BuildRequest) (int64, error) {
	if err := Available(ctx); err != nil {
		return 0, err
	}
	args := []string{"build", "-f", req.Dockerfile, "-t", req.Tag, req.Context}

	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr bytes.Buffer
	if req.Progress != nil {
		cmd.Stdout = req.Progress
		cmd.Stderr = io.MultiWriter(req.Progress, &stderr)
	} else {
		cmd.Stderr = &stderr
	}
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("building %s failed: %w\n%s", req.Dockerfile, err, tail(stderr.String(), 25))
	}
	return ImageSize(ctx, req.Tag)
}

// ImageSize asks the engine how large a built image is.
func ImageSize(ctx context.Context, tag string) (int64, error) {
	out, err := exec.CommandContext(ctx, "docker", "image", "inspect", tag, "--format", "{{.Size}}").Output()
	if err != nil {
		return 0, fmt.Errorf("cannot inspect %s: %w", tag, err)
	}
	var size int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &size); err != nil {
		return 0, fmt.Errorf("cannot read the size of %s: %w", tag, err)
	}
	return size, nil
}

// SmokeResult is what happened when the trimmed image was actually started.
type SmokeResult struct {
	Started  bool   `json:"started"`
	ExitCode int    `json:"exitCode"`
	Output   string `json:"output,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Smoke starts the image with its own entrypoint and watches it for the given
// window.
//
// A trimmed image that is smaller but does not run is a failure, and the only
// way to know is to start it. A process still running when the window closes
// counts as success: a server that stays up is exactly what is wanted. One
// that exits non-zero, or dies immediately with a loader error, is a failure
// worth reporting loudly.
func Smoke(ctx context.Context, tag string, window time.Duration) SmokeResult {
	runCtx, cancel := context.WithTimeout(ctx, window+30*time.Second)
	defer cancel()

	name := "dtrim-smoke-" + sanitize(tag)
	_ = exec.CommandContext(runCtx, "docker", "rm", "-f", name).Run()

	// Deliberately not --rm: an exited container has to stay inspectable, or
	// its exit code and logs vanish exactly when they are needed. It is
	// removed explicitly below instead.
	start := exec.CommandContext(runCtx, "docker", "run", "-d", "--name", name, tag)
	if out, err := start.CombinedOutput(); err != nil {
		return SmokeResult{Reason: "the container could not be started",
			Output: tail(string(out), 15)}
	}
	defer func() {
		_ = exec.CommandContext(context.WithoutCancel(runCtx), "docker", "rm", "-f", name).Run()
	}()

	logsOf := func() string {
		out, _ := exec.CommandContext(runCtx, "docker", "logs", name).CombinedOutput()
		return tail(string(out), 15)
	}

	deadline := time.Now().Add(window)
	for {
		state, err := inspectState(runCtx, name)
		if err != nil {
			// The container should exist until it is removed above, so
			// failing to inspect it means something is wrong. Never read that
			// as success: reporting a broken image as working is the worst
			// thing this tool could do.
			return SmokeResult{Reason: "the container could not be inspected: " + err.Error(),
				Output: logsOf()}
		}
		if !state.Running {
			return SmokeResult{
				Started:  state.ExitCode == 0,
				ExitCode: state.ExitCode,
				Output:   logsOf(),
				Reason:   fmt.Sprintf("the container exited with code %d", state.ExitCode),
			}
		}
		if !time.Now().Before(deadline) {
			// Still up when the window closed, which for a server is success.
			return SmokeResult{Started: true, Output: logsOf(),
				Reason: "still running after " + window.String()}
		}
		select {
		case <-runCtx.Done():
			return SmokeResult{Reason: "interrupted", Output: logsOf()}
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// Remove deletes an image, ignoring the case where it was never created.
func Remove(ctx context.Context, tags ...string) {
	for _, t := range tags {
		_ = exec.CommandContext(ctx, "docker", "image", "rm", "-f", t).Run()
	}
}

type containerState struct {
	Running  bool `json:"Running"`
	ExitCode int  `json:"ExitCode"`
}

func inspectState(ctx context.Context, name string) (containerState, error) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", name, "--format", "{{json .State}}").Output()
	if err != nil {
		return containerState{}, err
	}
	var s containerState
	if err := json.Unmarshal(bytes.TrimSpace(out), &s); err != nil {
		return containerState{}, err
	}
	return s, nil
}

// sanitize turns an image tag into something usable as a container name.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// tail keeps the last n lines, which is where a build or a crash says why.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

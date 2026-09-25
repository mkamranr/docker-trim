package tracer

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mkamranr/dtrim/pkg/analyzer"
)

// sensorSource is compiled inside the ephemeral image rather than shipped as a
// binary. Building it there means it is always the right architecture, needs no
// cross-compilation matrix, and no executable has to live in the repository.
//
//go:embed sensor/main.go
var sensorSource string

// sensorBuilderImage compiles the sensor. Pinned, because dtrim tells everyone
// else not to float their base image tags.
const sensorBuilderImage = "golang:1.25-alpine"

const (
	beginMarker = "<<<DTRIM-TRACE-BEGIN>>>"
	endMarker   = "<<<DTRIM-TRACE-END>>>"
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

	progress("building an instrumented copy of " + opts.Image)
	tag, err := buildInstrumented(ctx, opts.Image, command)
	if err != nil {
		return nil, err
	}
	defer Remove(context.WithoutCancel(ctx), tag)

	progress(fmt.Sprintf("running %s under the sampler for up to %s",
		strings.Join(command, " "), opts.Timeout))
	return runTraced(ctx, tag, opts)
}

// buildInstrumented produces an ephemeral image: the target, plus the sensor,
// with the original command moved behind it.
func buildInstrumented(ctx context.Context, image string, command []string) (string, error) {
	dir, err := os.MkdirTemp("", "dtrim-trace")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if err := os.WriteFile(filepath.Join(dir, "sensor.go"), []byte(sensorSource), 0o644); err != nil {
		return "", err
	}

	encoded, err := json.Marshal(command)
	if err != nil {
		return "", err
	}
	dockerfile := fmt.Sprintf(`FROM %s AS dtrim-sensor
WORKDIR /s
COPY sensor.go .
RUN go mod init dtrimsensor >/dev/null && CGO_ENABLED=0 go build -ldflags="-s -w" -o /dtrim-sensor .

FROM %s
COPY --from=dtrim-sensor /dtrim-sensor /.dtrim/sensor
ENTRYPOINT ["/.dtrim/sensor","--"]
CMD %s
`, sensorBuilderImage, image, encoded)

	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		return "", err
	}

	tag := "dtrim-trace:" + ShortHash(image+string(encoded))
	cmd := exec.CommandContext(ctx, "docker", "build", "-t", tag, dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cannot build an instrumented copy of %s: %w\n%s",
			image, err, tail(stderr.String(), 20))
	}
	return tag, nil
}

// runTraced starts the instrumented image and collects the manifest.
func runTraced(ctx context.Context, tag string, opts Options) (*Result, error) {
	name := "dtrim-trace-" + ShortHash(tag)
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run()
	defer func() {
		_ = exec.CommandContext(context.WithoutCancel(ctx), "docker", "rm", "-f", name).Run()
	}()

	// Deliberately not --rm: an exited container has to stay readable, or its
	// logs, and with them the manifest, vanish exactly when they are needed.
	if out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name, tag).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cannot start the instrumented container: %w\n%s", err, tail(string(out), 15))
	}

	result := &Result{Backend: BackendProc}
	deadline := time.Now().Add(opts.Timeout)
	for {
		state, err := inspectState(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect the traced container: %w", err)
		}
		if !state.Running {
			result.ExitCode = state.ExitCode
			break
		}
		if !time.Now().Before(deadline) {
			// A server does not exit on its own, so this is the normal path.
			// Stopping politely gives the sensor its SIGTERM and a chance to
			// print the manifest.
			result.TimedOut = true
			_ = exec.CommandContext(ctx, "docker", "stop", "-t", "5", name).Run()
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}

	logs, err := exec.CommandContext(context.WithoutCancel(ctx), "docker", "logs", name).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("cannot read the traced container's output: %w", err)
	}

	manifest, err := extractManifest(string(logs))
	if err != nil {
		return nil, fmt.Errorf("%w\nLast output from the container:\n%s", err, tail(string(logs), 20))
	}

	result.Manifest = analyzer.TraceManifest{
		AccessedFiles: manifest.AccessedFiles,
		UsedBinaries:  manifest.UsedBinaries,
		SharedLibs:    manifest.SharedLibs,
		ReadBytes:     manifest.ReadBytes,
	}
	result.Samples = manifest.Samples
	result.Processes = manifest.Processes
	result.Duration = time.Duration(manifest.DurationMS) * time.Millisecond
	return result, nil
}

// sensorManifest is what the sensor prints.
type sensorManifest struct {
	AccessedFiles []string `json:"accessedFiles"`
	UsedBinaries  []string `json:"usedBinaries"`
	SharedLibs    []string `json:"sharedLibs"`
	ReadBytes     int64    `json:"readBytes"`
	Samples       int      `json:"samples"`
	Processes     int      `json:"processes"`
	DurationMS    int64    `json:"durationMs"`
}

// extractManifest pulls the JSON out from between the markers. The container's
// own output is interleaved with it, which is why the markers exist.
func extractManifest(logs string) (*sensorManifest, error) {
	start := strings.LastIndex(logs, beginMarker)
	if start < 0 {
		return nil, fmt.Errorf("the sensor produced no manifest: the container may have been " +
			"killed before it could finish, or its entrypoint may not have run the sensor")
	}
	rest := logs[start+len(beginMarker):]
	end := strings.Index(rest, endMarker)
	if end < 0 {
		return nil, fmt.Errorf("the sensor's manifest was cut short")
	}

	var m sensorManifest
	if err := json.Unmarshal([]byte(strings.TrimSpace(rest[:end])), &m); err != nil {
		return nil, fmt.Errorf("cannot read the sensor's manifest: %w", err)
	}
	return &m, nil
}

// imageCommand reads an image's entrypoint and command.
//
// This asks the daemon directly rather than going through the registry client,
// because that would export every layer to read one small JSON blob.
func imageCommand(ctx context.Context, image string) ([]string, error) {
	out, err := exec.CommandContext(ctx, "docker", "image", "inspect", image,
		"--format", "{{json .Config}}").Output()
	if err != nil {
		return nil, fmt.Errorf("cannot inspect %s: is it built locally? %w", image, err)
	}
	var cfg struct {
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &cfg); err != nil {
		return nil, fmt.Errorf("cannot read the configuration of %s: %w", image, err)
	}
	return append(append([]string{}, cfg.Entrypoint...), cfg.Cmd...), nil
}

package tracer

import (
	"strings"
	"testing"
)

func TestExtractManifest_finds_the_json_among_the_container_output(t *testing.T) {
	logs := "starting up\nlistening on :8080\n" +
		"\n" + beginMarker + "\n" +
		`{"accessedFiles":["/a"],"usedBinaries":["/b"],"sharedLibs":["/c.so"],"readBytes":42,"samples":7,"processes":2}` +
		"\n" + endMarker + "\n"

	m, err := extractManifest(logs)
	if err != nil {
		t.Fatal(err)
	}
	if m.ReadBytes != 42 || m.Samples != 7 || m.Processes != 2 {
		t.Errorf("manifest = %+v", m)
	}
	if len(m.AccessedFiles) != 1 || len(m.SharedLibs) != 1 {
		t.Errorf("manifest lost entries: %+v", m)
	}
}

// The application's own output is interleaved with the manifest, which is the
// whole reason for the markers.
func TestExtractManifest_survives_output_that_looks_like_json(t *testing.T) {
	logs := `{"level":"info","msg":"this is the app logging in json"}` + "\n" +
		beginMarker + "\n" + `{"samples":3}` + "\n" + endMarker + "\n" +
		`{"level":"info","msg":"and more after"}` + "\n"

	m, err := extractManifest(logs)
	if err != nil {
		t.Fatal(err)
	}
	if m.Samples != 3 {
		t.Errorf("samples = %d, want 3", m.Samples)
	}
}

// A container that prints the marker itself must not be able to shadow the real
// manifest, which is always the last one written.
func TestExtractManifest_takes_the_last_manifest(t *testing.T) {
	logs := beginMarker + "\n" + `{"samples":1}` + "\n" + endMarker + "\n" +
		beginMarker + "\n" + `{"samples":99}` + "\n" + endMarker + "\n"

	m, err := extractManifest(logs)
	if err != nil {
		t.Fatal(err)
	}
	if m.Samples != 99 {
		t.Errorf("samples = %d, want the last manifest's 99", m.Samples)
	}
}

func TestExtractManifest_explains_a_missing_manifest(t *testing.T) {
	_, err := extractManifest("the container crashed immediately\n")
	if err == nil {
		t.Fatal("want an error when the sensor produced nothing")
	}
	if !strings.Contains(err.Error(), "no manifest") {
		t.Errorf("error = %q", err)
	}

	if _, err := extractManifest(beginMarker + "\n{\"samples\""); err == nil {
		t.Error("want an error for a truncated manifest")
	}
}

func TestParseBackend(t *testing.T) {
	for _, ok := range []string{"none", "proc", "ptrace", "ebpf"} {
		if _, err := ParseBackend(ok); err != nil {
			t.Errorf("ParseBackend(%q) = %v", ok, err)
		}
	}
	if _, err := ParseBackend("strace"); err == nil {
		t.Error("ParseBackend accepted a backend that does not exist")
	}
}

// An unimplemented backend has to name the one that works, or the error leaves
// the user with nowhere to go.
func TestNew_points_at_the_backend_that_works(t *testing.T) {
	if _, err := New(BackendProc); err != nil {
		t.Errorf("the proc backend should be available: %v", err)
	}
	for _, b := range []Backend{BackendPtrace, BackendEBPF} {
		_, err := New(b)
		if err == nil {
			t.Errorf("%s reported as available but is not implemented", b)
			continue
		}
		if !strings.Contains(err.Error(), "proc") {
			t.Errorf("%s error does not name the working backend: %v", b, err)
		}
	}
}

// The sensor is compiled inside the ephemeral image, so its source has to be
// embedded and has to be the real thing.
func TestSensorSource_is_embedded(t *testing.T) {
	if len(sensorSource) == 0 {
		t.Fatal("the sensor source was not embedded")
	}
	for _, want := range []string{"package main", beginMarker, "/proc", "func main("} {
		if !strings.Contains(sensorSource, want) {
			t.Errorf("the embedded sensor source is missing %q", want)
		}
	}
}

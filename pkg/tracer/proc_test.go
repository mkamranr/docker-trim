package tracer

import (
	"sort"
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

func TestNew_returns_the_implemented_backends(t *testing.T) {
	for _, b := range []Backend{BackendProc, BackendPtrace} {
		tr, err := New(b)
		if err != nil {
			t.Errorf("%s should be available: %v", b, err)
			continue
		}
		if tr.Backend() != b {
			t.Errorf("New(%s) returned a tracer reporting %s", b, tr.Backend())
		}
	}
}

// An unimplemented backend has to name one that works, or the error leaves the
// user with nowhere to go.
func TestNew_points_at_a_backend_that_works(t *testing.T) {
	_, err := New(BackendEBPF)
	if err == nil {
		t.Fatal("ebpf reported as available but is not implemented")
	}
	if !strings.Contains(err.Error(), "proc") {
		t.Errorf("the error does not name a working backend: %v", err)
	}
}

// The sensor is compiled inside the ephemeral image, so every file it needs has
// to be embedded. Missing one would only surface as a build failure inside a
// container, which is a slow and confusing place to find out.
func TestSensorSource_embeds_every_file_the_sensor_needs(t *testing.T) {
	entries, err := sensorFiles.ReadDir("sensor")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range entries {
		body, err := sensorFiles.ReadFile("sensor/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		got[e.Name()] = string(body)
	}

	// Both collectors, and the per-architecture syscall numbers. The arch files
	// are the ones easiest to forget, and a missing one turns into
	// "undefined: sysOpen" inside a docker build, which is a slow place to
	// find out.
	for _, want := range []string{
		"main.go", "collect_proc.go", "collect_ptrace.go", "collect_ptrace_stub.go",
		"syscalls_linux.go", "syscalls_amd64.go", "syscalls_arm64.go",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("the sensor source is missing %s; embedded: %v", want, keys(got))
		}
	}
	if !strings.Contains(got["main.go"], beginMarker) {
		t.Error("main.go does not carry the manifest marker the driver parses")
	}
	if !strings.Contains(got["collect_proc.go"], "/proc") {
		t.Error("the proc collector does not read /proc")
	}
	if !strings.Contains(got["collect_ptrace.go"], "PTRACE_O_TRACESYSGOOD") {
		t.Error("the ptrace collector does not set the syscall-stop option")
	}
	// 0x4206 is PTRACE_SEIZE, which fails with EIO on an already-traced process
	// and is indistinguishable from an unsupported kernel. Getting this wrong
	// cost an afternoon.
	if !strings.Contains(got["collect_ptrace.go"], "0x420e") {
		t.Error("PTRACE_GET_SYSCALL_INFO is not 0x420e in the embedded sensor")
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Only ptrace asks for privileges, and it has to ask for both: the default
// seccomp profile blocks ptrace even when the capability is granted.
func TestPtrace_requests_the_privileges_the_kernel_needs(t *testing.T) {
	flags := strings.Join(ptraceDockerFlags, " ")
	for _, want := range []string{"--cap-add=SYS_PTRACE", "seccomp=unconfined"} {
		if !strings.Contains(flags, want) {
			t.Errorf("the ptrace backend does not request %s: %v", want, ptraceDockerFlags)
		}
	}
}

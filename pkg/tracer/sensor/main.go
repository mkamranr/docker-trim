// Command docker-trim-sensor watches what a container actually uses.
//
// It is injected into a copy of the target image as an entrypoint wrapper,
// starts the real command as its child, and samples /proc while that command
// runs. On exit it prints a manifest and forwards the child's exit code, so
// wrapping a container changes what it reports and not what it does.
//
// Sampling /proc needs no capabilities, no seccomp changes and no kernel
// features, which is why it is the default backend: it works on Docker Desktop,
// on a hardened CI runner and on a locked-down node. It sees every binary that
// executed and every library that loaded, and can miss a file opened and closed
// between two samples. docs/tracing.md explains the trade against ptrace.
//
// This file is compiled inside an ephemeral image build rather than shipped as
// a binary, so it is always built for the right architecture and no executable
// ever has to live in the repository. Keep it dependency-free: it is built with
// nothing but the standard library available.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The manifest is delimited on stderr rather than written to a file: the image
// under trace may run as a user who cannot create one, and a marker costs
// nothing. docker-trim reads the container's logs and takes what is between these.
const (
	beginMarker = "<<<DOCKER-TRIM-TRACE-BEGIN>>>"
	endMarker   = "<<<DOCKER-TRIM-TRACE-END>>>"
)

// manifest mirrors the PRD's TraceManifest.
type manifest struct {
	AccessedFiles []string `json:"accessedFiles"`
	UsedBinaries  []string `json:"usedBinaries"`
	SharedLibs    []string `json:"sharedLibs"`
	ReadBytes     int64    `json:"readBytes"`
	// Samples is how many times /proc was walked, and Processes how many
	// distinct pids were seen. A trace with one sample saw almost nothing and
	// the report should say so rather than implying thorough coverage.
	Samples   int `json:"samples"`
	Processes int `json:"processes"`
	// DurationMS is how long the traced command ran. Sampling races with a
	// short-lived process: a library loaded late in a command that lives forty
	// milliseconds may never appear in any sample. The reader needs this to
	// judge how much the manifest is worth.
	DurationMS int64 `json:"durationMs"`
}

func main() {
	mode := flag.String("mode", "proc", "how to observe: proc or ptrace")
	interval := flag.Duration("interval", 50*time.Millisecond, "how often to sample /proc")
	settle := flag.Duration("settle", 0, "keep tracing this long after the command exits")
	flag.Parse()

	argv := flag.Args()
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "docker-trim-sensor: no command to run")
		os.Exit(2)
	}

	c := newCollector()
	started := time.Now()

	var (
		code int
		err  error
	)
	switch *mode {
	case "proc":
		code, err = runProc(argv, c, *interval, *settle)
	case "ptrace":
		code, err = runPtrace(argv, c)
	default:
		fmt.Fprintf(os.Stderr, "docker-trim-sensor: unknown mode %q\n", *mode)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "docker-trim-sensor: %v\n", err)
	}

	// The manifest is emitted even when the run failed: a partial trace of a
	// command that died still says which libraries loaded before it did.
	c.emit(time.Since(started))
	os.Exit(code)
}

// forwardSignals relays termination to the child, so a `docker stop` reaches
// the real process rather than only the sensor. A container is normally stopped
// rather than allowed to finish, so the manifest has to survive SIGTERM.
func forwardSignals(proc *os.Process) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for s := range signals {
			if proc != nil {
				_ = proc.Signal(s)
			}
		}
	}()
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 1
}

// collector accumulates what the sample loop sees.
type collector struct {
	mu        sync.Mutex
	files     map[string]bool
	binaries  map[string]bool
	libs      map[string]bool
	pids      map[int]bool
	readBytes map[int]int64
	samples   int
	self      int
}

func newCollector() *collector {
	return &collector{
		files:     map[string]bool{},
		binaries:  map[string]bool{},
		libs:      map[string]bool{},
		pids:      map[int]bool{},
		readBytes: map[int]int64{},
		self:      os.Getpid(),
	}
}

func (c *collector) addBinary(p string) {
	if !usefulPath(p) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.binaries[p] = true
	c.files[p] = true
}

func (c *collector) addMapped(p string) {
	if !usefulPath(p) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if isSharedLibrary(p) {
		c.libs[p] = true
	}
	c.files[p] = true
}

func (c *collector) addFile(p string) {
	if !usefulPath(p) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.files[p] = true
}

func (c *collector) addReadBytes(pid int, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// rchar is cumulative per process, so keep the highest reading rather than
	// adding every sample together.
	if n > c.readBytes[pid] {
		c.readBytes[pid] = n
	}
}

// usefulPath filters out what cannot belong to a package: kernel filesystems,
// pipes and sockets, and the sensor's own scaffolding.
func usefulPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false // pipe:[1234], socket:[5678], anon_inode:...
	}
	switch {
	case strings.HasPrefix(p, "/proc/"), strings.HasPrefix(p, "/sys/"),
		strings.HasPrefix(p, "/dev/"), strings.HasPrefix(p, "/.docker-trim"):
		return false
	}
	return true
}

func isSharedLibrary(p string) bool {
	base := filepath.Base(p)
	return strings.Contains(base, ".so.") || strings.HasSuffix(base, ".so")
}

func (c *collector) emit(elapsed time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var total int64
	for _, n := range c.readBytes {
		total += n
	}
	m := manifest{
		AccessedFiles: sortedKeys(c.files),
		UsedBinaries:  sortedKeys(c.binaries),
		SharedLibs:    sortedKeys(c.libs),
		ReadBytes:     total,
		Samples:       c.samples,
		Processes:     len(c.pids),
		DurationMS:    elapsed.Milliseconds(),
	}

	encoded, err := json.Marshal(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "docker-trim-sensor: cannot encode the manifest: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s\n%s\n%s\n", beginMarker, encoded, endMarker)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

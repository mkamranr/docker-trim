// Command dtrim-sensor watches what a container actually uses.
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The manifest is delimited on stderr rather than written to a file: the image
// under trace may run as a user who cannot create one, and a marker costs
// nothing. dtrim reads the container's logs and takes what is between these.
const (
	beginMarker = "<<<DTRIM-TRACE-BEGIN>>>"
	endMarker   = "<<<DTRIM-TRACE-END>>>"
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
	interval := flag.Duration("interval", 50*time.Millisecond, "how often to sample /proc")
	settle := flag.Duration("settle", 0, "keep tracing this long after the command exits")
	flag.Parse()

	argv := flag.Args()
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "dtrim-sensor: no command to run")
		os.Exit(2)
	}

	c := newCollector()

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "dtrim-sensor: cannot start %s: %v\n", argv[0], err)
		c.emit(0)
		os.Exit(127)
	}

	// A container is normally stopped rather than allowed to finish, so the
	// manifest has to survive SIGTERM. Forward it and keep going.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for s := range signals {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(s)
			}
		}
	}()

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.sampleUntil(done, *interval)
	}()

	started := time.Now()
	err := cmd.Wait()
	elapsed := time.Since(started)
	if *settle > 0 {
		time.Sleep(*settle)
	}
	close(done)
	wg.Wait()

	c.emit(elapsed)
	os.Exit(exitCode(err))
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

func (c *collector) sampleUntil(done <-chan struct{}, every time.Duration) {
	// Sample immediately: a command that exits in milliseconds still executed,
	// and waiting for the first tick would miss it entirely.
	c.sample()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-done:
			c.sample() // one last look before the process table empties
			return
		case <-t.C:
			c.sample()
		}
	}
}

func (c *collector) sample() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	c.mu.Lock()
	c.samples++
	c.mu.Unlock()

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == c.self {
			continue
		}
		c.scanProcess(pid)
	}
}

func (c *collector) scanProcess(pid int) {
	dir := "/proc/" + strconv.Itoa(pid)

	// The executable. This is the single most useful signal: it names every
	// program that ran, which is what maps back to packages.
	if exe, err := os.Readlink(dir + "/exe"); err == nil {
		c.addBinary(exe)
	}

	// Mapped files: shared libraries, and anything mmapped such as a locale
	// archive or a JIT cache.
	if maps, err := os.ReadFile(dir + "/maps"); err == nil {
		for _, line := range strings.Split(string(maps), "\n") {
			if p := mappedPath(line); p != "" {
				c.addMapped(p)
			}
		}
	}

	// Open descriptors: config files, certificates, sockets. This is the part
	// sampling can miss, because a file opened and closed between two samples
	// never appears here.
	if fds, err := os.ReadDir(dir + "/fd"); err == nil {
		for _, fd := range fds {
			if target, err := os.Readlink(dir + "/fd/" + fd.Name()); err == nil {
				c.addFile(target)
			}
		}
	}

	if io, err := os.ReadFile(dir + "/io"); err == nil {
		c.addReadBytes(pid, parseRchar(string(io)))
	}

	c.mu.Lock()
	c.pids[pid] = true
	c.mu.Unlock()
}

// mappedPath extracts the file behind a line of /proc/pid/maps. Anonymous
// mappings and pseudo-entries such as [heap] have no file.
func mappedPath(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return ""
	}
	p := strings.Join(fields[5:], " ")
	if !strings.HasPrefix(p, "/") || strings.HasSuffix(p, " (deleted)") {
		return ""
	}
	return p
}

func parseRchar(io string) int64 {
	for _, line := range strings.Split(io, "\n") {
		if v, ok := strings.CutPrefix(line, "rchar: "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return n
			}
		}
	}
	return 0
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
		strings.HasPrefix(p, "/dev/"), strings.HasPrefix(p, "/.dtrim"):
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
		fmt.Fprintf(os.Stderr, "dtrim-sensor: cannot encode the manifest: %v\n", err)
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

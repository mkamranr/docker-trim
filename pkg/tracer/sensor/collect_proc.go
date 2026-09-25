package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The /proc sampling collector. It needs no privileges at all, which is what
// makes it the default, and it races with short-lived processes, which is why
// the ptrace collector exists. See docs/tracing.md.

// runProc starts the command and samples /proc while it runs.
func runProc(argv []string, c *collector, interval, settle time.Duration) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return 127, fmt.Errorf("cannot start %s: %w", argv[0], err)
	}
	forwardSignals(cmd.Process)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.sampleUntil(done, interval)
	}()

	err := cmd.Wait()
	if settle > 0 {
		time.Sleep(settle)
	}
	close(done)
	wg.Wait()
	return exitCode(err), nil
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

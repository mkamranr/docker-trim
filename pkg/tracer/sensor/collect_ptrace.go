//go:build linux && (amd64 || arm64)

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

// The ptrace collector. Where the /proc sampler takes snapshots and can miss
// anything that happens between two of them, this stops the process at every
// syscall boundary, so nothing is missed by construction.
//
// It costs privileges (CAP_SYS_PTRACE and an unconfined seccomp profile) and
// runtime: every traced syscall is two context switches. That is the trade, and
// it is why this is not the default. See docs/tracing.md.

// atFDCWD is openat's "relative to the working directory" sentinel.
const atFDCWD = -100

// Constants Go's syscall package does not export on every architecture.
const (
	// ptraceOExitkill makes the kernel kill every tracee if the tracer dies, so
	// a sensor that crashes cannot leave a container full of stopped processes.
	ptraceOExitkill = 0x00100000
	// ptraceOTraceexit stops a tracee before it disappears, which is the last
	// moment its /proc entry can still be read.
	ptraceOTraceexit = 0x00000040
	// ptraceEventExit is the stop that option produces.
	ptraceEventExit = 6

	// Open flags, from asm-generic and the same on every architecture docker-trim
	// builds the sensor for.
	oCreat     = 0o100
	oDirectory = 0o200000

	// ptraceGetSyscallInfo asks the kernel what a syscall stop actually is,
	// rather than inferring it. Linux 5.3 and later. Go's syscall package does
	// not export it; 0x4206 next door is PTRACE_SEIZE, which returns EIO on an
	// already-traced process and looks exactly like an unsupported kernel.
	ptraceGetSyscallInfo = 0x420e
	syscallInfoEntry     = 1
	syscallInfoExit      = 2
	// syscallInfoSize covers struct ptrace_syscall_info, which is 88 bytes,
	// with room for a kernel that grows it.
	syscallInfoSize = 128
)

// syscallInfo is the part of struct ptrace_syscall_info this collector reads.
//
// Asking the kernel is the only reliable way to tell a syscall entry from an
// exit. Tracking it in the tracer works until a process forks: the child's
// first stop is not the entry the parent's bookkeeping expects, and from then
// on every entry is read as an exit. That bug silently drops most of a shell
// script's file accesses, which is exactly the case people trace.
//
// It also reports the syscall number and arguments directly, so this collector
// needs no per-architecture register decoding at all.
type syscallInfo struct {
	op   uint8
	nr   uint64
	args [6]uint64
	rval int64
}

// getSyscallInfo reads the kernel's description of the current stop.
func getSyscallInfo(pid int) (syscallInfo, error) {
	var buf [syscallInfoSize]byte
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, ptraceGetSyscallInfo,
		uintptr(pid), syscallInfoSize, uintptr(unsafe.Pointer(&buf[0])), 0, 0)
	if errno != 0 {
		return syscallInfo{}, errno
	}

	// struct ptrace_syscall_info: op at 0, arch at 4, instruction_pointer at 8,
	// stack_pointer at 16, then the union. Offsets confirmed against
	// linux/ptrace.h: entry.nr at 24, entry.args at 32, exit.rval at 24.
	info := syscallInfo{op: buf[0]}
	switch info.op {
	case syscallInfoEntry:
		info.nr = binary.NativeEndian.Uint64(buf[24:])
		for i := range info.args {
			info.args[i] = binary.NativeEndian.Uint64(buf[32+i*8:])
		}
	case syscallInfoExit:
		info.rval = int64(binary.NativeEndian.Uint64(buf[24:]))
	}
	return info, nil
}

// pending is what a tracee asked for at syscall entry, held until the exit stop
// says whether it worked.
//
// Recording on exit rather than entry is the whole point of this collector: a
// failed open proves the file is absent, and counting it would attribute a file
// to a package that never provided it.
type pending struct {
	nr   uint64
	path string
}

// tracee is one process under trace.
type tracee struct {
	pending pending
	mem     *os.File
}

// runPtrace runs the command under ptrace and records every successful execve
// and openat.
func runPtrace(argv []string, c *collector) (int, error) {
	// Every ptrace request has to come from the thread that attached, and Go
	// will otherwise move this goroutine between threads at will.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Ptrace makes the child call PTRACE_TRACEME and stop at its own execve, so
	// tracing begins before the program's first instruction.
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}

	if err := cmd.Start(); err != nil {
		return 127, fmt.Errorf("cannot start %s: %w", argv[0], err)
	}
	root := cmd.Process.Pid
	forwardSignals(cmd.Process)

	// cmd.Wait would reap the child out from under the trace loop, so the
	// process is waited on directly from here on.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(root, &ws, 0, nil); err != nil {
		return 127, fmt.Errorf("waiting for %s to stop: %w", argv[0], err)
	}

	opts := syscall.PTRACE_O_TRACESYSGOOD | // mark syscall stops as SIGTRAP|0x80
		syscall.PTRACE_O_TRACEFORK | // follow the whole process tree, which is
		syscall.PTRACE_O_TRACEVFORK | // where a shell wrapper puts the real work
		syscall.PTRACE_O_TRACECLONE |
		syscall.PTRACE_O_TRACEEXEC |
		ptraceOTraceexit | // catch each process while /proc still has it
		ptraceOExitkill // never leave orphans behind if the sensor dies
	if err := syscall.PtraceSetOptions(root, opts); err != nil {
		return 127, fmt.Errorf("cannot set ptrace options (does this container have "+
			"CAP_SYS_PTRACE and an unconfined seccomp profile?): %w", err)
	}

	// Whether the kernel supports PTRACE_GET_SYSCALL_INFO can only be answered
	// at a syscall stop; asking at the initial signal stop returns EIO on a
	// kernel that supports it perfectly well. So the answer is collected in the
	// loop and reported afterwards, rather than guessed at up front.
	var infoOK, infoFailed int

	tracked := map[int]*tracee{root: {}}
	// The child's first execve completes before the tracer gets control, so
	// watching the syscall never sees the program itself. Reading the link is
	// also more accurate than the path that was passed: it is resolved.
	c.recordExe(root)
	defer func() {
		for _, t := range tracked {
			if t.mem != nil {
				_ = t.mem.Close()
			}
		}
	}()

	exit := 0
	_ = syscall.PtraceSyscall(root, 0)

	for {
		wpid, err := syscall.Wait4(-1, &ws, syscall.WALL, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || wpid <= 0 {
			// ECHILD means every tracee is gone, which is the normal end.
			break
		}

		if ws.Exited() || ws.Signaled() {
			if wpid == root {
				exit = ws.ExitStatus()
			}
			c.countProcess(wpid)
			if t := tracked[wpid]; t != nil && t.mem != nil {
				_ = t.mem.Close()
			}
			delete(tracked, wpid)
			if len(tracked) == 0 {
				break
			}
			continue
		}
		if !ws.Stopped() {
			continue
		}

		t := tracked[wpid]
		if t == nil {
			// A child whose birth event has not been seen yet. Its first stop
			// is a SIGSTOP, and the next syscall stop is an entry.
			t = &tracee{}
			tracked[wpid] = t
		}

		deliver := 0
		switch sig := ws.StopSignal(); sig {
		case syscall.SIGTRAP | 0x80:
			if c.onSyscallStop(wpid, t) {
				infoOK++
			} else {
				infoFailed++
			}

		case syscall.SIGTRAP:
			switch event := (int(ws) >> 16) & 0xff; event {
			case syscall.PTRACE_EVENT_FORK, syscall.PTRACE_EVENT_VFORK, syscall.PTRACE_EVENT_CLONE:
				if child, err := syscall.PtraceGetEventMsg(wpid); err == nil {
					if _, known := tracked[int(child)]; !known {
						tracked[int(child)] = &tracee{}
					}
					_ = syscall.PtraceSyscall(int(child), 0)
				}
			case syscall.PTRACE_EVENT_EXEC:
				// The image was replaced, so the old address space and its
				// /proc/pid/mem handle are gone.
				if t.mem != nil {
					_ = t.mem.Close()
					t.mem = nil
				}
				c.recordExe(wpid)
			case ptraceEventExit:
				// The last chance to read this process's counters.
				c.recordIO(wpid)
			}

		case syscall.SIGSTOP:
			// A new child's initial stop. Swallowing it is correct: delivering
			// it would suspend the process we are trying to observe.

		default:
			// Anything else belongs to the program, so pass it through.
			deliver = int(sig)
		}

		if err := syscall.PtraceSyscall(wpid, deliver); err != nil {
			delete(tracked, wpid)
			if len(tracked) == 0 {
				break
			}
		}
	}
	if infoOK == 0 && infoFailed > 0 {
		return exit, fmt.Errorf("this kernel does not support PTRACE_GET_SYSCALL_INFO "+
			"(Linux 5.3 and later), so no syscall could be decoded across %d stops. "+
			"Use --tracer proc, which works anywhere", infoFailed)
	}
	return exit, nil
}

// onSyscallStop handles one syscall boundary: read the arguments going in, and
// commit them coming out if the call succeeded. It reports whether the kernel
// answered.
func (c *collector) onSyscallStop(pid int, t *tracee) bool {
	info, err := getSyscallInfo(pid)
	if err != nil {
		return false
	}

	if info.op == syscallInfoEntry {
		t.pending = pending{}

		nr, args := info.nr, info.args
		switch nr {
		case sysExecve:
			t.pending = pending{nr: nr, path: c.readPath(pid, t, args[0], atFDCWD)}
		case sysExecveat:
			t.pending = pending{nr: nr, path: c.readPath(pid, t, args[1], int64(args[0]))}
		case sysOpenat:
			if consumesFile(args[2]) {
				t.pending = pending{nr: nr, path: c.readPath(pid, t, args[1], int64(args[0]))}
			}
		case sysOpenat2:
			// openat2 takes a struct rather than a flag word. Reading it would
			// mean a second memory read for a syscall almost nothing uses yet,
			// so the path is recorded and the flags are not inspected.
			t.pending = pending{nr: nr, path: c.readPath(pid, t, args[1], int64(args[0]))}
		case sysOpen:
			if consumesFile(args[1]) {
				t.pending = pending{nr: nr, path: c.readPath(pid, t, args[0], atFDCWD)}
			}
		}
		return true
	}
	if info.op != syscallInfoExit || t.pending.path == "" {
		return true
	}
	// A negative return is an errno: the file was not there, or could not be
	// opened. Either way nothing used it.
	if info.rval < 0 {
		t.pending = pending{}
		return true
	}

	switch t.pending.nr {
	case sysExecve, sysExecveat:
		c.addBinary(t.pending.path)
	default:
		c.addFile(t.pending.path)
		// A library opened by the loader is a shared library whether or not it
		// is later mapped, and the mapping is not a syscall we watch.
		c.addMappedFrom(t.pending.path)
	}
	t.pending = pending{}
	return true
}

// consumesFile reports whether an open is reading something the image already
// contains, as opposed to creating something new.
//
// A program that writes a temporary file is not using a file the image shipped,
// and counting those would attribute a package for something it never provided.
// Python's atomic .pyc writes alone produce a dozen of them per run. Opening a
// directory is likewise a lookup rather than a use.
func consumesFile(flags uint64) bool {
	return flags&oCreat == 0 && flags&oDirectory == 0
}

// addMappedFrom records a path as a shared library when it looks like one.
// The /proc collector learns this from the mapping table; this one only sees
// the open, so it classifies by name.
func (c *collector) addMappedFrom(p string) {
	if !usefulPath(p) || !isSharedLibrary(p) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.libs[p] = true
}

// countProcess records that a pid was observed. The /proc collector counts
// these as it walks the process table; this one counts them as they exit.
func (c *collector) countProcess(pid int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pids[pid] = true
}

// recordExe reads the resolved path of what a process is executing.
func (c *collector) recordExe(pid int) {
	if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil {
		c.addBinary(exe)
	}
}

// recordIO reads a process's byte counters while its /proc entry still exists.
func (c *collector) recordIO(pid int) {
	if io, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/io"); err == nil {
		c.addReadBytes(pid, parseRchar(string(io)))
	}
}

// readPath reads a NUL-terminated string out of the tracee and makes it
// absolute, since a relative openat says nothing about which file was used.
func (c *collector) readPath(pid int, t *tracee, addr uint64, dirfd int64) string {
	if addr == 0 {
		return ""
	}
	if t.mem == nil {
		f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/mem")
		if err != nil {
			return ""
		}
		t.mem = f
	}

	// PATH_MAX is 4096; reading in one go is one syscall instead of many.
	buf := make([]byte, 4096)
	n, err := t.mem.ReadAt(buf, int64(addr))
	if n == 0 && err != nil {
		return ""
	}
	end := 0
	for end < n && buf[end] != 0 {
		end++
	}
	p := string(buf[:end])
	if p == "" {
		return ""
	}
	if p[0] == '/' {
		return path.Clean(p)
	}

	// Relative: resolve against the working directory, or against the
	// directory openat was given.
	base := "/proc/" + strconv.Itoa(pid) + "/cwd"
	if dirfd != atFDCWD && dirfd >= 0 {
		base = "/proc/" + strconv.Itoa(pid) + "/fd/" + strconv.FormatInt(dirfd, 10)
	}
	dir, err := os.Readlink(base)
	if err != nil {
		return ""
	}
	return path.Join(dir, p)
}

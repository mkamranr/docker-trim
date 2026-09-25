//go:build linux

package main

import "syscall"

// The syscalls this collector watches.
//
// Their numbers differ between architectures, but Go's syscall package already
// defines the right ones for whichever it is compiled for, and the kernel
// reports the number directly through PTRACE_GET_SYSCALL_INFO, so nothing here
// has to be decoded by hand.
const (
	sysExecve  = syscall.SYS_EXECVE
	sysOpenat  = syscall.SYS_OPENAT
	sysOpenat2 = 437 // added after both architectures, so the number is shared
)

//go:build linux && arm64

package main

import "syscall"

const (
	// arm64 has no open(2) at all: everything goes through openat. The
	// constant exists so the shared switch compiles, and nothing can match it.
	sysOpen     = ^uint64(0)
	sysExecveat = syscall.SYS_EXECVEAT
)

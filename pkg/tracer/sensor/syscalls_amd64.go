//go:build linux && amd64

package main

import "syscall"

// x86-64 keeps the original open(2) and numbers execveat differently.
const (
	sysOpen     = syscall.SYS_OPEN
	sysExecveat = 322
)

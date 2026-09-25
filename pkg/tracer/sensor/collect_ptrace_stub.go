//go:build !linux || (!amd64 && !arm64)

package main

import "fmt"

// The ptrace collector is Linux-only and needs per-architecture register
// decoding. This stub keeps the sensor compiling on a developer's machine so
// the shared code is still vetted and tested there; the real thing is always
// built for Linux inside the ephemeral image.
func runPtrace([]string, *collector) (int, error) {
	return 2, fmt.Errorf("the ptrace collector is only built for linux on amd64 and arm64")
}

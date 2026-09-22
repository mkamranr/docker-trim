// Package version carries build metadata stamped in by the linker.
package version

import (
	"fmt"
	"runtime"
)

// Overwritten at build time via -ldflags; see the Makefile and .goreleaser.yaml.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Version is the semantic version of this build, without a leading "v".
func Version() string { return version }

// String is the value shown by `dtrim --version`.
func String() string {
	return fmt.Sprintf("dtrim %s (commit %s, built %s, %s/%s, %s)",
		version, commit, date, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

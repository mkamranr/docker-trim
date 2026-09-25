package analyzer

import (
	"sort"
	"strings"
)

// Usage is what a trace says about an image's installed packages.
type Usage struct {
	// Used are packages that own at least one file the container touched.
	Used []Package `json:"used"`
	// Unused are packages nothing touched and that are safe to consider for
	// removal. "Consider" is the operative word: see Coverage.
	Unused []Package `json:"unused"`
	// Essential are packages left alone regardless, because removing them
	// breaks the image whether or not a trace happened to touch them.
	Essential []Package `json:"essential"`
	// UnownedFiles are paths the container used that no package claims:
	// application code, generated files, anything installed by hand.
	UnownedFiles []string `json:"unownedFiles,omitempty"`
	// RemovableBytes is what the unused packages report as their installed
	// size. It is the package database's own figure, not a measurement.
	RemovableBytes int64 `json:"removableBytes"`
	// Notes record anything that limits how far this should be trusted.
	Notes []string `json:"notes,omitempty"`
}

// neverRemove are packages whose absence breaks an image no matter what a trace
// observed. The dynamic loader is only read at exec time, a trust store only
// when something makes a TLS connection, and time zone data only when something
// formats a local time: a short trace sees none of that and would happily
// suggest deleting all three.
var neverRemove = map[string]bool{
	// Debian
	"libc6": true, "libc-bin": true, "base-files": true, "base-passwd": true,
	"ca-certificates": true, "tzdata": true, "libgcc-s1": true, "libstdc++6": true,
	"zlib1g": true, "libssl3": true, "libssl3t64": true, "openssl": true,
	"dpkg": true, "debianutils": true, "libcrypt1": true, "netbase": true,
	// Alpine
	"musl": true, "musl-utils": true, "alpine-baselayout": true,
	"alpine-baselayout-data": true, "alpine-keys": true, "busybox": true,
	"busybox-binsh": true, "ca-certificates-bundle": true, "libcrypto3": true,
	"libssl3-alpine": true, "zlib": true, "libgcc": true, "libstdc++": true,
	"ssl_client": true, "scanelf": true,
}

// AttributeUsage maps the files a trace saw onto the packages that own them.
//
// A package with no observed file is reported as unused, which is a statement
// about the trace and not about the package: it means nothing exercised it
// while dtrim was watching. Coverage is what tells you how much that is worth,
// and it is why removal is a decision for the person who knows the workload.
func AttributeUsage(rep *ImageReport, manifest TraceManifest) Usage {
	var u Usage

	if len(rep.Packages) == 0 {
		u.Notes = append(u.Notes,
			"No package inventory is available for this image, so used files cannot be "+
				"attributed to packages.")
		return u
	}
	if !ownershipKnown(rep.Packages) {
		u.Notes = append(u.Notes,
			"The package database does not record which files belong to which package, so "+
				"usage cannot be attributed.")
		return u
	}

	// One pass to build the reverse index: a path to the package owning it.
	owner := make(map[string]string, 1<<14)
	for _, p := range rep.Packages {
		for _, f := range p.Files {
			owner[f] = p.Name
		}
	}

	touched := map[string]bool{}
	var unowned []string
	for _, f := range accessedPaths(manifest) {
		var found bool
		for _, candidate := range pathAliases(f) {
			if name, ok := owner[candidate]; ok {
				touched[name] = true
				found = true
				break
			}
		}
		if !found {
			unowned = append(unowned, f)
		}
	}
	sort.Strings(unowned)
	u.UnownedFiles = unowned

	for _, p := range rep.Packages {
		switch {
		case touched[p.Name]:
			u.Used = append(u.Used, p)
		case p.Essential || neverRemove[p.Name]:
			u.Essential = append(u.Essential, p)
		default:
			u.Unused = append(u.Unused, p)
			u.RemovableBytes += p.SizeBytes
		}
	}

	sort.Slice(u.Unused, func(i, j int) bool { return u.Unused[i].SizeBytes > u.Unused[j].SizeBytes })
	sort.Slice(u.Used, func(i, j int) bool { return u.Used[i].SizeBytes > u.Used[j].SizeBytes })
	return u
}

// accessedPaths is every path a trace observed, in one list.
func accessedPaths(m TraceManifest) []string {
	seen := make(map[string]bool, len(m.AccessedFiles))
	out := make([]string, 0, len(m.AccessedFiles))
	for _, group := range [][]string{m.AccessedFiles, m.UsedBinaries, m.SharedLibs} {
		for _, f := range group {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out
}

// usrMerged are the directories Debian and most modern distributions turned
// into symlinks under /usr.
var usrMerged = []string{"/lib/", "/lib64/", "/bin/", "/sbin/"}

// pathAliases returns the ways a package database might spell a path.
//
// A traced open records the path the program actually asked for, which for a
// shared library is whatever the loader found in ld.so.cache: usually
// /lib/x86_64-linux-gnu/libc.so.6. dpkg records the same file as
// /usr/lib/x86_64-linux-gnu/libc.so.6, because /lib is a symlink to /usr/lib.
// Without reconciling the two, every library a trace observes looks unowned and
// the package that provides it looks unused, which is the most dangerous way
// this tool could be wrong.
func pathAliases(p string) []string {
	p = strings.TrimSuffix(p, "/")
	out := []string{p}
	for _, dir := range usrMerged {
		if strings.HasPrefix(p, dir) {
			out = append(out, "/usr"+p)
			return out
		}
		if strings.HasPrefix(p, "/usr"+dir) {
			out = append(out, strings.TrimPrefix(p, "/usr"))
			return out
		}
	}
	return out
}

func ownershipKnown(pkgs []Package) bool {
	for _, p := range pkgs {
		if len(p.Files) > 0 {
			return true
		}
	}
	return false
}

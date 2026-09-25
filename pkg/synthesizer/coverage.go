package synthesizer

import (
	"path"
	"sort"
	"strings"

	"github.com/mkamranr/dtrim/pkg/analyzer"
)

// RuntimeGap is something a trace saw the program use that the runtime stage
// will not contain.
//
// This is the failure this tool is most capable of causing. A rewrite that
// drops a shell is correct for almost every service and catastrophic for the
// one that shells out, and the damage does not show up at build time: the image
// builds, starts, and fails the first time that code path runs. Static analysis
// cannot see it. A trace can.
type RuntimeGap struct {
	// Binary is the executable the trace observed running.
	Binary string
	// Why says what makes it unavailable in the new runtime stage.
	Why string
}

// Explain renders the gap as a warning.
func (g RuntimeGap) Explain() string {
	return "The trace saw `" + g.Binary + "` executed, but " + g.Why +
		" Either keep a base that provides it, or remove whatever runs it."
}

// alwaysProvided are things every runtime base here has, or that are not real
// executables on disk.
var alwaysProvided = map[string]bool{
	// The kernel reports these for a process that has already exec'd into the
	// image's own entrypoint under a shim.
	"": true,
}

// checkRuntimeCoverage compares what a trace executed against what the planned
// runtime stage will actually contain.
//
// Only executables are checked. A missing shared library is caught by the build
// or by the smoke test in --verify; a missing binary is not, because nothing
// touches it until the code path that shells out runs.
func checkRuntimeCoverage(p Plan, trace *analyzer.TraceManifest) []RuntimeGap {
	if trace == nil || !p.Supported || len(trace.UsedBinaries) == 0 {
		return nil
	}

	// Anything copied across the stage boundary is present by definition, as
	// is anything under a copied directory.
	copied := func(bin string) bool {
		for _, art := range p.Artifacts {
			if bin == art.To || strings.HasPrefix(bin, strings.TrimSuffix(art.To, "/")+"/") {
				return true
			}
		}
		return false
	}

	var gaps []RuntimeGap
	seen := map[string]bool{}
	for _, bin := range trace.UsedBinaries {
		if alwaysProvided[bin] || copied(bin) || seen[bin] {
			continue
		}
		why, missing := unavailable(p, bin)
		if !missing {
			continue
		}
		seen[bin] = true
		gaps = append(gaps, RuntimeGap{Binary: bin, Why: why})
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].Binary < gaps[j].Binary })
	return gaps
}

// unavailable decides whether a runtime base will lack a given executable.
//
// It answers conservatively: a base is only reported as lacking something when
// that is a property of the base rather than a guess. Warning about a binary
// that turns out to be present is how a tool trains people to ignore it.
func unavailable(p Plan, bin string) (string, bool) {
	base := strings.ToLower(p.Runtime)
	name := path.Base(bin)

	switch {
	case base == "scratch":
		return "scratch contains nothing at all beyond what is copied into it.", true

	case strings.Contains(base, "distroless"):
		// distroless ships no shell and no userland. The language runtimes
		// ship their own interpreter and nothing else.
		if interpreterOf(base) == name {
			return "", false
		}
		return "a distroless base has no shell and no general userland, so that binary " +
			"will not exist there.", true

	case strings.Contains(base, "alpine"):
		// busybox covers a large slice of coreutils, so only flag the tools it
		// is known not to provide.
		if busyboxProvides[name] {
			return "", false
		}
		if notInAlpineBase[name] {
			return "alpine's base image does not include it; it would need installing " +
				"in the runtime stage.", true
		}
		return "", false
	}
	return "", false
}

// interpreterOf names the one executable a language distroless image provides.
func interpreterOf(base string) string {
	switch {
	case strings.Contains(base, "nodejs"):
		return "node"
	case strings.Contains(base, "python3"):
		return "python3"
	case strings.Contains(base, "java"):
		return "java"
	}
	return ""
}

// busyboxProvides are the applets alpine's busybox supplies, so finding one of
// these in a trace says nothing alarming.
var busyboxProvides = map[string]bool{
	"sh": true, "ash": true, "busybox": true, "cat": true, "ls": true, "cp": true,
	"mv": true, "rm": true, "mkdir": true, "chmod": true, "chown": true, "ln": true,
	"echo": true, "printf": true, "grep": true, "sed": true, "awk": true, "find": true,
	"head": true, "tail": true, "sort": true, "uniq": true, "wc": true, "cut": true,
	"tr": true, "date": true, "sleep": true, "env": true, "id": true, "ps": true,
	"kill": true, "tar": true, "gzip": true, "wget": true, "nc": true, "ping": true,
	"hostname": true, "uname": true, "df": true, "du": true, "touch": true, "test": true,
	"true": true, "false": true, "dirname": true, "basename": true, "xargs": true,
}

// notInAlpineBase are common tools alpine does not ship, so a trace that
// executes one is a real warning rather than noise.
var notInAlpineBase = map[string]bool{
	"bash": true, "curl": true, "git": true, "python3": true, "python": true,
	"perl": true, "ruby": true, "node": true, "java": true, "gcc": true, "make": true,
	"openssl": true, "ssh": true, "rsync": true, "jq": true, "dash": true,
}

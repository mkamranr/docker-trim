package synthesizer

import (
	"sort"
	"strings"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
)

// pruneUnused removes packages a trace never saw used from the install commands
// that ask for them.
//
// Two constraints decide the whole shape of this, and both are easy to get
// wrong in a way that looks like it works:
//
// It removes packages from the install rather than purging them afterwards. A
// purge in a later RUN cannot shrink an earlier layer, so appending one makes
// the image bigger while appearing to clean up. docker-trim reports that as DT002 in
// other people's Dockerfiles and must not do it in its own output.
//
// It only touches the stage that ships. A trace observes the finished image
// running, so it knows nothing about what compiling it required: the compiler
// that a builder stage needs is exactly the sort of thing a runtime trace never
// sees. Pruning a builder on that evidence would break the build.
func pruneUnused(a *analyzer.Analysis, opts Options) []string {
	if !opts.PruneUnused || opts.Usage == nil {
		return nil
	}
	final := a.FinalStage()
	if final == nil {
		return nil
	}
	// A single-stage file builds and ships in the same stage, so its install
	// commands serve both. There is no way to tell from a runtime trace which
	// packages the build needed, and guessing breaks builds.
	if !a.MultiStage() {
		return nil
	}

	removable := map[string]bool{}
	for _, p := range opts.Usage.Unused {
		// Belt and braces: AttributeUsage already keeps language packages out
		// of Unused, and it matters enough to check here too. A PyPI package
		// sharing a name with an OS one would otherwise be stripped from an
		// apt-get install line on evidence about something else entirely.
		if p.IsOS() {
			removable[p.Name] = true
		}
	}
	if len(removable) == 0 {
		return nil
	}

	var pruned []string
	for i := range final.Instructions {
		ins := &final.Instructions[i]
		if ins.Keyword != "RUN" || ins.Exec {
			continue
		}

		var (
			changed bool
			cmds    [][]string
		)
		for _, cmd := range analyzer.Commands(ins.Args) {
			if !isPackageInstall(cmd) {
				cmds = append(cmds, cmd)
				continue
			}
			kept, dropped := dropPackages(cmd, removable)
			if len(dropped) == 0 {
				cmds = append(cmds, cmd)
				continue
			}
			changed = true
			pruned = append(pruned, dropped...)
			// An install with nothing left to install is dead weight, and
			// `apt-get install -y` with no arguments is not an error, just a
			// pointless layer.
			if installsNothing(kept) {
				continue
			}
			cmds = append(cmds, kept)
		}
		if !changed {
			continue
		}

		if len(cmds) == 0 {
			// The whole RUN existed only to install things nothing uses.
			ins.Keyword = ""
			continue
		}
		var args []string
		for j, cmd := range cmds {
			if j > 0 {
				args = append(args, "&&")
			}
			args = append(args, cmd...)
		}
		ins.Args = args
		ins.Raw = ""
		ins.Lead = append(ins.Lead,
			comment("DT106", "dropped packages the trace never saw used"))
	}

	if len(pruned) == 0 {
		return nil
	}
	// Dropping an instruction leaves a hole; close it rather than emitting a
	// blank keyword.
	final.Instructions = compactInstructions(final.Instructions)

	sort.Strings(pruned)
	return dedupeStrings(pruned)
}

// isPackageInstall reports whether a command installs operating-system packages.
func isPackageInstall(cmd []string) bool {
	return analyzer.IsCmd(cmd, "apt-get", "apt", "apk", "yum", "dnf") &&
		analyzer.HasSubcommand(cmd, "install", "add")
}

// dropPackages removes the named packages from an install command, keeping its
// flags and ordering intact.
func dropPackages(cmd []string, removable map[string]bool) (kept []string, dropped []string) {
	seenVerb := false
	for i, w := range cmd {
		if i == 0 || strings.HasPrefix(w, "-") {
			kept = append(kept, w)
			continue
		}
		if !seenVerb {
			seenVerb = true // install / add
			kept = append(kept, w)
			continue
		}
		if removable[w] {
			dropped = append(dropped, w)
			continue
		}
		kept = append(kept, w)
	}
	return kept, dropped
}

// installsNothing reports whether an install command has no packages left.
func installsNothing(cmd []string) bool {
	seenVerb := false
	for i, w := range cmd {
		if i == 0 || strings.HasPrefix(w, "-") {
			continue
		}
		if !seenVerb {
			seenVerb = true
			continue
		}
		return false
	}
	return true
}

// compactInstructions drops the placeholders left by removing an instruction.
func compactInstructions(in []analyzer.Instruction) []analyzer.Instruction {
	out := in[:0:0]
	for _, ins := range in {
		if ins.Keyword == "" {
			continue
		}
		out = append(out, ins)
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

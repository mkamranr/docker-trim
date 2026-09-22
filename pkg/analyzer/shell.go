package analyzer

import "strings"

// shellOperators separate one command from the next inside a single RUN.
var shellOperators = map[string]bool{"&&": true, "||": true, ";": true, "|": true}

// Commands splits a shell-form RUN into its individual commands. `RUN apt-get
// update && apt-get install -y curl` yields two. Rules reason about commands
// rather than raw strings so that `pip install` is not confused with
// `echo "pip install"`.
func Commands(args []string) [][]string {
	var (
		out [][]string
		cur []string
	)
	for _, w := range args {
		if shellOperators[w] {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, w)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// IsCmd reports whether a command invokes the given program, ignoring any
// leading environment assignments and a `sudo` prefix.
func IsCmd(cmd []string, names ...string) bool {
	i := 0
	for i < len(cmd) && (strings.Contains(cmd[i], "=") && !strings.HasPrefix(cmd[i], "-") || cmd[i] == "sudo") {
		i++
	}
	if i >= len(cmd) {
		return false
	}
	// Match the basename so /usr/bin/apt-get counts as apt-get.
	base := cmd[i]
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	for _, n := range names {
		if base == n {
			return true
		}
	}
	return false
}

// HasSubcommand reports whether the command's first non-flag argument after the
// program name is one of the given verbs, e.g. `apt-get install`.
func HasSubcommand(cmd []string, verbs ...string) bool {
	for i := 1; i < len(cmd); i++ {
		if strings.HasPrefix(cmd[i], "-") {
			continue
		}
		for _, v := range verbs {
			if cmd[i] == v {
				return true
			}
		}
		return false
	}
	return false
}

// HasFlag reports whether any word in the command matches a flag exactly or as
// a `--flag=value` prefix.
func HasFlag(cmd []string, flags ...string) bool {
	for _, w := range cmd {
		for _, f := range flags {
			if w == f || strings.HasPrefix(w, f+"=") {
				return true
			}
		}
	}
	return false
}

// InstalledPackages returns the package names an install command names, which
// is every trailing argument that is not a flag or a flag's value.
func InstalledPackages(cmd []string) []string {
	var out []string
	seenVerb := false
	for i := 1; i < len(cmd); i++ {
		w := cmd[i]
		if strings.HasPrefix(w, "-") {
			continue
		}
		if !seenVerb {
			seenVerb = true // the verb itself: install / add
			continue
		}
		out = append(out, w)
	}
	return out
}

// JoinCommand renders a command back to a shell string.
func JoinCommand(cmd []string) string { return strings.Join(cmd, " ") }

package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Rule is one thing dtrim knows how to notice about a Dockerfile.
//
// The interface mirrors the shape used by the sibling ctrim project: small,
// stateless units registered in one place, each owning its own explanation.
// Adding a rule means writing one of these and appending it to registry; see
// CONTRIBUTING.md.
type Rule interface {
	ID() string
	Title() string
	Severity() Severity
	Confidence() Confidence
	// Check reports what the rule found. It must not mutate the Analysis.
	Check(*Analysis) []Finding
}

// Fixer is a Rule that can also repair what it found.
//
// Fix mutates the Analysis in place and returns the findings it resolved. A
// fixer must be idempotent: running it twice has to leave the file unchanged
// the second time, which the rule tests enforce.
type Fixer interface {
	Rule
	Fix(*Analysis) []Finding
}

// registry is every rule dtrim ships, in ID order.
func registry() []Rule {
	return []Rule{
		ruleNoInstallRecommends{},
		ruleAptListsNotCleaned{},
		ruleSplitAptUpdate{},
		rulePipNoCacheDir{},
		ruleApkNoCache{},
		ruleNpmCache{},
		ruleCopyBeforeManifest{},
		ruleAddRemoteURL{},
		ruleFloatingBaseTag{},
		ruleRunsAsRoot{},
		ruleDevToolsInFinalStage{},
		ruleMergeableRuns{},
		ruleSecretInEnv{},
		ruleMissingDockerignore{},
		ruleRunCd{},
	}
}

// Lint runs every rule and returns the findings sorted by severity then line.
func Lint(a *Analysis) []Finding {
	var out []Finding
	for _, r := range registry() {
		out = append(out, r.Check(a)...)
	}
	sortFindings(out)
	return out
}

// FixAll applies every fixer whose confidence is at or below max, then re-lints
// so the returned findings reflect the repaired file. Findings the fixers
// resolved come back with Fixed set, which is what the diff report renders.
func FixAll(a *Analysis, max Confidence) (fixed []Finding, remaining []Finding) {
	for _, r := range registry() {
		f, ok := r.(Fixer)
		if !ok || r.Confidence().Rank() > max.Rank() {
			continue
		}
		for _, found := range f.Fix(a) {
			found.Fixed = true
			fixed = append(fixed, found)
		}
	}
	sortFindings(fixed)
	return fixed, Lint(a)
}

func sortFindings(f []Finding) {
	rank := map[Severity]int{
		SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2,
		SeverityLow: 3, SeverityInfo: 4,
	}
	sort.SliceStable(f, func(i, j int) bool {
		if rank[f[i].Severity] != rank[f[j].Severity] {
			return rank[f[i].Severity] < rank[f[j].Severity]
		}
		return f[i].Line < f[j].Line
	})
}

// finding builds a Finding carrying the rule's own metadata, so a rule can
// never report a severity that disagrees with its declaration.
func finding(r Rule, line int, detail string, fixable bool, saving int64) Finding {
	return Finding{
		RuleID:          r.ID(),
		Title:           r.Title(),
		Detail:          detail,
		Severity:        r.Severity(),
		Confidence:      r.Confidence(),
		Line:            line,
		Fixable:         fixable,
		EstimatedSaving: saving,
	}
}

// rewrite replaces an instruction's arguments and drops its captured source, so
// the emitter renders it from parts instead of echoing the original text.
func rewrite(ins *Instruction, args []string) {
	ins.Args = args
	ins.Raw = ""
}

// eachRun visits every shell-form RUN in every stage.
func eachRun(a *Analysis, fn func(stage int, ins *Instruction)) {
	for si := range a.Stages {
		for ii := range a.Stages[si].Instructions {
			ins := &a.Stages[si].Instructions[ii]
			if ins.Keyword == "RUN" && !ins.Exec {
				fn(si, ins)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// DT001 apt-get install without --no-install-recommends
// -----------------------------------------------------------------------------

type ruleNoInstallRecommends struct{}

func (ruleNoInstallRecommends) ID() string             { return "DT001" }
func (ruleNoInstallRecommends) Title() string          { return "apt-get install pulls recommended packages" }
func (ruleNoInstallRecommends) Severity() Severity     { return SeverityMedium }
func (ruleNoInstallRecommends) Confidence() Confidence { return ConfidenceSafe }

func (r ruleNoInstallRecommends) Check(a *Analysis) []Finding {
	var out []Finding
	eachRun(a, func(_ int, ins *Instruction) {
		for _, cmd := range Commands(ins.Args) {
			if !IsCmd(cmd, "apt-get", "apt") || !HasSubcommand(cmd, "install") {
				continue
			}
			if HasFlag(cmd, "--no-install-recommends") {
				continue
			}
			out = append(out, finding(r, ins.Line,
				"Recommended packages are installed alongside the ones you asked for. "+
					"Adding --no-install-recommends typically removes tens of megabytes.",
				true, 30<<20))
		}
	})
	return out
}

func (r ruleNoInstallRecommends) Fix(a *Analysis) []Finding {
	var out []Finding
	eachRun(a, func(_ int, ins *Instruction) {
		var (
			changed bool
			args    []string
			cmds    = Commands(ins.Args)
		)
		for i, cmd := range cmds {
			if IsCmd(cmd, "apt-get", "apt") && HasSubcommand(cmd, "install") && !HasFlag(cmd, "--no-install-recommends") {
				cmd = insertAfterVerb(cmd, "--no-install-recommends")
				changed = true
				out = append(out, finding(r, ins.Line,
					"Added --no-install-recommends to `"+JoinCommand(cmds[i])+"`.", true, 30<<20))
			}
			if i > 0 {
				args = append(args, "&&")
			}
			args = append(args, cmd...)
		}
		if changed {
			rewrite(ins, args)
		}
	})
	return out
}

// insertAfterVerb places a flag directly after the install verb, which is where
// apt and pip both document it and where a reader expects to find it.
func insertAfterVerb(cmd []string, flag string) []string {
	for i := 1; i < len(cmd); i++ {
		if strings.HasPrefix(cmd[i], "-") {
			continue
		}
		out := make([]string, 0, len(cmd)+1)
		out = append(out, cmd[:i+1]...)
		out = append(out, flag)
		out = append(out, cmd[i+1:]...)
		return out
	}
	return append(cmd, flag)
}

// -----------------------------------------------------------------------------
// DT002 apt lists left in the layer
// -----------------------------------------------------------------------------

type ruleAptListsNotCleaned struct{}

func (ruleAptListsNotCleaned) ID() string             { return "DT002" }
func (ruleAptListsNotCleaned) Title() string          { return "apt package lists shipped in the image" }
func (ruleAptListsNotCleaned) Severity() Severity     { return SeverityMedium }
func (ruleAptListsNotCleaned) Confidence() Confidence { return ConfidenceSafe }

func (ruleAptListsNotCleaned) usesApt(ins *Instruction) bool {
	for _, cmd := range Commands(ins.Args) {
		if IsCmd(cmd, "apt-get", "apt") && HasSubcommand(cmd, "update", "install") {
			return true
		}
	}
	return false
}

func (ruleAptListsNotCleaned) cleans(ins *Instruction) bool {
	return strings.Contains(JoinCommand(ins.Args), "/var/lib/apt/lists")
}

func (r ruleAptListsNotCleaned) Check(a *Analysis) []Finding {
	var out []Finding
	eachRun(a, func(_ int, ins *Instruction) {
		if r.usesApt(ins) && !r.cleans(ins) {
			out = append(out, finding(r, ins.Line,
				"apt writes its package index to /var/lib/apt/lists and nothing removes it, so "+
					"it is baked into the layer. Cleaning has to happen in the same RUN: a later "+
					"RUN cannot shrink an earlier layer.", true, 40<<20))
		}
	})
	return out
}

func (r ruleAptListsNotCleaned) Fix(a *Analysis) []Finding {
	var out []Finding
	eachRun(a, func(_ int, ins *Instruction) {
		if !r.usesApt(ins) || r.cleans(ins) {
			return
		}
		args := append(append([]string{}, ins.Args...), "&&", "rm", "-rf", "/var/lib/apt/lists/*")
		rewrite(ins, args)
		out = append(out, finding(r, ins.Line,
			"Appended `rm -rf /var/lib/apt/lists/*` to the same RUN.", true, 40<<20))
	})
	return out
}

// -----------------------------------------------------------------------------
// DT003 apt-get update in its own layer
// -----------------------------------------------------------------------------

type ruleSplitAptUpdate struct{}

func (ruleSplitAptUpdate) ID() string             { return "DT003" }
func (ruleSplitAptUpdate) Title() string          { return "apt-get update runs in its own layer" }
func (ruleSplitAptUpdate) Severity() Severity     { return SeverityHigh }
func (ruleSplitAptUpdate) Confidence() Confidence { return ConfidenceLikely }

func (r ruleSplitAptUpdate) Check(a *Analysis) []Finding {
	var out []Finding
	eachRun(a, func(_ int, ins *Instruction) {
		var update, install bool
		for _, cmd := range Commands(ins.Args) {
			if !IsCmd(cmd, "apt-get", "apt") {
				continue
			}
			if HasSubcommand(cmd, "update") {
				update = true
			}
			if HasSubcommand(cmd, "install") {
				install = true
			}
		}
		if update && !install {
			out = append(out, finding(r, ins.Line,
				"`apt-get update` is cached as its own layer, so a later `apt-get install` can "+
					"reuse a stale index and install versions that no longer exist. Put both in "+
					"one RUN.", false, 0))
		}
	})
	return out
}

// -----------------------------------------------------------------------------
// DT004 pip install without --no-cache-dir
// -----------------------------------------------------------------------------

type rulePipNoCacheDir struct{}

func (rulePipNoCacheDir) ID() string             { return "DT004" }
func (rulePipNoCacheDir) Title() string          { return "pip wheel cache shipped in the image" }
func (rulePipNoCacheDir) Severity() Severity     { return SeverityMedium }
func (rulePipNoCacheDir) Confidence() Confidence { return ConfidenceSafe }

func (rulePipNoCacheDir) needsFix(cmd []string) bool {
	return IsCmd(cmd, "pip", "pip3") && HasSubcommand(cmd, "install") && !HasFlag(cmd, "--no-cache-dir")
}

func (r rulePipNoCacheDir) Check(a *Analysis) []Finding {
	var out []Finding
	eachRun(a, func(_ int, ins *Instruction) {
		// PIP_NO_CACHE_DIR in the environment does the same job.
		if envSet(a, "PIP_NO_CACHE_DIR") {
			return
		}
		for _, cmd := range Commands(ins.Args) {
			if r.needsFix(cmd) {
				out = append(out, finding(r, ins.Line,
					"pip keeps downloaded wheels in ~/.cache/pip, which ends up in the layer. "+
						"--no-cache-dir skips it.", true, 50<<20))
			}
		}
	})
	return out
}

func (r rulePipNoCacheDir) Fix(a *Analysis) []Finding {
	var out []Finding
	if envSet(a, "PIP_NO_CACHE_DIR") {
		return nil
	}
	eachRun(a, func(_ int, ins *Instruction) {
		var (
			changed bool
			args    []string
		)
		for i, cmd := range Commands(ins.Args) {
			if r.needsFix(cmd) {
				cmd = insertAfterVerb(cmd, "--no-cache-dir")
				changed = true
				out = append(out, finding(r, ins.Line, "Added --no-cache-dir to pip install.", true, 50<<20))
			}
			if i > 0 {
				args = append(args, "&&")
			}
			args = append(args, cmd...)
		}
		if changed {
			rewrite(ins, args)
		}
	})
	return out
}

// envSet reports whether any stage sets the named environment variable to a
// truthy value.
func envSet(a *Analysis, name string) bool {
	for si := range a.Stages {
		for _, ins := range a.Stages[si].Instructions {
			if ins.Keyword != "ENV" {
				continue
			}
			for i, w := range ins.Args {
				// Args are folded to NAME=value; the legacy `ENV NAME value`
				// form arrives as two words.
				k, v, ok := strings.Cut(w, "=")
				if !ok {
					if w != name || i+1 >= len(ins.Args) {
						continue
					}
					k, v = w, ins.Args[i+1]
				}
				if k == name && v != "" && v != "0" && v != "false" {
					return true
				}
			}
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// DT005 apk add without --no-cache
// -----------------------------------------------------------------------------

type ruleApkNoCache struct{}

func (ruleApkNoCache) ID() string             { return "DT005" }
func (ruleApkNoCache) Title() string          { return "apk index shipped in the image" }
func (ruleApkNoCache) Severity() Severity     { return SeverityMedium }
func (ruleApkNoCache) Confidence() Confidence { return ConfidenceSafe }

func (ruleApkNoCache) needsFix(cmd []string) bool {
	return IsCmd(cmd, "apk") && HasSubcommand(cmd, "add") && !HasFlag(cmd, "--no-cache")
}

func (r ruleApkNoCache) Check(a *Analysis) []Finding {
	var out []Finding
	eachRun(a, func(_ int, ins *Instruction) {
		for _, cmd := range Commands(ins.Args) {
			if r.needsFix(cmd) {
				out = append(out, finding(r, ins.Line,
					"`apk add --no-cache` skips the package index entirely, which is smaller "+
						"and simpler than adding a matching `rm -rf /var/cache/apk/*`.", true, 5<<20))
			}
		}
	})
	return out
}

func (r ruleApkNoCache) Fix(a *Analysis) []Finding {
	var out []Finding
	eachRun(a, func(_ int, ins *Instruction) {
		var (
			changed bool
			args    []string
		)
		for i, cmd := range Commands(ins.Args) {
			if r.needsFix(cmd) {
				cmd = insertAfterVerb(cmd, "--no-cache")
				changed = true
				out = append(out, finding(r, ins.Line, "Added --no-cache to apk add.", true, 5<<20))
			}
			if i > 0 {
				args = append(args, "&&")
			}
			args = append(args, cmd...)
		}
		if changed {
			rewrite(ins, args)
		}
	})
	return out
}

// -----------------------------------------------------------------------------
// DT006 npm install ships dev dependencies and its cache
// -----------------------------------------------------------------------------

type ruleNpmCache struct{}

func (ruleNpmCache) ID() string             { return "DT006" }
func (ruleNpmCache) Title() string          { return "npm ships dev dependencies and its cache" }
func (ruleNpmCache) Severity() Severity     { return SeverityMedium }
func (ruleNpmCache) Confidence() Confidence { return ConfidenceLikely }

func (ruleNpmCache) isInstall(cmd []string) bool {
	return IsCmd(cmd, "npm") && HasSubcommand(cmd, "install", "i", "ci")
}

func (r ruleNpmCache) Check(a *Analysis) []Finding {
	var out []Finding
	eachRun(a, func(stage int, ins *Instruction) {
		joined := JoinCommand(ins.Args)
		for _, cmd := range Commands(ins.Args) {
			if !r.isInstall(cmd) {
				continue
			}
			if !strings.Contains(joined, "cache clean") {
				out = append(out, finding(r, ins.Line,
					"npm leaves its download cache in ~/.npm. `npm cache clean --force` in the "+
						"same RUN removes it.", true, 60<<20))
			}
			// Installing dev dependencies is fine if they are pruned again
			// before anything is copied out of the stage, which is what the
			// synthesizer arranges.
			if !HasFlag(cmd, "--omit", "--production", "--only") && !prunesDevDeps(a, stage) {
				out = append(out, finding(r, ins.Line,
					"Dev dependencies are installed into the shipped image. `npm ci --omit=dev` "+
						"installs only what runtime needs, from the lockfile.", false, 150<<20))
			}
		}
	})
	return out
}

// prunesDevDeps reports whether a stage drops its dev dependencies before it
// ends.
func prunesDevDeps(a *Analysis, stage int) bool {
	if stage >= len(a.Stages) {
		return false
	}
	for _, ins := range a.Stages[stage].Instructions {
		if ins.Keyword != "RUN" || ins.Exec {
			continue
		}
		for _, cmd := range Commands(ins.Args) {
			if IsCmd(cmd, "npm", "yarn", "pnpm") && HasSubcommand(cmd, "prune") &&
				HasFlag(cmd, "--omit", "--production") {
				return true
			}
		}
	}
	return false
}

func (r ruleNpmCache) Fix(a *Analysis) []Finding {
	var out []Finding
	eachRun(a, func(_ int, ins *Instruction) {
		joined := JoinCommand(ins.Args)
		if strings.Contains(joined, "cache clean") {
			return
		}
		var install bool
		for _, cmd := range Commands(ins.Args) {
			if r.isInstall(cmd) {
				install = true
			}
		}
		if !install {
			return
		}
		rewrite(ins, append(append([]string{}, ins.Args...), "&&", "npm", "cache", "clean", "--force"))
		out = append(out, finding(r, ins.Line,
			"Appended `npm cache clean --force` to the same RUN.", true, 60<<20))
	})
	return out
}

// -----------------------------------------------------------------------------
// DT007 COPY . . before the dependency manifest
// -----------------------------------------------------------------------------

type ruleCopyBeforeManifest struct{}

func (ruleCopyBeforeManifest) ID() string { return "DT007" }
func (ruleCopyBeforeManifest) Title() string {
	return "source copied before dependencies are installed"
}
func (ruleCopyBeforeManifest) Severity() Severity { return SeverityLow }
func (ruleCopyBeforeManifest) Confidence() Confidence {
	return ConfidenceLikely
}

var manifestFiles = []string{
	"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
	"requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock",
	"go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "pom.xml", "build.gradle", "Gemfile.lock",
}

func (r ruleCopyBeforeManifest) Check(a *Analysis) []Finding {
	var out []Finding
	for si := range a.Stages {
		var (
			copiedAll int
			installed bool
		)
		for _, ins := range a.Stages[si].Instructions {
			// Copying the manifest, installing, then copying the source is
			// the pattern this rule asks for. Having already seen the install
			// means the author is doing it right.
			if ins.Keyword == "RUN" && !ins.Exec && copiedAll == 0 {
				for _, cmd := range Commands(ins.Args) {
					if isDependencyInstall(cmd) {
						installed = true
					}
				}
			}
			if ins.Keyword == "COPY" && copiedAll == 0 && !installed &&
				len(ins.Args) >= 2 && ins.Args[0] == "." {
				copiedAll = ins.Line
				continue
			}
			if copiedAll == 0 || ins.Keyword != "RUN" {
				continue
			}
			for _, cmd := range Commands(ins.Args) {
				if isDependencyInstall(cmd) {
					out = append(out, finding(r, copiedAll,
						fmt.Sprintf("`COPY . .` at line %d invalidates the dependency cache on every "+
							"source change, so the install at line %d re-runs every build. Copy the "+
							"manifest, install, then copy the source.", copiedAll, ins.Line), false, 0))
					copiedAll = 0
					break
				}
			}
		}
	}
	return out
}

// isDependencyInstall reports whether a command fetches or installs project
// dependencies, as opposed to compiling the project itself.
func isDependencyInstall(cmd []string) bool {
	switch {
	case IsCmd(cmd, "npm", "yarn", "pnpm", "bun"):
		return HasSubcommand(cmd, "install", "i", "ci", "add")
	case IsCmd(cmd, "pip", "pip3", "uv"):
		return HasSubcommand(cmd, "install", "sync")
	case IsCmd(cmd, "poetry", "bundle", "composer"):
		return HasSubcommand(cmd, "install")
	case IsCmd(cmd, "go"):
		return HasSubcommand(cmd, "mod", "download", "get")
	case IsCmd(cmd, "cargo"):
		return HasSubcommand(cmd, "fetch", "vendor")
	case IsCmd(cmd, "mvn", "gradle"):
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// DT008 ADD with a remote URL
// -----------------------------------------------------------------------------

type ruleAddRemoteURL struct{}

func (ruleAddRemoteURL) ID() string             { return "DT008" }
func (ruleAddRemoteURL) Title() string          { return "ADD fetches a remote URL" }
func (ruleAddRemoteURL) Severity() Severity     { return SeverityMedium }
func (ruleAddRemoteURL) Confidence() Confidence { return ConfidenceLikely }

func (r ruleAddRemoteURL) Check(a *Analysis) []Finding {
	var out []Finding
	for si := range a.Stages {
		for _, ins := range a.Stages[si].Instructions {
			if ins.Keyword != "ADD" || len(ins.Args) == 0 {
				continue
			}
			src := ins.Args[0]
			if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
				out = append(out, finding(r, ins.Line,
					"ADD downloads "+src+" into its own layer with no checksum and no way to "+
						"clean up afterwards. Fetch it in a RUN that also verifies and removes it.",
					false, 0))
			}
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// DT009 floating base image tag
// -----------------------------------------------------------------------------

type ruleFloatingBaseTag struct{}

func (ruleFloatingBaseTag) ID() string             { return "DT009" }
func (ruleFloatingBaseTag) Title() string          { return "base image tag is not pinned" }
func (ruleFloatingBaseTag) Severity() Severity     { return SeverityLow }
func (ruleFloatingBaseTag) Confidence() Confidence { return ConfidenceLikely }

func (r ruleFloatingBaseTag) Check(a *Analysis) []Finding {
	var out []Finding
	for si := range a.Stages {
		base := a.Stages[si].BaseImage
		if base == "" || base == "scratch" || strings.HasPrefix(base, "$") {
			continue
		}
		// A digest or an explicit tag other than latest is fine.
		if strings.Contains(base, "@sha256:") {
			continue
		}
		name, tag := splitTag(base)
		if tag != "" && tag != "latest" {
			continue
		}
		line := 0
		if len(a.Stages[si].Instructions) > 0 {
			line = a.Stages[si].Instructions[0].Line
		}
		what := "carries no tag, so it resolves to :latest"
		if tag == "latest" {
			what = "is pinned to :latest"
		}
		out = append(out, finding(r, line,
			"`"+name+"` "+what+". The image you build today and the one CI builds next month "+
				"can differ without a single line changing.", false, 0))
	}
	return out
}

// splitTag separates an image reference into its name and tag, leaving a
// registry's port number alone.
func splitTag(ref string) (name, tag string) {
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return ref, ""
	}
	if strings.Contains(ref[i+1:], "/") {
		return ref, "" // the colon belonged to a registry host:port
	}
	return ref[:i], ref[i+1:]
}

// -----------------------------------------------------------------------------
// DT010 the image runs as root
// -----------------------------------------------------------------------------

type ruleRunsAsRoot struct{}

func (ruleRunsAsRoot) ID() string             { return "DT010" }
func (ruleRunsAsRoot) Title() string          { return "container runs as root" }
func (ruleRunsAsRoot) Severity() Severity     { return SeverityHigh }
func (ruleRunsAsRoot) Confidence() Confidence { return ConfidenceLikely }

func (r ruleRunsAsRoot) Check(a *Analysis) []Finding {
	final := a.FinalStage()
	if final == nil {
		return nil
	}
	line := 0
	for _, ins := range final.Instructions {
		if ins.Keyword == "USER" && len(ins.Args) > 0 && ins.Args[0] != "root" && ins.Args[0] != "0" {
			return nil
		}
		if ins.Keyword == "ENTRYPOINT" || ins.Keyword == "CMD" {
			line = ins.Line
		}
	}
	return []Finding{finding(r, line,
		"The final stage never drops privileges, so the process runs as uid 0. A container "+
			"breakout, or any bind mount, then has root's reach.", true, 0)}
}

// -----------------------------------------------------------------------------
// DT011 shell and network tools in the final stage
// -----------------------------------------------------------------------------

type ruleDevToolsInFinalStage struct{}

func (ruleDevToolsInFinalStage) ID() string         { return "DT011" }
func (ruleDevToolsInFinalStage) Title() string      { return "build and debug tools shipped to production" }
func (ruleDevToolsInFinalStage) Severity() Severity { return SeverityHigh }
func (ruleDevToolsInFinalStage) Confidence() Confidence {
	return ConfidenceLikely
}

// devTools are packages that give an attacker who lands a shell somewhere to
// stand: a way to fetch a payload, compile it, or move laterally.
var devTools = map[string]string{
	"curl": "downloads a payload", "wget": "downloads a payload",
	"netcat": "opens a reverse shell", "netcat-openbsd": "opens a reverse shell",
	"netcat-traditional": "opens a reverse shell", "nc": "opens a reverse shell",
	"socat": "opens a reverse shell", "openssh-client": "moves laterally",
	"git": "clones a payload", "vim": "edits files in place", "nano": "edits files in place",
	"build-essential": "compiles a payload", "gcc": "compiles a payload",
	"g++": "compiles a payload", "make": "compiles a payload", "cmake": "compiles a payload",
	"sudo": "escalates privileges", "strace": "inspects other processes",
	"python3": "runs arbitrary scripts", "perl": "runs arbitrary scripts",
}

func (r ruleDevToolsInFinalStage) Check(a *Analysis) []Finding {
	final := a.FinalStage()
	if final == nil {
		return nil
	}
	var out []Finding
	for _, ins := range final.Instructions {
		if ins.Keyword != "RUN" || ins.Exec {
			continue
		}
		for _, cmd := range Commands(ins.Args) {
			if !IsCmd(cmd, "apt-get", "apt", "apk", "yum", "dnf") || !HasSubcommand(cmd, "install", "add") {
				continue
			}
			for _, pkg := range InstalledPackages(cmd) {
				why, bad := devTools[pkg]
				if !bad {
					continue
				}
				out = append(out, finding(r, ins.Line,
					"`"+pkg+"` stays in the shipped image, where it "+why+". Install it in a "+
						"builder stage instead, or drop it.", false, 0))
			}
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// DT012 consecutive RUN instructions
// -----------------------------------------------------------------------------

type ruleMergeableRuns struct{}

func (ruleMergeableRuns) ID() string             { return "DT012" }
func (ruleMergeableRuns) Title() string          { return "consecutive RUN instructions each add a layer" }
func (ruleMergeableRuns) Severity() Severity     { return SeverityLow }
func (ruleMergeableRuns) Confidence() Confidence { return ConfidenceAggressive }

func (r ruleMergeableRuns) Check(a *Analysis) []Finding {
	var out []Finding
	for si := range a.Stages {
		ins := a.Stages[si].Instructions
		run := 0
		for i := 0; i <= len(ins); i++ {
			if i < len(ins) && ins[i].Keyword == "RUN" {
				run++
				continue
			}
			if run > 1 {
				out = append(out, finding(r, ins[i-run].Line,
					fmt.Sprintf("%d RUN instructions in a row create %d layers. Merging them with "+
						"`&&` lets one cleanup step reach everything they wrote.", run, run), false, 0))
			}
			run = 0
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// DT013 secret-shaped build arguments
// -----------------------------------------------------------------------------

type ruleSecretInEnv struct{}

func (ruleSecretInEnv) ID() string             { return "DT013" }
func (ruleSecretInEnv) Title() string          { return "credential-shaped value baked into the image" }
func (ruleSecretInEnv) Severity() Severity     { return SeverityCritical }
func (ruleSecretInEnv) Confidence() Confidence { return ConfidenceLikely }

var secretName = regexp.MustCompile(`(?i)(pass(wo?rd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)`)

func (r ruleSecretInEnv) Check(a *Analysis) []Finding {
	var out []Finding
	check := func(ins Instruction) {
		for _, w := range ins.Args {
			name, value, hasValue := strings.Cut(w, "=")
			if !hasValue {
				name, value = w, ""
			}
			if !secretName.MatchString(name) {
				continue
			}
			// A bare `ARG TOKEN` with no value is the correct pattern.
			if ins.Keyword == "ARG" && value == "" {
				continue
			}
			out = append(out, finding(r, ins.Line,
				"`"+name+"` is set at build time and every layer keeps it, so `docker history` "+
					"reveals it to anyone who can pull the image. Use a BuildKit secret mount.",
				false, 0))
			return
		}
	}
	for _, ins := range a.GlobalARGs {
		check(ins)
	}
	for si := range a.Stages {
		for _, ins := range a.Stages[si].Instructions {
			if ins.Keyword == "ENV" || ins.Keyword == "ARG" {
				check(ins)
			}
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// DT014 missing .dockerignore
// -----------------------------------------------------------------------------

type ruleMissingDockerignore struct{}

func (ruleMissingDockerignore) ID() string             { return "DT014" }
func (ruleMissingDockerignore) Title() string          { return "no .dockerignore beside the Dockerfile" }
func (ruleMissingDockerignore) Severity() Severity     { return SeverityLow }
func (ruleMissingDockerignore) Confidence() Confidence { return ConfidenceLikely }

func (r ruleMissingDockerignore) Check(a *Analysis) []Finding {
	if a.Path == "" || a.Path == "-" {
		return nil
	}
	// Only worth saying when something actually copies the context in.
	var copies bool
	for si := range a.Stages {
		for _, ins := range a.Stages[si].Instructions {
			if (ins.Keyword == "COPY" || ins.Keyword == "ADD") && len(ins.Args) >= 2 &&
				flagValue(ins.Flags, "from") == "" {
				copies = true
			}
		}
	}
	if !copies {
		return nil
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(a.Path), ".dockerignore")); err == nil {
		return nil
	}
	return []Finding{finding(r, 0,
		"Without a .dockerignore the whole directory is uploaded as build context and any "+
			"`COPY . .` bakes in .git, node_modules and local build output.", false, 0)}
}

// -----------------------------------------------------------------------------
// DT015 RUN cd instead of WORKDIR
// -----------------------------------------------------------------------------

type ruleRunCd struct{}

func (ruleRunCd) ID() string             { return "DT015" }
func (ruleRunCd) Title() string          { return "RUN cd instead of WORKDIR" }
func (ruleRunCd) Severity() Severity     { return SeverityInfo }
func (ruleRunCd) Confidence() Confidence { return ConfidenceLikely }

func (r ruleRunCd) Check(a *Analysis) []Finding {
	var out []Finding
	eachRun(a, func(_ int, ins *Instruction) {
		cmds := Commands(ins.Args)
		if len(cmds) > 0 && IsCmd(cmds[0], "cd") {
			out = append(out, finding(r, ins.Line,
				"`cd` only lasts for this RUN. WORKDIR sets the directory for every instruction "+
					"that follows, and for the running container.", false, 0))
		}
	})
	return out
}

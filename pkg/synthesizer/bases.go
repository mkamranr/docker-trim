package synthesizer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/mkamranr/dtrim/pkg/analyzer"
)

// Base is the minimal runtime base image family the trimmed final stage lands
// on. It is the value of the --base flag.
type Base string

// The runtime bases dtrim can target.
const (
	// BaseDistroless is a Google distroless image: no shell, no package
	// manager, and the smallest option that still carries a libc.
	BaseDistroless Base = "distroless"
	// BaseAlpine is Alpine Linux, which uses musl rather than glibc.
	BaseAlpine Base = "alpine"
	// BaseScratch is the empty image, which suits a static binary and nothing else.
	BaseScratch Base = "scratch"
)

// ParseBase validates the --base value.
func ParseBase(s string) (Base, error) {
	switch Base(s) {
	case BaseDistroless, BaseAlpine, BaseScratch:
		return Base(s), nil
	}
	return "", fmt.Errorf("unknown base %q: want distroless, alpine or scratch", s)
}

// Ecosystem is the language toolchain a Dockerfile builds with. It decides
// which runtime base can host the result and what has to be copied into it.
type Ecosystem string

// Artifact is one path copied out of the builder stage.
type Artifact struct{ From, To string }

// The toolchains dtrim can recognise. EcosystemUnknown means it could not tell
// what the build produces, and so declines to restructure it.
const (
	EcosystemGo      Ecosystem = "go"
	EcosystemNode    Ecosystem = "node"
	EcosystemPython  Ecosystem = "python"
	EcosystemRust    Ecosystem = "rust"
	EcosystemJava    Ecosystem = "java"
	EcosystemUnknown Ecosystem = "unknown"
)

// Plan is the mapping decision for one Dockerfile: which runtime base to land
// on and what has to travel there from the builder.
//
// Supported is false when dtrim could not work out what the build produces. It
// then declines to invent a builder split and says why, because emitting a
// confident multi-stage Dockerfile that does not run is worse than emitting
// nothing.
type Plan struct {
	Ecosystem Ecosystem
	// Builder is the base image of the builder stage, normally the original.
	Builder string
	// Runtime is the minimal base the final stage lands on.
	Runtime string
	// Artifacts travel from the builder into the runtime stage. From and To
	// are normally identical: keeping the path unchanged is what lets
	// ENTRYPOINT, CMD, WORKDIR and ENV carry over untouched instead of being
	// rewritten and guessed at.
	Artifacts []Artifact
	// RuntimeEnv are extra `NAME=value` settings the runtime stage needs,
	// such as the PYTHONPATH that points at the copied dependency tree.
	RuntimeEnv []string
	// PipTarget, when set, rewrites every `pip install` in the builder to
	// install into that directory instead of the system one.
	PipTarget string
	// User is the identity the final stage drops to.
	User string
	// PrepareBuilder are commands appended to the builder stage, such as
	// pruning dev dependencies, before anything is copied out.
	PrepareBuilder []string
	// ReplaceCommand says the runtime base supplies its own entrypoint, so the
	// original ENTRYPOINT and CMD must be dropped rather than carried over.
	// Entrypoint and Cmd below then describe the whole command; either may be
	// empty, meaning "inherit that half from the base image".
	ReplaceCommand bool
	Entrypoint     []string
	Cmd            []string
	// Supported reports whether a multi-stage rewrite is safe to attempt.
	Supported bool
	// Reason explains an unsupported plan, or a base dtrim declined to use.
	Reason string
	// Warnings are things the author has to know about the rewrite.
	Warnings []string
}

// alpineTag and debianDistroless pin the runtime images dtrim emits. They are
// deliberately explicit: a tool that tells you to stop using :latest cannot
// itself emit a floating tag.
const (
	alpineTag        = "alpine:3.21"
	distrolessStatic = "gcr.io/distroless/static-debian12:nonroot"
	distrolessCC     = "gcr.io/distroless/cc-debian12:nonroot"
)

// DetectEcosystem works out what the final stage builds with, from its base
// image and the commands it runs.
func DetectEcosystem(a *analyzer.Analysis) Ecosystem {
	stage := a.FinalStage()
	if stage == nil {
		return EcosystemUnknown
	}
	if eco := ecosystemOf(stage); eco != EcosystemUnknown {
		return eco
	}
	// A multi-stage file builds in an earlier stage and ships from a minimal
	// one, so the final stage alone says nothing. Fall back to the stage that
	// does the work, which is what a reader would call the project's language.
	for i := len(a.Stages) - 2; i >= 0; i-- {
		if eco := ecosystemOf(&a.Stages[i]); eco != EcosystemUnknown {
			return eco
		}
	}
	return EcosystemUnknown
}

// ecosystemOf identifies a single stage.
func ecosystemOf(stage *analyzer.DockerfileAST) Ecosystem {
	base := strings.ToLower(stage.BaseImage)

	// The build command is the stronger signal: `FROM debian` + `go build` is
	// a Go project, whatever the base image is called.
	for _, ins := range stage.Instructions {
		if ins.Keyword != "RUN" || ins.Exec {
			continue
		}
		// Match on the program word, never on a substring: "cargo build"
		// contains "go build", which would make every Rust project a Go one.
		for _, cmd := range analyzer.Commands(ins.Args) {
			switch {
			case analyzer.IsCmd(cmd, "go") && analyzer.HasSubcommand(cmd, "build", "install"):
				return EcosystemGo
			case analyzer.IsCmd(cmd, "cargo"):
				return EcosystemRust
			case analyzer.IsCmd(cmd, "mvn", "gradle", "./gradlew", "gradlew"):
				return EcosystemJava
			case analyzer.IsCmd(cmd, "npm", "yarn", "pnpm", "bun", "bunx", "npx"):
				return EcosystemNode
			case analyzer.IsCmd(cmd, "pip", "pip3", "poetry", "uv"):
				return EcosystemPython
			}
		}
	}

	switch {
	case strings.Contains(base, "golang"):
		return EcosystemGo
	case strings.Contains(base, "rust"):
		return EcosystemRust
	case strings.Contains(base, "node"), strings.Contains(base, "bun"):
		return EcosystemNode
	case strings.Contains(base, "python"):
		return EcosystemPython
	case strings.Contains(base, "maven"), strings.Contains(base, "gradle"),
		strings.Contains(base, "jdk"), strings.Contains(base, "temurin"), strings.Contains(base, "openjdk"):
		return EcosystemJava
	}
	return EcosystemUnknown
}

// buildPlanEcosystem is what restructuring keys off: only the final stage
// matters there, because that is the stage being split.
func buildPlanEcosystem(a *analyzer.Analysis) Ecosystem {
	if stage := a.FinalStage(); stage != nil {
		return ecosystemOf(stage)
	}
	return EcosystemUnknown
}

var (
	goOutputFlag = regexp.MustCompile(`^-o$`)
	minorVersion = regexp.MustCompile(`(\d+)(?:\.(\d+))?`)
)

// BuildPlan decides how to split a single-stage Dockerfile.
func BuildPlan(a *analyzer.Analysis, base Base) Plan {
	stage := a.FinalStage()
	eco := buildPlanEcosystem(a)
	p := Plan{Ecosystem: eco, Builder: stage.BaseImage, User: "nonroot:nonroot"}

	if eco == EcosystemUnknown {
		p.Reason = "no recognisable build step, so dtrim cannot tell what the runtime stage " +
			"would need to copy. Applying cleanups to the single stage instead."
		return p
	}

	work := workdir(stage)
	switch eco {
	case EcosystemGo:
		planGo(&p, stage, base)
	case EcosystemRust:
		planRust(&p, stage, base, work)
	case EcosystemNode:
		planNode(&p, stage, base, work)
	case EcosystemPython:
		planPython(&p, stage, base, work)
	case EcosystemJava:
		planJava(&p, stage, base, work)
	}

	return p
}

func planGo(p *Plan, stage *analyzer.DockerfileAST, base Base) {
	out := goOutputPath(stage)
	if out == "" {
		p.Reason = "the `go build` command has no -o flag, so dtrim cannot tell where the " +
			"binary lands. Add `-o /path/to/binary` and run dtrim again."
		return
	}
	p.Artifacts = []Artifact{{From: out, To: out}}
	p.Supported = true

	switch base {
	case BaseScratch:
		p.Runtime = "scratch"
		// scratch has no trust store, so any outbound TLS call fails with an
		// unhelpful x509 error unless the bundle comes along.
		p.Artifacts = append(p.Artifacts, Artifact{
			From: "/etc/ssl/certs/ca-certificates.crt",
			To:   "/etc/ssl/certs/ca-certificates.crt"})
		p.User = "10001:10001"
		p.Warnings = append(p.Warnings,
			"scratch has no /etc/passwd, so USER 10001:10001 uses a numeric id with no name. "+
				"It also has no shell, so `docker exec` into this container will not work.")
	case BaseAlpine:
		p.Runtime = alpineTag
		p.User = "10001:10001"
	default:
		p.Runtime = distrolessStatic
	}

	// A static binary is the one thing that runs on all three of these. Without
	// it, a cgo build links against the builder's glibc and then finds no libc
	// at all on distroless/static or scratch, and the wrong one on alpine,
	// which is musl. So this is set for every target, not just the libc-free
	// ones.
	p.PrepareBuilder = append(p.PrepareBuilder, "ENV CGO_ENABLED=0")
	p.Warnings = append(p.Warnings,
		"CGO_ENABLED=0 was set in the builder so the binary is static and depends on no libc. "+
			"If the project genuinely needs cgo, build on an image matching the runtime's libc "+
			"and remove that line.")
}

func planRust(p *Plan, stage *analyzer.DockerfileAST, base Base, work string) {
	out := entrypointPath(stage)
	if out == "" {
		p.Reason = "dtrim could not find the compiled binary: ENTRYPOINT or CMD has to name " +
			"it by absolute path for the runtime stage to copy it."
		return
	}
	p.Artifacts = []Artifact{{From: out, To: out}}
	p.Supported = true
	_ = work

	switch base {
	case BaseScratch:
		p.Runtime = "scratch"
		p.User = "10001:10001"
		p.Warnings = append(p.Warnings,
			"scratch only works for a fully static binary. Build for "+
				"x86_64-unknown-linux-musl, or use --base distroless.")
	case BaseAlpine:
		if !buildsMuslTarget(stage) {
			p.Supported = false
			p.Reason = "alpine is musl, but this build produces a glibc binary, which will not " +
				"run there. Add `--target x86_64-unknown-linux-musl` to the cargo build and run " +
				"dtrim again, or use --base distroless."
			return
		}
		p.Runtime = alpineTag
		p.User = "10001:10001"
	default:
		// cc carries libc and libstdc++, which a default rustc target needs.
		p.Runtime = distrolessCC
	}
}

func planNode(p *Plan, stage *analyzer.DockerfileAST, base Base, work string) {
	if work == "" {
		p.Reason = "no WORKDIR, so dtrim cannot tell which directory holds the application."
		return
	}
	p.Artifacts = []Artifact{{From: work, To: work}}
	p.Supported = true
	// Dev dependencies are the bulk of a node_modules tree and none of them run
	// in production. Pruning in the builder is what makes the copy small.
	p.PrepareBuilder = append(p.PrepareBuilder, "RUN npm prune --omit=dev")

	major := majorVersion(stage.BaseImage)
	switch base {
	case BaseScratch:
		p.Supported = false
		p.Reason = "Node needs its interpreter and libc; scratch has neither. " +
			"Use --base distroless or --base alpine."
		return
	case BaseAlpine:
		if major == "" {
			p.Supported = false
			p.Reason = "cannot read the Node major version from " + stage.BaseImage +
				", so dtrim cannot pick a matching alpine runtime."
			return
		}
		p.Runtime = "node:" + major + "-alpine"
		// Native modules built by node-gyp link against the builder's libc,
		// so the builder moves to alpine too.
		p.Builder = "node:" + major + "-alpine"
		p.User = "node"
	default:
		if major == "" {
			p.Supported = false
			p.Reason = "cannot read the Node major version from " + stage.BaseImage +
				", so dtrim cannot pick a matching distroless runtime."
			return
		}
		p.Runtime = fmt.Sprintf("gcr.io/distroless/nodejs%s-debian12:nonroot", major)
		// Verified against the published config: the entrypoint is already
		// /nodejs/bin/node, so a CMD starting with `node` would run the
		// interpreter twice.
		p.ReplaceCommand = true
		p.Entrypoint, p.Cmd = stripInterpreter(stage, "node")
	}
}

func planPython(p *Plan, stage *analyzer.DockerfileAST, base Base, work string) {
	if work == "" {
		p.Reason = "no WORKDIR, so dtrim cannot tell which directory holds the application."
		return
	}
	// `pip install --target` writes a flat tree with no version-specific
	// subdirectory, unlike --prefix, whose lib/pythonX.Y/... layout differs
	// between Debian and upstream CPython.
	p.PipTarget = "/install"
	// Append to any PYTHONPATH the file already set rather than replacing it:
	// an app that puts its own package directory on the path stops importing
	// itself the moment that value is overwritten.
	pythonPath := "/install"
	if existing := envValue(stage, "PYTHONPATH"); existing != "" {
		pythonPath += ":" + existing
	}
	p.RuntimeEnv = []string{"PYTHONPATH=" + pythonPath, "PATH=/install/bin:$PATH"}
	p.Artifacts = []Artifact{{From: "/install", To: "/install"}, {From: work, To: work}}
	p.Supported = true

	minor := minorOf(stage.BaseImage)
	switch base {
	case BaseScratch:
		p.Supported = false
		p.Reason = "CPython needs libc and its own standard library; scratch has neither. " +
			"Use --base distroless or --base alpine."
		return

	case BaseAlpine:
		if minor == "" {
			p.Supported = false
			p.Reason = "cannot read the Python version from " + stage.BaseImage + "."
			return
		}
		p.Runtime = "python:" + minor + "-alpine"
		// The builder has to move to alpine as well. A wheel compiled against
		// glibc does not load on musl, so building on slim and running on
		// alpine produces an image that starts and then fails to import.
		p.Builder = "python:" + minor + "-alpine"
		p.User = "10001:10001"
		p.Warnings = append(p.Warnings,
			"The builder moved to "+p.Builder+" so wheels are compiled against musl, the libc "+
				"alpine actually uses. Packages without a musl wheel are built from source there, "+
				"which needs build-base and can make the build markedly slower.")

	default:
		// Deliberately NOT gcr.io/distroless/python3-debian12.
		//
		// Dependencies are resolved by the interpreter that runs pip, and
		// environment markers key off the full patch version. Debian's
		// python3.11 (what distroless ships) and the python:3.11-slim image
		// are different patch releases, so a requirement guarded by
		// `python_full_version < "3.11.3"` is skipped on the builder and then
		// required at runtime. redis pulling in async-timeout is the case
		// that found this: the image builds, starts, and dies on import.
		// Compiled wheels have the same problem at the ABI level.
		//
		// Keeping the interpreter identical removes the whole class of
		// failure, and the saving that matters for Python is leaving the
		// build toolchain behind, not changing base image. See
		// docs/heuristics.md.
		p.Runtime = stage.BaseImage
		p.User = "10001:10001"
		p.Warnings = append(p.Warnings,
			"The runtime stage stays on "+stage.BaseImage+" rather than moving to distroless. "+
				"Python resolves dependencies against the exact interpreter build that runs pip, "+
				"so copying an installed tree onto a different CPython patch release can fail at "+
				"import time. The saving here comes from leaving the build toolchain behind.")
	}
}

func planJava(p *Plan, stage *analyzer.DockerfileAST, base Base, work string) {
	jar := jarPath(stage)
	if jar == "" {
		p.Reason = "dtrim could not find the built artifact: ENTRYPOINT or CMD has to name " +
			"the jar by absolute path, as `java -jar /path/app.jar`."
		return
	}
	p.Artifacts = []Artifact{{From: jar, To: jar}}
	p.Supported = true
	_ = work

	major := majorVersion(stage.BaseImage)
	switch base {
	case BaseScratch:
		p.Supported = false
		p.Reason = "a JVM cannot run on scratch. Use --base distroless or --base alpine."
		return
	case BaseAlpine:
		if major == "" {
			p.Supported = false
			p.Reason = "cannot read the JDK major version from " + stage.BaseImage + "."
			return
		}
		p.Runtime = "eclipse-temurin:" + major + "-jre-alpine"
		p.User = "10001:10001"
	default:
		if major == "" {
			p.Supported = false
			p.Reason = "cannot read the JDK major version from " + stage.BaseImage + "."
			return
		}
		p.Runtime = fmt.Sprintf("gcr.io/distroless/java%s-debian12:nonroot", major)
		// Verified against the published config: this image's entrypoint is
		// already ["/usr/bin/java","-jar"], so the jar path alone is the
		// entire command. Leaving `java` or `-jar` in would run java -jar -jar.
		p.ReplaceCommand = true
		p.Cmd = []string{jar}
	}
}

// envValue returns the last value a stage assigns to an environment variable.
func envValue(stage *analyzer.DockerfileAST, name string) string {
	var out string
	for _, ins := range stage.Instructions {
		if ins.Keyword != "ENV" {
			continue
		}
		for _, w := range ins.Args {
			if k, v, ok := strings.Cut(w, "="); ok && k == name {
				out = unquote(v)
			}
		}
	}
	return out
}

// buildsMuslTarget reports whether a cargo build already targets musl, which
// is what alpine needs.
func buildsMuslTarget(stage *analyzer.DockerfileAST) bool {
	for _, ins := range stage.Instructions {
		if ins.Keyword != "RUN" || ins.Exec {
			continue
		}
		if strings.Contains(strings.Join(ins.Args, " "), "musl") {
			return true
		}
	}
	return false
}

// workdir returns the last WORKDIR set in a stage.
func workdir(stage *analyzer.DockerfileAST) string {
	var w string
	for _, ins := range stage.Instructions {
		if ins.Keyword == "WORKDIR" && len(ins.Args) > 0 {
			w = ins.Args[0]
		}
	}
	return w
}

// goOutputPath extracts the absolute path from `go build -o <path>`.
func goOutputPath(stage *analyzer.DockerfileAST) string {
	for _, ins := range stage.Instructions {
		if ins.Keyword != "RUN" || ins.Exec {
			continue
		}
		for i := 0; i+1 < len(ins.Args); i++ {
			if goOutputFlag.MatchString(ins.Args[i]) && strings.HasPrefix(ins.Args[i+1], "/") {
				return ins.Args[i+1]
			}
		}
	}
	return ""
}

// entrypointPath returns the absolute program path an ENTRYPOINT or CMD names.
func entrypointPath(stage *analyzer.DockerfileAST) string {
	for _, ins := range stage.Instructions {
		if ins.Keyword != "ENTRYPOINT" && ins.Keyword != "CMD" {
			continue
		}
		if len(ins.Args) > 0 && strings.HasPrefix(ins.Args[0], "/") {
			return unquote(ins.Args[0])
		}
	}
	return ""
}

// jarPath finds the argument to `java -jar`.
func jarPath(stage *analyzer.DockerfileAST) string {
	for _, ins := range stage.Instructions {
		if ins.Keyword != "ENTRYPOINT" && ins.Keyword != "CMD" {
			continue
		}
		for i := 0; i+1 < len(ins.Args); i++ {
			if unquote(ins.Args[i]) == "-jar" {
				if v := unquote(ins.Args[i+1]); strings.HasPrefix(v, "/") {
					return v
				}
			}
		}
	}
	return ""
}

// stripInterpreter rewrites ENTRYPOINT and CMD for a runtime base that already
// supplies the interpreter as its own entrypoint. `CMD ["node","server.js"]` on
// gcr.io/distroless/nodejs would otherwise run node with node as its argument.
func stripInterpreter(stage *analyzer.DockerfileAST, names ...string) (entrypoint, cmd []string) {
	matches := func(w string) bool {
		w = unquote(w)
		if i := strings.LastIndex(w, "/"); i >= 0 {
			w = w[i+1:]
		}
		for _, n := range names {
			if w == n {
				return true
			}
		}
		return false
	}
	for _, ins := range stage.Instructions {
		switch ins.Keyword {
		case "ENTRYPOINT":
			args := unquoteAll(ins.Args)
			if len(args) > 0 && matches(args[0]) {
				args = args[1:]
			}
			entrypoint = args
		case "CMD":
			args := unquoteAll(ins.Args)
			if len(args) > 0 && matches(args[0]) {
				args = args[1:]
			}
			cmd = args
		}
	}
	return entrypoint, cmd
}

// majorVersion pulls the leading major version out of an image tag,
// e.g. node:18-bookworm -> 18, maven:3.9-eclipse-temurin-21 -> 21 for the JDK.
func majorVersion(ref string) string {
	_, tag := splitImageTag(ref)
	if tag == "" {
		return ""
	}
	// A JDK image names the JDK version last, after the toolchain version.
	if i := strings.LastIndex(tag, "temurin-"); i >= 0 {
		return digits(tag[i+len("temurin-"):])
	}
	if i := strings.LastIndex(tag, "jdk-"); i >= 0 {
		return digits(tag[i+len("jdk-"):])
	}
	return digits(tag)
}

// minorOf returns the major.minor version from an image tag, e.g.
// python:3.12-slim -> 3.12.
func minorOf(ref string) string {
	_, tag := splitImageTag(ref)
	m := minorVersion.FindStringSubmatch(tag)
	if len(m) < 3 || m[2] == "" {
		return ""
	}
	return m[1] + "." + m[2]
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func splitImageTag(ref string) (name, tag string) {
	i := strings.LastIndex(ref, ":")
	if i < 0 || strings.Contains(ref[i+1:], "/") {
		return ref, ""
	}
	return ref[:i], ref[i+1:]
}

func unquote(s string) string {
	return strings.Trim(s, `"'`)
}

func unquoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = unquote(s)
	}
	return out
}

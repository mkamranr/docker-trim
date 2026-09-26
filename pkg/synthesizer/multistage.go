package synthesizer

import (
	"strings"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
)

// builderStageName is the name given to the stage that keeps the toolchain.
const builderStageName = "builder"

// Result is what the synthesizer produced and why.
type Result struct {
	// Analysis is the rewritten file, ready for Render.
	Analysis *analyzer.Analysis
	// Plan records the mapping decision, including the reason a multi-stage
	// rewrite was declined.
	Plan Plan
	// Restructured reports whether a builder stage was actually introduced.
	// False means only in-place cleanups were applied.
	Restructured bool
	// Findings are the rule findings that were fixed, plus what remains.
	Fixed     []analyzer.Finding
	Remaining []analyzer.Finding
	// Pruned are packages dropped from an install command because a trace
	// never saw them used.
	Pruned []string
	// RuntimeGaps are things the trace saw the program use that the chosen
	// runtime base will not provide.
	RuntimeGaps []RuntimeGap
	// Notes are human-readable statements about what happened, shown in the
	// report and written into the file as comments.
	Notes []string
}

// Options control a rewrite.
type Options struct {
	// Base is the minimal runtime the final stage should land on.
	Base Base
	// Aggressiveness gates which rules may repair what they find.
	Aggressiveness analyzer.Confidence
	// Usage is what a runtime trace observed, when one was run. It lets the
	// synthesizer check its own work: a trace knows which binaries the program
	// actually executes, and a minimal runtime that lacks one of them produces
	// an image that builds cleanly and fails in production.
	Usage *analyzer.Usage
	// Trace is the raw manifest behind Usage.
	Trace *analyzer.TraceManifest
	// PruneUnused drops packages the trace never touched from the install
	// commands that name them. It only ever applies to a stage that ships,
	// never to a builder: a trace observes the finished image and says nothing
	// about what compiling it required.
	PruneUnused bool
}

// Optimize rewrites an analyzed Dockerfile.
//
// It refuses to restructure a file that already builds in stages: the author
// has made those decisions, and a tool that silently rearranges them is a tool
// people uninstall. Such a file still gets the safe in-place cleanups.
func Optimize(a *analyzer.Analysis, opts Options) *Result {
	base, aggressiveness := opts.Base, opts.Aggressiveness
	res := &Result{Analysis: a}

	if a.MultiStage() {
		res.Plan = Plan{Ecosystem: DetectEcosystem(a), Supported: false,
			Reason: "the file already builds in multiple stages, so docker-trim left the structure " +
				"alone and applied cleanups only."}
		res.Notes = append(res.Notes, res.Plan.Reason)
		res.Fixed, res.Remaining = analyzer.FixAll(a, aggressiveness)
		// Nothing was restructured, so the packages the final stage installs
		// are the ones that ship. This is where a trace pays off directly.
		res.Pruned = pruneUnused(a, opts)
		return res
	}

	res.Plan = BuildPlan(a, base)
	if !res.Plan.Supported {
		if res.Plan.Reason != "" {
			res.Notes = append(res.Notes, res.Plan.Reason)
		}
		res.Fixed, res.Remaining = analyzer.FixAll(a, aggressiveness)
		res.Pruned = pruneUnused(a, opts)
		return res
	}

	// A runtime base identical to the builder base only pays off if the build
	// installs something on top that the runtime can then leave behind.
	// Otherwise the two stages start from the same bytes and the split is pure
	// churn, so say that instead of writing a file that changes nothing.
	if res.Plan.Runtime == res.Plan.Builder && !installsPackages(a.FinalStage()) {
		res.Plan.Supported = false
		if res.Plan.Reason == "" {
			res.Plan.Reason = "this build already starts from " + res.Plan.Builder +
				" and installs no extra system packages, so a builder stage would copy the " +
				"same bytes into the same base and save nothing."
		} else {
			// The plan already explained why it stepped down to this base;
			// extend that explanation rather than emitting a second note that
			// says most of the same thing.
			old := res.Plan.Reason
			res.Plan.Reason += " Splitting into stages on the same base would save nothing, " +
				"so docker-trim applied cleanups only."
			res.Plan.Warnings = withoutString(res.Plan.Warnings, old)
		}
		res.Notes = append(res.Notes, res.Plan.Reason)
		res.Fixed, res.Remaining = analyzer.FixAll(a, aggressiveness)
		res.Pruned = pruneUnused(a, opts)
		return res
	}

	// Clean up first: the builder stage inherits those fixes, and the runtime
	// stage is built fresh so nothing needs cleaning there.
	res.Fixed, res.Remaining = analyzer.FixAll(a, aggressiveness)

	// A trace knows what the program actually runs. Checking that against what
	// the chosen runtime will contain catches the failure mode this tool could
	// otherwise cause: an image that is dramatically smaller, builds cleanly,
	// and then dies in production because something it shells out to is gone.
	// Kept out of Plan.Warnings deliberately: the reporter gives gaps their own
	// block, and a warning that also appears in the notes reads as two separate
	// problems.
	res.RuntimeGaps = checkRuntimeCoverage(res.Plan, opts.Trace)

	restructure(a, res.Plan)
	res.Restructured = true
	res.Notes = append(res.Notes,
		"Split into a builder stage on "+res.Plan.Builder+" and a runtime stage on "+res.Plan.Runtime+".")
	res.Notes = append(res.Notes, res.Plan.Warnings...)

	// The rules ran against the single-stage file; re-lint the rewritten one so
	// the report describes what the user will actually build.
	res.Remaining = analyzer.Lint(a)
	return res
}

// withoutString drops every occurrence of s from the slice.
func withoutString(in []string, s string) []string {
	out := in[:0:0]
	for _, v := range in {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

// installsPackages reports whether a stage adds operating-system packages that
// a separate runtime stage could then leave behind.
func installsPackages(stage *analyzer.DockerfileAST) bool {
	if stage == nil {
		return false
	}
	for _, ins := range stage.Instructions {
		if ins.Keyword != "RUN" || ins.Exec {
			continue
		}
		for _, cmd := range analyzer.Commands(ins.Args) {
			if analyzer.IsCmd(cmd, "apt-get", "apt", "apk", "yum", "dnf") &&
				analyzer.HasSubcommand(cmd, "install", "add") {
				return true
			}
		}
	}
	return false
}

// restructure turns the single stage into builder plus runtime, in place.
func restructure(a *analyzer.Analysis, p Plan) {
	orig := a.Stages[0]

	builder := orig
	builder.BuildStage = builderStageName
	builder.Instructions = append([]analyzer.Instruction(nil), orig.Instructions...)
	builder.Instructions[0] = fromInstruction(p.Builder, builderStageName, orig.Instructions[0].Lead)

	// Anything that only describes the running container belongs to the
	// runtime stage, not the builder.
	builder.Instructions = dropKeywords(builder.Instructions, "ENTRYPOINT", "CMD", "EXPOSE", "USER", "HEALTHCHECK", "STOPSIGNAL")

	// Preparation steps, such as pruning dev dependencies or forcing a static
	// build, have to be in place before anything is copied out.
	builder.Instructions = applyPrepare(builder.Instructions, p.PrepareBuilder)
	if p.PipTarget != "" {
		builder.Instructions = redirectPip(builder.Instructions, p.PipTarget)
	}

	runtime := analyzer.DockerfileAST{
		BaseImage:    p.Runtime,
		Instructions: buildRuntimeStage(orig, p),
	}

	a.Stages = []analyzer.DockerfileAST{builder, runtime}
}

// buildRuntimeStage assembles the minimal final stage.
//
// Artifacts are copied to the same absolute path they had in the builder, which
// is what lets WORKDIR, ENV, EXPOSE, ENTRYPOINT and CMD carry over unchanged
// instead of being rewritten and guessed at.
func buildRuntimeStage(orig analyzer.DockerfileAST, p Plan) []analyzer.Instruction {
	var out []analyzer.Instruction

	out = append(out, fromInstruction(p.Runtime, "", []string{"",
		comment("DT100", "runtime stage carries the application and nothing else"),
	}))

	// Re-declare the ARGs the runtime stage still references: Docker scopes
	// ARG per stage.
	for _, ins := range orig.Instructions {
		if ins.Keyword == "ARG" {
			out = append(out, synth("ARG", ins.Args, nil))
		}
	}

	if w := workdir(&orig); w != "" {
		out = append(out, synth("WORKDIR", []string{w}, nil))
	}

	for i, art := range p.Artifacts {
		var lead []string
		if i == 0 {
			lead = []string{comment("DT101", "only the build output crosses the stage boundary")}
		}
		out = append(out, analyzer.Instruction{
			Keyword: "COPY",
			Flags:   []string{"--from=" + builderStageName, "--chown=" + chownOf(p.User)},
			Args:    []string{art.From, art.To},
			Lead:    lead,
		})
	}

	for _, ins := range orig.Instructions {
		switch ins.Keyword {
		case "ENV", "EXPOSE", "LABEL", "VOLUME", "STOPSIGNAL", "HEALTHCHECK":
			out = append(out, synthFrom(ins))
		}
	}
	for i, env := range p.RuntimeEnv {
		var lead []string
		if i == 0 {
			lead = []string{comment("DT104", "point the interpreter at the copied dependency tree")}
		}
		out = append(out, synth("ENV", []string{env}, lead))
	}

	out = append(out, synth("USER", []string{p.User},
		[]string{comment("DT010", "drop privileges before the process starts")}))

	if !p.ReplaceCommand {
		// The runtime base has no command of its own, so the original one is
		// still the right one; the artifacts sit at their original paths.
		for _, ins := range orig.Instructions {
			if ins.Keyword == "ENTRYPOINT" || ins.Keyword == "CMD" {
				out = append(out, synthFrom(ins))
			}
		}
		return out
	}

	lead := []string{comment("DT102", p.Runtime+" supplies the interpreter as its entrypoint")}
	if len(p.Entrypoint) > 0 {
		out = append(out, analyzer.Instruction{Keyword: "ENTRYPOINT", Exec: true, Args: p.Entrypoint, Lead: lead})
		lead = nil
	}
	if len(p.Cmd) > 0 {
		out = append(out, analyzer.Instruction{Keyword: "CMD", Exec: true, Args: p.Cmd, Lead: lead})
	}
	return out
}

// chownOf turns a USER value into a --chown argument. A named user without a
// group reuses the name for both, which is how Docker resolves it anyway.
func chownOf(user string) string {
	if strings.Contains(user, ":") {
		return user
	}
	return user + ":" + user
}

func fromInstruction(image, stage string, lead []string) analyzer.Instruction {
	args := []string{image}
	if stage != "" {
		args = append(args, "AS", stage)
	}
	return analyzer.Instruction{Keyword: "FROM", Args: args, Lead: lead}
}

func synth(keyword string, args, lead []string) analyzer.Instruction {
	return analyzer.Instruction{Keyword: keyword, Args: args, Lead: lead}
}

// synthFrom copies an instruction across a stage boundary, keeping its exec
// form and flags but dropping the captured source, whose line numbers no longer
// describe where it sits.
func synthFrom(ins analyzer.Instruction) analyzer.Instruction {
	return analyzer.Instruction{
		Keyword: ins.Keyword,
		Args:    append([]string(nil), ins.Args...),
		Flags:   append([]string(nil), ins.Flags...),
		Exec:    ins.Exec,
	}
}

// redirectPip rewrites every `pip install` in the builder to install into dir,
// which is what makes the dependency tree a single copyable directory.
func redirectPip(in []analyzer.Instruction, dir string) []analyzer.Instruction {
	for i := range in {
		ins := &in[i]
		if ins.Keyword != "RUN" || ins.Exec {
			continue
		}
		var (
			changed bool
			args    []string
		)
		for j, cmd := range analyzer.Commands(ins.Args) {
			if analyzer.IsCmd(cmd, "pip", "pip3") && analyzer.HasSubcommand(cmd, "install") &&
				!analyzer.HasFlag(cmd, "--target", "-t", "--prefix") {
				cmd = append(append([]string{}, cmd...), "--target="+dir)
				changed = true
			}
			if j > 0 {
				args = append(args, "&&")
			}
			args = append(args, cmd...)
		}
		if changed {
			ins.Args = args
			ins.Raw = ""
			ins.Lead = append(ins.Lead,
				comment("DT105", "install into "+dir+" so the runtime stage can copy it whole"))
		}
	}
	return in
}

func dropKeywords(in []analyzer.Instruction, keywords ...string) []analyzer.Instruction {
	drop := map[string]bool{}
	for _, k := range keywords {
		drop[k] = true
	}
	out := in[:0:0]
	for _, ins := range in {
		if !drop[ins.Keyword] {
			out = append(out, ins)
		}
	}
	return out
}

// applyPrepare appends the plan's builder preparation steps. An ENV has to come
// before the build that depends on it; a RUN has to come after.
func applyPrepare(in []analyzer.Instruction, prepare []string) []analyzer.Instruction {
	for _, step := range prepare {
		keyword, rest, _ := strings.Cut(step, " ")
		ins := analyzer.Instruction{
			Keyword: keyword,
			Args:    strings.Fields(rest),
			Lead:    []string{comment("DT103", "added by docker-trim so the runtime stage can be minimal")},
		}
		if keyword == "ENV" {
			// Insert directly after FROM so every later command sees it.
			out := append([]analyzer.Instruction{}, in[0])
			out = append(out, ins)
			in = append(out, in[1:]...)
			continue
		}
		in = append(in, ins)
	}
	return in
}

// Package synthesizer turns an analyzed Dockerfile into an optimized one and
// renders it back to text.
package synthesizer

import (
	"encoding/json"
	"strings"

	"github.com/mkamranr/dtrim/pkg/analyzer"
)

// Render writes an Analysis back out as Dockerfile source.
//
// An instruction that still carries its captured source text is emitted
// byte-for-byte, so anything dtrim did not touch survives untouched, including
// heredocs, line continuations and whatever spacing the author preferred. Only
// instructions a rule rewrote, or the synthesizer created, are rendered from
// their parts. The output must parse: TestRender_output_reparses enforces it.
func Render(a *analyzer.Analysis) string {
	var b strings.Builder

	for _, line := range a.Preamble {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	for _, ins := range a.GlobalARGs {
		writeInstruction(&b, ins)
	}

	for si := range a.Stages {
		for _, ins := range a.Stages[si].Instructions {
			writeInstruction(&b, ins)
		}
	}
	for _, line := range a.Epilogue {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func writeInstruction(b *strings.Builder, ins analyzer.Instruction) {
	for _, line := range ins.Lead {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if ins.Raw != "" {
		b.WriteString(ins.Raw)
		b.WriteByte('\n')
		return
	}
	b.WriteString(format(ins))
	b.WriteByte('\n')
}

// format renders an instruction from its parts.
func format(ins analyzer.Instruction) string {
	var b strings.Builder
	b.WriteString(ins.Keyword)
	for _, f := range ins.Flags {
		b.WriteByte(' ')
		b.WriteString(f)
	}

	if ins.Exec {
		b.WriteByte(' ')
		enc, err := json.Marshal(ins.Args)
		if err != nil {
			// Args are plain strings, so this cannot fail; fall back to the
			// shell form rather than emitting nothing.
			b.WriteString(strings.Join(ins.Args, " "))
		} else {
			b.Write(enc)
		}
		return b.String()
	}

	if ins.Keyword == "RUN" {
		b.WriteByte(' ')
		b.WriteString(formatRun(ins.Args))
		return b.String()
	}

	if len(ins.Args) > 0 {
		b.WriteByte(' ')
		b.WriteString(strings.Join(ins.Args, " "))
	}
	return b.String()
}

// formatRun lays a shell command out one sub-command per line, which is how a
// reviewer can actually see what a rewritten RUN now does.
func formatRun(args []string) string {
	segments := splitOnAnd(args)
	if len(segments) < 2 {
		return strings.Join(args, " ")
	}
	var b strings.Builder
	for i, seg := range segments {
		if i == 0 {
			b.WriteString(strings.Join(seg, " "))
			continue
		}
		b.WriteString(" \\\n && ")
		b.WriteString(strings.Join(seg, " "))
	}
	return b.String()
}

// splitOnAnd breaks a command list at `&&` only. Other shell operators keep
// their sub-command inline, because moving a `|` or `;` onto its own line
// changes how the line reads without changing what it does.
func splitOnAnd(args []string) [][]string {
	var (
		out [][]string
		cur []string
	)
	for _, w := range args {
		if w == "&&" {
			out = append(out, cur)
			cur = nil
			continue
		}
		cur = append(cur, w)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// comment builds a dtrim annotation explaining a change it made. Every line the
// synthesizer adds or rewrites carries one, so the diff explains itself.
func comment(ruleID, why string) string {
	return "# dtrim(" + ruleID + "): " + why
}

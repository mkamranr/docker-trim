// Package analyzer parses Dockerfiles into the PRD's AST and inspects built
// container images layer by layer.
package analyzer

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// Analysis is a whole parsed Dockerfile. The PRD's DockerfileAST describes a
// single stage, so a multi-stage file yields one per stage plus the shared
// preamble and any ARGs declared before the first FROM.
type Analysis struct {
	// Path is the file the Dockerfile was read from, "-" for stdin.
	Path string
	// Preamble is every source line before the first instruction: parser
	// directives such as `# syntax=`, the licence header, blank lines. It is
	// re-emitted verbatim so rewriting never eats a comment.
	Preamble []string
	// GlobalARGs are ARG instructions declared before the first FROM. Docker
	// scopes these outside every stage, so each stage that uses one has to
	// re-declare it; the synthesizer relies on that.
	GlobalARGs []Instruction
	// Stages is one DockerfileAST per FROM, in source order.
	Stages []DockerfileAST
	// EscapeToken is `\` unless an `# escape=` directive said otherwise.
	EscapeToken rune
	// Warnings are the parser's own complaints, carried through to the report.
	Warnings []string
	// Source is the original file split into lines, so instructions can be
	// re-emitted byte-for-byte when a rule did not touch them.
	Source []string
	// Epilogue is everything after the last instruction.
	Epilogue []string
	// Newline is the line ending the source used, "\n" or "\r\n". A
	// Dockerfile checked out on Windows is CRLF, and rewriting it as LF would
	// change every line of the file and make the diff useless.
	Newline string
}

// MultiStage reports whether the file already builds in more than one stage,
// or copies from an external image. dtrim never restructures such a file: the
// author has already made the layering decisions, and guessing at them is how a
// tool like this breaks someone's build.
func (a *Analysis) MultiStage() bool {
	if len(a.Stages) > 1 {
		return true
	}
	for i := range a.Stages {
		for _, ins := range a.Stages[i].Instructions {
			if ins.Keyword == "COPY" && flagValue(ins.Flags, "from") != "" {
				return true
			}
		}
	}
	return false
}

// FinalStage is the stage that produces the shipped image.
func (a *Analysis) FinalStage() *DockerfileAST {
	if len(a.Stages) == 0 {
		return nil
	}
	return &a.Stages[len(a.Stages)-1]
}

// ParseFile reads and parses a Dockerfile from disk.
func ParseFile(path string) (*Analysis, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	defer f.Close()

	a, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("cannot parse %s: %w", path, err)
	}
	a.Path = path
	return a, nil
}

// Parse turns Dockerfile source into an Analysis.
func Parse(r io.Reader) (*Analysis, error) {
	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	src := buf.String()

	res, err := parser.Parse(strings.NewReader(src))
	if err != nil {
		return nil, err
	}

	a := &Analysis{
		EscapeToken: res.EscapeToken,
		Source:      splitLines(src),
		Newline:     detectNewline(src),
	}
	for _, w := range res.Warnings {
		a.Warnings = append(a.Warnings, w.Short)
	}

	children := res.AST.Children
	if len(children) == 0 {
		return nil, fmt.Errorf("no instructions found: is this a Dockerfile?")
	}

	// Everything above the first instruction is preamble. Taking it as a raw
	// slice rather than from PrevComment keeps `# syntax=` directives, blank
	// lines and the ordering between them exactly as written.
	if first := children[0].StartLine; first > 1 && first-1 <= len(a.Source) {
		a.Preamble = a.Source[:first-1]
	}

	var (
		cur     *DockerfileAST
		prevEnd int // last source line already accounted for
	)
	if len(a.Preamble) > 0 {
		prevEnd = len(a.Preamble)
	}
	for i, node := range children {
		ins := a.instruction(node, i == 0, prevEnd)
		prevEnd = node.EndLine

		if ins.Keyword == "FROM" {
			base, stage := parseFrom(ins.Args)
			a.Stages = append(a.Stages, DockerfileAST{
				BaseImage:    base,
				BuildStage:   stage,
				Instructions: []Instruction{ins},
			})
			cur = &a.Stages[len(a.Stages)-1]
			continue
		}

		if cur == nil {
			// Only ARG is legal before the first FROM.
			a.GlobalARGs = append(a.GlobalARGs, ins)
			continue
		}
		cur.Instructions = append(cur.Instructions, ins)
	}

	if len(a.Stages) == 0 {
		return nil, fmt.Errorf("no FROM instruction found")
	}
	if prevEnd < len(a.Source) {
		a.Epilogue = a.Source[prevEnd:]
	}
	return a, nil
}

// instruction converts one parser node, capturing the exact source text so the
// emitter can reproduce untouched instructions without reformatting them.
func (a *Analysis) instruction(node *parser.Node, isFirst bool, prevEnd int) Instruction {
	ins := Instruction{
		Keyword: strings.ToUpper(node.Value),
		Flags:   append([]string(nil), node.Flags...),
		Line:    node.StartLine,
		EndLine: node.EndLine,
	}
	ins.Exec = node.Attributes["json"]
	for n := node.Next; n != nil; n = n.Next {
		ins.Args = append(ins.Args, n.Value)
	}

	// ENV and LABEL arrive as a flat name, value, "=" triple per pair. Fold
	// them back into name=value so an instruction re-rendered from its parts
	// is still valid; the marker is an artefact of the parser, not syntax.
	if ins.Keyword == "ENV" || ins.Keyword == "LABEL" {
		ins.Args = foldAssignments(ins.Args)
	}

	// Shell-form RUN/CMD/ENTRYPOINT/SHELL arrive as a single opaque string.
	// PRD section 5 specifies Args as the command split into words, so split
	// it here. The splitter keeps quote characters inside the tokens, which
	// means strings.Join(Args, " ") reconstructs the original command.
	if !ins.Exec && len(ins.Args) == 1 && isShellForm(ins.Keyword) {
		ins.Args = splitShellWords(ins.Args[0])
	}

	// Raw spans StartLine..EndLine, which covers line continuations and
	// heredoc bodies; node.Original collapses both and would lose them.
	if node.StartLine >= 1 && node.EndLine <= len(a.Source) && node.EndLine >= node.StartLine {
		ins.Raw = strings.Join(a.Source[node.StartLine-1:node.EndLine], "\n")
	} else {
		ins.Raw = node.Original
	}

	// The first instruction's lead is already in Preamble. For the rest, take
	// the gap verbatim rather than from node.PrevComment, which keeps only the
	// comments and would silently drop the blank lines between them.
	if !isFirst && node.StartLine-1 > prevEnd && node.StartLine-1 <= len(a.Source) {
		ins.Lead = a.Source[prevEnd : node.StartLine-1]
	}
	return ins
}

// foldAssignments turns the parser's ["NAME","value","="] triples into
// ["NAME=value"]. Input that does not use the marker is returned unchanged, so
// the legacy `ENV NAME value` form still works.
func foldAssignments(args []string) []string {
	var out []string
	for i := 0; i < len(args); {
		if i+2 < len(args) && args[i+2] == "=" {
			out = append(out, args[i]+"="+args[i+1])
			i += 3
			continue
		}
		out = append(out, args[i])
		i++
	}
	return out
}

// isShellForm reports whether a keyword's argument is a shell command line.
func isShellForm(keyword string) bool {
	switch keyword {
	case "RUN", "CMD", "ENTRYPOINT", "SHELL":
		return true
	}
	return false
}

// splitShellWords splits a command on unquoted whitespace, leaving the quote
// characters attached to their token. Joining the result with a single space
// reproduces the input except for runs of repeated whitespace, and Raw remains
// the authority for anything that has to be reproduced byte-for-byte.
func splitShellWords(s string) []string {
	var (
		out     []string
		cur     strings.Builder
		single  bool
		double  bool
		escaped bool
		started bool
	)
	flush := func() {
		if started {
			out = append(out, cur.String())
			cur.Reset()
			started = false
		}
	}
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
			started = true
		case r == '\\' && !single:
			cur.WriteRune(r)
			escaped = true
			started = true
		case r == '\'' && !double:
			single = !single
			cur.WriteRune(r)
			started = true
		case r == '"' && !single:
			double = !double
			cur.WriteRune(r)
			started = true
		case (r == ' ' || r == '\t' || r == '\n' || r == '\r') && !single && !double:
			flush()
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	flush()
	return out
}

// parseFrom splits `FROM image[:tag] [AS stage]` into its two interesting parts.
func parseFrom(args []string) (base, stage string) {
	if len(args) == 0 {
		return "", ""
	}
	base = args[0]
	for i := 1; i+1 < len(args); i++ {
		if strings.EqualFold(args[i], "as") {
			return base, args[i+1]
		}
	}
	return base, ""
}

// flagValue pulls `--name=value` out of an instruction's flag list.
func flagValue(flags []string, name string) string {
	prefix := "--" + name + "="
	for _, f := range flags {
		if strings.HasPrefix(f, prefix) {
			return strings.TrimPrefix(f, prefix)
		}
	}
	return ""
}

// detectNewline reports the line ending the source uses. Mixed endings resolve
// to whichever is more common, so a file with one stray CRLF is not rewritten
// wholesale.
func detectNewline(src string) string {
	crlf := strings.Count(src, "\r\n")
	lf := strings.Count(src, "\n") - crlf
	if crlf > lf {
		return "\r\n"
	}
	return "\n"
}

func splitLines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

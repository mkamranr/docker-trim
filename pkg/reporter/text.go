// Package reporter renders what dtrim found: the terminal summary, the JSON
// report, and the diff between the original Dockerfile and the trimmed one.
package reporter

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/mkamranr/dtrim/pkg/analyzer"
	"github.com/mkamranr/dtrim/pkg/dtrim"
)

// rule is the horizontal separator from the PRD's output specification.
const rule = "-------------------------------------------------------------"

// Options control rendering.
type Options struct {
	// NoColor disables ANSI colour even on a terminal.
	NoColor bool
	// Verbose prints every finding rather than the top ones.
	Verbose bool
	// FailOn, when set, adds the pass or fail line that explains the exit code.
	FailOn dtrim.Severity
}

// palette wraps text in ANSI escapes, or leaves it alone.
//
// Six SGR codes do not justify a dependency, particularly in a tool whose whole
// argument is that most dependencies are not carrying their weight.
type palette struct {
	bold, dim, good, warn, bad, head func(a ...interface{}) string
}

// ANSI select-graphic-rendition codes.
const (
	sgrReset  = "\x1b[0m"
	sgrBold   = "\x1b[1m"
	sgrFaint  = "\x1b[2m"
	sgrRed    = "\x1b[31m"
	sgrGreen  = "\x1b[32m"
	sgrYellow = "\x1b[33m"
	sgrCyan   = "\x1b[36;1m"
)

func newPalette(w io.Writer, noColor bool) palette {
	// Respect NO_COLOR, a non-terminal destination, and the explicit flag.
	plain := func(a ...interface{}) string { return fmt.Sprint(a...) }
	if noColor || os.Getenv("NO_COLOR") != "" || !isTerminal(w) {
		return palette{plain, plain, plain, plain, plain, plain}
	}
	paint := func(code string) func(a ...interface{}) string {
		return func(a ...interface{}) string { return code + fmt.Sprint(a...) + sgrReset }
	}
	return palette{
		bold: paint(sgrBold),
		dim:  paint(sgrFaint),
		good: paint(sgrGreen),
		warn: paint(sgrYellow),
		bad:  paint(sgrRed),
		head: paint(sgrCyan),
	}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// Text writes the human-readable report in the shape the PRD specifies.
func Text(w io.Writer, rep *dtrim.Report, opt Options) error {
	p := newPalette(w, opt.NoColor)
	b := &strings.Builder{}

	writeProgress(b, p, rep)
	writeTrace(b, p, rep, opt)
	writeFindings(b, p, rep, opt)
	writeSummary(b, p, rep)
	writeWarnings(b, p, rep)
	writeGate(b, p, rep, opt)

	_, err := io.WriteString(w, b.String())
	return err
}

// writeGate explains a --fail-on failure, naming the rules responsible so the
// person reading a red pipeline knows what to fix without re-running anything.
func writeGate(b *strings.Builder, p palette, rep *dtrim.Report, opt Options) {
	if opt.FailOn == "" {
		return
	}
	breaches := rep.Breaches(opt.FailOn)
	if len(breaches) == 0 {
		fmt.Fprintf(b, "\n%s nothing at %s or above.\n",
			p.good("PASS"), string(opt.FailOn))
		return
	}
	seen := map[string]bool{}
	var rules []string
	for _, f := range breaches {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			rules = append(rules, f.RuleID)
		}
	}
	fmt.Fprintf(b, "\n%s %d %s at %s or above: %s\n",
		p.bad("FAIL"), len(breaches), plural("finding", len(breaches)),
		string(opt.FailOn), strings.Join(rules, ", "))
}

// plural adds the right suffix. "process" needs "es", and getting that wrong
// is visible in the first line of output.
func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	switch {
	case strings.HasSuffix(word, "s"), strings.HasSuffix(word, "x"),
		strings.HasSuffix(word, "z"), strings.HasSuffix(word, "ch"),
		strings.HasSuffix(word, "sh"):
		return word + "es"
	case strings.HasSuffix(word, "y") && !strings.ContainsAny(word[len(word)-2:len(word)-1], "aeiou"):
		return word[:len(word)-1] + "ies"
	}
	return word + "s"
}

// writeProgress emits the `[dtrim] ...` lines that narrate the run.
func writeProgress(b *strings.Builder, p palette, rep *dtrim.Report) {
	tag := p.head("[dtrim]")

	if df := rep.Dockerfile; df != nil {
		what := describeEcosystem(df.Ecosystem)
		fmt.Fprintf(b, "%s Analyzed %s (%s, %s)\n", tag, df.Path, what, stageWord(df.Stages))
	}
	if img := rep.Image; img != nil {
		var files int
		for _, l := range img.Layers {
			files += l.Files
		}
		fmt.Fprintf(b, "%s Inspected %s: %s across %d layers, %s files\n",
			tag, img.Reference, humanize.Bytes(uint64(img.TotalSize)), len(img.Layers),
			humanize.Comma(int64(files)))
	}
	if df := rep.Dockerfile; df != nil && df.Output != "" {
		verb := "Applied cleanups"
		if df.Restructured {
			verb = "Created Multi-Stage Dockerfile"
		}
		fmt.Fprintf(b, "%s %s -> %s\n", tag, verb, df.Output)
	}
	if v := rep.Verification; v != nil {
		switch {
		case !v.Smoke.Started:
			fmt.Fprintf(b, "%s %s: %s\n", tag, p.bad("the trimmed image did not run"), v.Smoke.Reason)
		default:
			// Say what was observed rather than implying the image was fully
			// validated: it was started and watched, not exercised.
			fmt.Fprintf(b, "%s Built both images; trimmed image %s\n", tag, p.good(v.Smoke.Reason))
		}
	}
}

// writeTrace reports what running the container showed, and how much of the
// program that trace actually covered.
func writeTrace(b *strings.Builder, p palette, rep *dtrim.Report, opt Options) {
	t := rep.Trace
	if t == nil {
		return
	}
	u := t.Usage

	fmt.Fprintf(b, "\n%s\n", p.bold("Runtime trace"))
	fmt.Fprintf(b, "  Observed            : %s across %d %s, %d %s\n",
		t.TraceSummary(), t.Processes, plural("process", t.Processes),
		t.Samples, plural("sample", t.Samples))

	if total := len(u.Used) + len(u.Unused) + len(u.Essential); total > 0 {
		fmt.Fprintf(b, "  Packages exercised  : %d of %d\n", len(u.Used), total)
		if len(u.Unused) > 0 {
			fmt.Fprintf(b, "  Never touched       : %d %s, %s if removed %s\n",
				len(u.Unused), plural("package", len(u.Unused)),
				humanize.Bytes(uint64(u.RemovableBytes)),
				p.dim("(as the package database reports it)"))
		}
		if len(u.Essential) > 0 {
			fmt.Fprintf(b, "  Kept regardless     : %d %s %s\n",
				len(u.Essential), plural("package", len(u.Essential)),
				p.dim("(libc, the loader, trust store, time zones)"))
		}
	}

	limit := 10
	if opt.Verbose {
		limit = len(u.Unused)
	}
	for i, pkg := range u.Unused {
		if i >= limit {
			fmt.Fprintf(b, "      %s\n", p.dim(fmt.Sprintf("... and %d more, run with --verbose to see them",
				len(u.Unused)-limit)))
			break
		}
		fmt.Fprintf(b, "      %s %-28s %s\n", p.warn("-"), pkg.Name,
			p.dim(humanize.Bytes(uint64(pkg.SizeBytes))))
	}
}

func writeFindings(b *strings.Builder, p palette, rep *dtrim.Report, opt Options) {
	if len(rep.Fixed) > 0 {
		fmt.Fprintf(b, "\n%s\n", p.bold("Applied"))
		for _, f := range dedupe(rep.Fixed) {
			fmt.Fprintf(b, "  %s %s %s\n", p.good("+"), p.dim(f.RuleID), f.Detail)
		}
	}

	remaining := dedupe(rep.Findings)
	if len(remaining) == 0 {
		return
	}
	limit := 8
	if opt.Verbose {
		limit = len(remaining)
	}
	fmt.Fprintf(b, "\n%s\n", p.bold("Findings"))
	for i, f := range remaining {
		if i >= limit {
			fmt.Fprintf(b, "  %s\n", p.dim(fmt.Sprintf("... and %d more, run with --verbose to see them",
				len(remaining)-limit)))
			break
		}
		mark := p.warn("!")
		switch f.Severity {
		case dtrim.SeverityCritical, dtrim.SeverityHigh:
			mark = p.bad("!")
		case dtrim.SeverityLow, dtrim.SeverityInfo:
			mark = p.dim("-")
		}
		where := ""
		if f.Line > 0 {
			where = p.dim(fmt.Sprintf(":%d", f.Line))
		}
		fmt.Fprintf(b, "  %s %s%s %s\n", mark, p.dim(f.RuleID), where, f.Title)
		fmt.Fprintf(b, "      %s\n", wrap(f.Detail, 72, "      "))
	}
}

// writeSummary emits the boxed block the PRD specifies, with the measured or
// estimated label that keeps the numbers honest.
func writeSummary(b *strings.Builder, p palette, rep *dtrim.Report) {
	res := rep.Result
	if res.OriginalSizeBytes == 0 && rep.Security == nil {
		return
	}

	fmt.Fprintf(b, "%s\n", p.dim(rule))

	if res.OriginalSizeBytes > 0 && res.TrimmedSizeBytes > 0 {
		label := "measured"
		if !res.Measured {
			label = "estimated"
		}
		fmt.Fprintf(b, "Original Image Size : %-9s %s\n",
			humanize.Bytes(uint64(res.OriginalSizeBytes)), p.dim("("+baseOf(rep, true)+")"))
		fmt.Fprintf(b, "Optimized Image Size: %-9s %s\n",
			humanize.Bytes(uint64(res.TrimmedSizeBytes)), p.dim("("+baseOf(rep, false)+")"))

		pct := res.ReductionRatio * 100
		shown := fmt.Sprintf("%.1f%%", pct)
		if pct > 0 {
			shown = p.good("-" + shown)
		} else {
			shown = p.warn("+" + strings.TrimPrefix(shown, "-"))
		}
		fmt.Fprintf(b, "Size Reduction      : %s %s\n", shown, p.dim("("+label+")"))
	} else if res.OriginalSizeBytes > 0 {
		fmt.Fprintf(b, "Image Size          : %s\n", humanize.Bytes(uint64(res.OriginalSizeBytes)))
		fmt.Fprintf(b, "Size Reduction      : %s\n",
			p.dim("not measured, re-run with --optimize --verify"))
	}

	if img := rep.Image; img != nil {
		writeBloat(b, p, img)
	}
	if sec := rep.Security; sec != nil {
		fmt.Fprintf(b, "Attack Surface      : %s\n", sec.Summary())
	}
	fmt.Fprintf(b, "%s\n", p.dim(rule))
}

// writeBloat lists where an image's bytes went, largest category first.
func writeBloat(b *strings.Builder, p palette, img *analyzer.ImageReport) {
	type kv struct {
		name  string
		bytes int64
	}
	var cats []kv
	for k, v := range img.Categories {
		cats = append(cats, kv{k, v})
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i].bytes > cats[j].bytes })

	if img.WastedBytes > 0 {
		fmt.Fprintf(b, "Replaced in Layers  : %-9s %s\n", humanize.Bytes(uint64(img.WastedBytes)),
			p.dim("(written then overwritten, still downloaded on every pull)"))
	}
	if img.WhiteoutBytes > 0 {
		fmt.Fprintf(b, "Deleted But Shipped : %-9s %s\n", humanize.Bytes(uint64(img.WhiteoutBytes)),
			p.dim("(removed in a later layer, so still in the image)"))
	}
	for i, c := range cats {
		if i >= 5 || c.bytes < 1<<20 {
			break
		}
		fmt.Fprintf(b, "  %-18s: %-9s %s\n", c.name, humanize.Bytes(uint64(c.bytes)),
			p.dim("("+analyzer.BloatExplanation(c.name)+")"))
	}
}

func writeWarnings(b *strings.Builder, p palette, rep *dtrim.Report) {
	var all []string
	if df := rep.Dockerfile; df != nil {
		all = append(all, df.Warnings...)
	}
	all = append(all, rep.Notes...)
	if rep.Security != nil {
		all = append(all, rep.Security.Notes...)
	}
	if rep.Trace != nil {
		all = append(all, rep.Trace.Usage.Notes...)
	}
	if len(all) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s\n", p.bold("Notes"))
	for _, n := range unique(all) {
		fmt.Fprintf(b, "  %s %s\n", p.warn("*"), wrap(n, 72, "    "))
	}
}

func baseOf(rep *dtrim.Report, original bool) string {
	df := rep.Dockerfile
	if df == nil {
		if rep.Image != nil {
			return rep.Image.Reference
		}
		return ""
	}
	if original {
		if df.BuilderBase != "" {
			return df.BuilderBase
		}
		return "original"
	}
	if df.RuntimeBase != "" {
		return df.RuntimeBase
	}
	return "cleaned up in place"
}

func describeEcosystem(eco string) string {
	switch eco {
	case "go":
		return "Go"
	case "node":
		return "Node.js"
	case "python":
		return "Python"
	case "rust":
		return "Rust"
	case "java":
		return "Java"
	}
	return "unrecognised toolchain"
}

func stageWord(n int) string {
	if n == 1 {
		return "single stage"
	}
	return fmt.Sprintf("%d stages", n)
}

// dedupe collapses findings that repeat the same rule and detail, which happens
// when one rule fires on several lines for the same reason.
func dedupe(in []dtrim.Finding) []dtrim.Finding {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, f := range in {
		key := f.RuleID + "\x00" + f.Detail
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// wrap folds text to width, indenting continuation lines.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var (
		b    strings.Builder
		line = words[0]
	)
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			b.WriteString(line)
			b.WriteByte('\n')
			b.WriteString(indent)
			line = w
			continue
		}
		line += " " + w
	}
	b.WriteString(line)
	return b.String()
}

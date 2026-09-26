package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/mkamranr/docker-trim/pkg/trim"
)

// Diff writes a unified diff between the original Dockerfile and the trimmed
// one, so a reviewer can see every line docker-trim changed rather than taking the
// summary on trust.
func Diff(w io.Writer, rep *trim.Report, opt Options) error {
	df := rep.Dockerfile
	if df == nil || df.Trimmed == "" || df.Trimmed == df.Original {
		return nil
	}
	p := newPalette(w, opt.NoColor)

	from, to := df.Path, df.Output
	if to == "" {
		to = df.Path + " (trimmed)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n", p.bold("--- "+from), p.bold("+++ "+to))

	for _, h := range hunks(splitLines(df.Original), splitLines(df.Trimmed), 3) {
		fmt.Fprintf(&b, "%s\n", p.head(h.header()))
		for _, l := range h.lines {
			switch l.kind {
			case '-':
				fmt.Fprintf(&b, "%s\n", p.bad("-"+l.text))
			case '+':
				fmt.Fprintf(&b, "%s\n", p.good("+"+l.text))
			default:
				fmt.Fprintf(&b, " %s\n", p.dim(l.text))
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Markdown writes a report suitable for pasting into a pull request.
func Markdown(w io.Writer, rep *trim.Report) error {
	var b strings.Builder
	b.WriteString("## docker-trim report\n\n")

	res := rep.Result
	if res.OriginalSizeBytes > 0 && res.TrimmedSizeBytes > 0 {
		label := "estimated"
		if res.Measured {
			label = "measured"
		}
		b.WriteString("| | Size |\n| :-- | --: |\n")
		fmt.Fprintf(&b, "| Original | %s |\n", bytesOf(res.OriginalSizeBytes))
		fmt.Fprintf(&b, "| Trimmed | %s |\n", bytesOf(res.TrimmedSizeBytes))
		fmt.Fprintf(&b, "| Reduction | **%.1f%%** (%s) |\n\n", res.ReductionRatio*100, label)
	}
	if sec := rep.Security; sec != nil {
		fmt.Fprintf(&b, "**Attack surface:** %s\n\n", sec.Summary())
	}

	if len(rep.Fixed) > 0 {
		b.WriteString("### Applied\n\n")
		for _, f := range dedupe(rep.Fixed) {
			fmt.Fprintf(&b, "- `%s` %s\n", f.RuleID, f.Detail)
		}
		b.WriteString("\n")
	}
	if remaining := dedupe(rep.Findings); len(remaining) > 0 {
		b.WriteString("### Still worth fixing\n\n")
		b.WriteString("| Rule | Severity | Line | Finding |\n| :-- | :-- | --: | :-- |\n")
		for _, f := range remaining {
			line := ""
			if f.Line > 0 {
				line = fmt.Sprintf("%d", f.Line)
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", f.RuleID, f.Severity, line, f.Title)
		}
		b.WriteString("\n")
	}
	if df := rep.Dockerfile; df != nil && df.Trimmed != "" && df.Trimmed != df.Original {
		b.WriteString("<details><summary>Diff</summary>\n\n```diff\n")
		for _, h := range hunks(splitLines(df.Original), splitLines(df.Trimmed), 3) {
			fmt.Fprintf(&b, "%s\n", h.header())
			for _, l := range h.lines {
				if l.kind == ' ' {
					b.WriteString(" ")
				} else {
					b.WriteByte(l.kind)
				}
				b.WriteString(l.text)
				b.WriteByte('\n')
			}
		}
		b.WriteString("```\n\n</details>\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// --- a small unified-diff implementation -------------------------------------
//
// Dockerfiles are tens of lines, so the quadratic longest-common-subsequence
// table is the right trade: exact output, no dependency, and no risk of a diff
// library's heuristics eliding a line that matters.

type diffLine struct {
	kind byte // ' ', '-', '+'
	text string
}

type hunk struct {
	fromStart, fromCount int
	toStart, toCount     int
	lines                []diffLine
}

func (h hunk) header() string {
	return fmt.Sprintf("@@ -%d,%d +%d,%d @@", h.fromStart, h.fromCount, h.toStart, h.toCount)
}

func hunks(from, to []string, context int) []hunk {
	script := lcsDiff(from, to)

	var (
		out     []hunk
		cur     *hunk
		fromPos = 1
		toPos   = 1
		pending []diffLine
	)
	flushPending := func(keep int) {
		if len(pending) > keep {
			pending = pending[len(pending)-keep:]
		}
	}

	for i := 0; i < len(script); i++ {
		l := script[i]
		if l.kind == ' ' {
			if cur == nil {
				pending = append(pending, l)
				flushPending(context)
			} else {
				cur.lines = append(cur.lines, l)
				// Close the hunk once enough unchanged lines have passed.
				trailing := 0
				for j := len(cur.lines) - 1; j >= 0 && cur.lines[j].kind == ' '; j-- {
					trailing++
				}
				// Close once the run of unchanged lines is longer than two
				// context widths, which is where a standard unified diff stops
				// merging neighbouring changes into one hunk. Trim back to
				// exactly `context` lines: the excess is what to drop, not a
				// fixed count.
				if trailing > context*2 {
					cur.lines = cur.lines[:len(cur.lines)-(trailing-context)]
					out = append(out, *cur)
					cur = nil
					pending = nil
				}
			}
			fromPos++
			toPos++
			continue
		}

		if cur == nil {
			cur = &hunk{fromStart: fromPos - len(pending), toStart: toPos - len(pending)}
			if cur.fromStart < 1 {
				cur.fromStart = 1
			}
			if cur.toStart < 1 {
				cur.toStart = 1
			}
			cur.lines = append(cur.lines, pending...)
			pending = nil
		}
		cur.lines = append(cur.lines, l)
		if l.kind == '-' {
			fromPos++
		} else {
			toPos++
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}

	for i := range out {
		for _, l := range out[i].lines {
			if l.kind != '+' {
				out[i].fromCount++
			}
			if l.kind != '-' {
				out[i].toCount++
			}
		}
	}
	return out
}

// lcsDiff produces the edit script via a longest-common-subsequence table.
func lcsDiff(a, b []string) []diffLine {
	n, m := len(a), len(b)
	table := make([][]int, n+1)
	for i := range table {
		table[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
			} else if table[i+1][j] >= table[i][j+1] {
				table[i][j] = table[i+1][j]
			} else {
				table[i][j] = table[i][j+1]
			}
		}
	}

	var out []diffLine
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, diffLine{' ', a[i]})
			i++
			j++
		case table[i+1][j] >= table[i][j+1]:
			out = append(out, diffLine{'-', a[i]})
			i++
		default:
			out = append(out, diffLine{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, diffLine{'-', a[i]})
	}
	for ; j < m; j++ {
		out = append(out, diffLine{'+', b[j]})
	}
	return out
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func bytesOf(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

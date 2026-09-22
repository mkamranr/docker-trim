package synthesizer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mkamranr/dtrim/pkg/analyzer"
)

const fixtures = "../../tests/fixtures"

func parseFixture(t *testing.T, name string) *analyzer.Analysis {
	t.Helper()
	a, err := analyzer.ParseFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return a
}

// The load-bearing property: whatever dtrim emits has to be a Dockerfile.
func TestRender_output_reparses(t *testing.T) {
	entries, err := os.ReadDir(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".Dockerfile") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			a := parseFixture(t, e.Name())
			analyzer.FixAll(a, analyzer.ConfidenceAggressive)

			out := Render(a)
			reparsed, err := analyzer.Parse(strings.NewReader(out))
			if err != nil {
				t.Fatalf("emitted Dockerfile does not parse: %v\n---\n%s", err, out)
			}
			if got, want := len(reparsed.Stages), len(a.Stages); got != want {
				t.Errorf("reparsed stage count = %d, want %d\n---\n%s", got, want, out)
			}
			for i := range a.Stages {
				if got, want := reparsed.Stages[i].BaseImage, a.Stages[i].BaseImage; got != want {
					t.Errorf("stage %d base = %q, want %q", i, got, want)
				}
				if got, want := reparsed.Stages[i].BuildStage, a.Stages[i].BuildStage; got != want {
					t.Errorf("stage %d name = %q, want %q", i, got, want)
				}
			}
		})
	}
}

// An untouched file must round-trip byte-for-byte, or `--analyze-only` and a
// no-op `--optimize` would produce a diff out of nothing.
func TestRender_round_trips_an_untouched_file_exactly(t *testing.T) {
	entries, _ := os.ReadDir(fixtures)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".Dockerfile") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			path := filepath.Join(fixtures, e.Name())
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got := Render(parseFixture(t, e.Name()))
			if got != string(src) {
				t.Errorf("round trip changed the file:\n--- want ---\n%s\n--- got ---\n%s", src, got)
			}
		})
	}
}

func TestRender_lays_a_rewritten_run_out_one_command_per_line(t *testing.T) {
	a, err := analyzer.Parse(strings.NewReader(
		"FROM debian:12\nRUN apt-get update && apt-get install -y curl\n"))
	if err != nil {
		t.Fatal(err)
	}
	analyzer.FixAll(a, analyzer.ConfidenceSafe)

	out := Render(a)
	if !strings.Contains(out, " \\\n && ") {
		t.Errorf("rewritten RUN was not wrapped:\n%s", out)
	}
	if strings.Count(out, "&&") < 2 {
		t.Errorf("expected the cleanup to be appended:\n%s", out)
	}
	if _, err := analyzer.Parse(strings.NewReader(out)); err != nil {
		t.Fatalf("wrapped RUN does not parse: %v\n%s", err, out)
	}
}

func TestFormat_preserves_exec_form_as_a_json_array(t *testing.T) {
	got := format(analyzer.Instruction{Keyword: "CMD", Exec: true, Args: []string{"node", "dist/server.js"}})
	if got != `CMD ["node","dist/server.js"]` {
		t.Errorf("format = %q, want the JSON array form", got)
	}
}

func TestFormat_keeps_instruction_flags(t *testing.T) {
	got := format(analyzer.Instruction{
		Keyword: "COPY", Flags: []string{"--from=builder", "--chown=10001:10001"},
		Args: []string{"/src/bin/api", "/api"},
	})
	if got != "COPY --from=builder --chown=10001:10001 /src/bin/api /api" {
		t.Errorf("format = %q", got)
	}
}

// A Dockerfile checked out on Windows is CRLF. Rewriting it as LF would change
// every line of the file and drown the real change in noise, so the line ending
// has to survive.
func TestRender_preserves_crlf_line_endings(t *testing.T) {
	const lf = "FROM debian:12\nWORKDIR /app\nRUN apt-get update && apt-get install -y curl\nCMD [\"/app/x\"]\n"
	crlf := strings.ReplaceAll(lf, "\n", "\r\n")

	a, err := analyzer.Parse(strings.NewReader(crlf))
	if err != nil {
		t.Fatal(err)
	}
	if a.Newline != "\r\n" {
		t.Fatalf("Newline = %q, want CRLF", a.Newline)
	}
	if got := Render(a); got != crlf {
		t.Errorf("untouched CRLF file did not round trip:\n%q\nwant\n%q", got, crlf)
	}

	// And it must still hold once a rule has rewritten an instruction.
	a2, err := analyzer.Parse(strings.NewReader(crlf))
	if err != nil {
		t.Fatal(err)
	}
	analyzer.FixAll(a2, analyzer.ConfidenceSafe)
	out := Render(a2)
	if strings.Contains(strings.ReplaceAll(out, "\r\n", ""), "\n") {
		t.Errorf("rewritten CRLF file contains bare LF line endings:\n%q", out)
	}
	if !strings.Contains(out, "--no-install-recommends") {
		t.Error("the rewrite did not happen, so this proves nothing")
	}
	if _, err := analyzer.Parse(strings.NewReader(out)); err != nil {
		t.Fatalf("rewritten CRLF file does not parse: %v", err)
	}
}

func TestParse_leaves_an_lf_file_as_lf(t *testing.T) {
	a, err := analyzer.Parse(strings.NewReader("FROM alpine:3.21\nCMD [\"true\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Newline != "\n" {
		t.Errorf("Newline = %q, want LF", a.Newline)
	}
	if strings.Contains(Render(a), "\r") {
		t.Error("an LF file gained carriage returns")
	}
}

package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtures = "../../tests/fixtures"

func parseFixture(t *testing.T, name string) *Analysis {
	t.Helper()
	a, err := ParseFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return a
}

func TestParse_reads_a_single_stage_file_into_one_stage(t *testing.T) {
	a := parseFixture(t, "python-flask.Dockerfile")

	if got := len(a.Stages); got != 1 {
		t.Fatalf("stages = %d, want 1", got)
	}
	if got := a.Stages[0].BaseImage; got != "python:3.12-slim" {
		t.Errorf("base image = %q, want python:3.12-slim", got)
	}
	if a.Stages[0].BuildStage != "" {
		t.Errorf("build stage = %q, want empty for an unnamed stage", a.Stages[0].BuildStage)
	}
	if a.MultiStage() {
		t.Error("MultiStage() = true for a single-stage file")
	}
}

func TestParse_names_every_stage_of_a_multistage_file(t *testing.T) {
	a := parseFixture(t, "already-multistage.Dockerfile")

	if got := len(a.Stages); got != 3 {
		t.Fatalf("stages = %d, want 3", got)
	}
	want := []string{"frontend", "backend-builder", ""}
	for i, w := range want {
		if got := a.Stages[i].BuildStage; got != w {
			t.Errorf("stage %d name = %q, want %q", i, got, w)
		}
	}
	if !a.MultiStage() {
		t.Error("MultiStage() = false for a three-stage file")
	}
	if got := a.FinalStage().BaseImage; got != "python:3.11-slim" {
		t.Errorf("final stage base = %q, want python:3.11-slim", got)
	}
}

func TestParse_hoists_args_declared_before_the_first_from(t *testing.T) {
	a := parseFixture(t, "already-multistage.Dockerfile")

	if got := len(a.GlobalARGs); got != 1 {
		t.Fatalf("global ARGs = %d, want 1", got)
	}
	if got := a.GlobalARGs[0].Args[0]; got != "PYTORCH_VARIANT=cpu" {
		t.Errorf("global ARG = %q, want PYTORCH_VARIANT=cpu", got)
	}
	// The ARG must not also appear inside a stage, or it would be emitted twice.
	for _, ins := range a.Stages[0].Instructions {
		if ins.Keyword == "ARG" {
			t.Errorf("stage 0 wrongly owns the global ARG at line %d", ins.Line)
		}
	}
}

func TestParse_keeps_the_leading_comment_block_as_preamble(t *testing.T) {
	a := parseFixture(t, "node-express.Dockerfile")

	if len(a.Preamble) == 0 {
		t.Fatal("preamble is empty, the fixture opens with two comment lines")
	}
	if !strings.HasPrefix(a.Preamble[0], "# A typical bloated Node service") {
		t.Errorf("preamble[0] = %q, want the fixture's first comment", a.Preamble[0])
	}
	// Preamble owns those comments, so the first instruction must not repeat them.
	if got := a.Stages[0].Instructions[0].Lead; len(got) != 0 {
		t.Errorf("first instruction lead = %v, want none (preamble owns them)", got)
	}
}

func TestParse_captures_raw_source_across_line_continuations(t *testing.T) {
	a := parseFixture(t, "already-multistage.Dockerfile")

	var found bool
	for _, ins := range a.Stages[1].Instructions {
		if ins.Keyword != "RUN" || !strings.Contains(ins.Raw, "apt-get") {
			continue
		}
		found = true
		if ins.EndLine <= ins.Line {
			t.Errorf("EndLine %d not past Line %d for a continued RUN", ins.EndLine, ins.Line)
		}
		// node.Original would have collapsed the continuation; Raw must not.
		if !strings.Contains(ins.Raw, "\n") {
			t.Errorf("Raw lost the line continuation: %q", ins.Raw)
		}
		if !strings.Contains(ins.Raw, "rm -rf /var/lib/apt/lists/*") {
			t.Errorf("Raw dropped the continued line: %q", ins.Raw)
		}
	}
	if !found {
		t.Fatal("no continued RUN instruction found in stage 1")
	}
}

func TestParse_splits_run_arguments_the_way_the_prd_describes(t *testing.T) {
	a := parseFixture(t, "node-express.Dockerfile")

	for _, ins := range a.Stages[0].Instructions {
		if ins.Keyword != "RUN" || len(ins.Args) == 0 || ins.Args[0] != "apt-get" {
			continue
		}
		// PRD section 5 shows Args as the command split on whitespace.
		want := []string{"apt-get", "update", "&&", "apt-get", "install", "-y"}
		for i, w := range want {
			if i >= len(ins.Args) || ins.Args[i] != w {
				t.Fatalf("Args = %v, want prefix %v", ins.Args, want)
			}
		}
		return
	}
	t.Fatal("no apt-get RUN instruction found")
}

func TestParse_records_copy_from_flags(t *testing.T) {
	a := parseFixture(t, "already-multistage.Dockerfile")

	var seen int
	for _, ins := range a.FinalStage().Instructions {
		if ins.Keyword != "COPY" {
			continue
		}
		if v := flagValue(ins.Flags, "from"); v != "" {
			seen++
		}
	}
	if seen != 2 {
		t.Errorf("COPY --from count = %d, want 2", seen)
	}
}

func TestParse_rejects_input_with_no_from(t *testing.T) {
	_, err := Parse(strings.NewReader("RUN echo hello\n"))
	if err == nil {
		t.Fatal("want an error for a Dockerfile with no FROM")
	}
	if !strings.Contains(err.Error(), "FROM") {
		t.Errorf("error = %q, want it to mention FROM", err)
	}
}

func TestParse_rejects_empty_input(t *testing.T) {
	if _, err := Parse(strings.NewReader("")); err == nil {
		t.Fatal("want an error for empty input")
	}
}

func TestParseFile_reports_the_path_it_could_not_read(t *testing.T) {
	_, err := ParseFile(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Fatal("want an error for a missing file")
	}
	if !strings.Contains(err.Error(), "absent") {
		t.Errorf("error = %q, want it to name the missing file", err)
	}
}

// Every fixture has to parse; a fixture that does not is a broken test bed.
func TestParse_handles_every_fixture(t *testing.T) {
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
			if len(a.Stages) == 0 {
				t.Error("no stages parsed")
			}
		})
	}
}

func TestSplitShellWords_keeps_quotes_so_joining_round_trips(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`apt-get update && apt-get install -y curl`,
			[]string{"apt-get", "update", "&&", "apt-get", "install", "-y", "curl"}},
		{`echo "a b" c`, []string{"echo", `"a b"`, "c"}},
		{`echo 'x  y'`, []string{"echo", `'x  y'`}},
		{`sh -c "echo \"q\""`, []string{"sh", "-c", `"echo \"q\""`}},
		{`   spaced   out   `, []string{"spaced", "out"}},
		{``, nil},
	}
	for _, c := range cases {
		got := splitShellWords(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitShellWords(%q) = %q, want %q", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitShellWords(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
		// The join has to reconstruct the command, modulo repeated whitespace.
		if rejoined := strings.Join(got, " "); rejoined != strings.Join(strings.Fields(c.in), " ") &&
			!strings.ContainsAny(c.in, `'"`) {
			t.Errorf("joining %q gave %q, want %q", c.in, rejoined, strings.Join(strings.Fields(c.in), " "))
		}
	}
}

func TestParse_marks_exec_form_but_not_shell_form(t *testing.T) {
	a := parseFixture(t, "node-express.Dockerfile")
	for _, ins := range a.Stages[0].Instructions {
		switch ins.Keyword {
		case "CMD":
			if !ins.Exec {
				t.Error(`CMD ["node","dist/server.js"] should be marked exec form`)
			}
		case "RUN":
			if ins.Exec {
				t.Errorf("shell-form RUN at line %d wrongly marked exec", ins.Line)
			}
		}
	}
}

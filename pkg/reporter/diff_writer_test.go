package reporter

import (
	"strings"
	"testing"
)

func TestHunks_reports_a_single_changed_line_with_context(t *testing.T) {
	from := []string{"a", "b", "c", "d", "e", "f", "g"}
	to := []string{"a", "b", "c", "D", "e", "f", "g"}

	hs := hunks(from, to, 1)
	if len(hs) != 1 {
		t.Fatalf("hunks = %d, want 1", len(hs))
	}
	var got strings.Builder
	for _, l := range hs[0].lines {
		got.WriteByte(l.kind)
		got.WriteString(l.text)
		got.WriteByte('\n')
	}
	want := " c\n-d\n+D\n e\n"
	if got.String() != want {
		t.Errorf("hunk =\n%q\nwant\n%q", got.String(), want)
	}
}

func TestHunks_returns_nothing_for_identical_input(t *testing.T) {
	lines := []string{"FROM alpine", "CMD [\"true\"]"}
	if hs := hunks(lines, lines, 3); len(hs) != 0 {
		t.Errorf("hunks = %d, want 0 for identical input", len(hs))
	}
}

func TestHunks_handles_pure_insertion_and_deletion(t *testing.T) {
	if hs := hunks(nil, []string{"x", "y"}, 3); len(hs) != 1 || len(hs[0].lines) != 2 {
		t.Errorf("insertion: hunks = %+v", hs)
	}
	if hs := hunks([]string{"x", "y"}, nil, 3); len(hs) != 1 || len(hs[0].lines) != 2 {
		t.Errorf("deletion: hunks = %+v", hs)
	}
}

func TestLcsDiff_keeps_every_line_of_both_sides(t *testing.T) {
	from := []string{"FROM node:18", "RUN npm install", "CMD [\"node\"]"}
	to := []string{"FROM node:18 AS builder", "RUN npm ci", "RUN npm prune", "CMD [\"node\"]"}

	var kept, added int
	for _, l := range lcsDiff(from, to) {
		switch l.kind {
		case '-':
			kept++
		case '+':
			added++
		case ' ':
			kept++
			added++
		}
	}
	if kept != len(from) {
		t.Errorf("the diff accounts for %d of %d original lines", kept, len(from))
	}
	if added != len(to) {
		t.Errorf("the diff accounts for %d of %d new lines", added, len(to))
	}
}

func TestWrap_folds_without_losing_words(t *testing.T) {
	in := "the quick brown fox jumps over the lazy dog and keeps going for a while"
	got := wrap(in, 20, "  ")

	if strings.Join(strings.Fields(got), " ") != in {
		t.Errorf("wrapping changed the text: %q", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if len(strings.TrimLeft(line, " ")) > 20 {
			t.Errorf("line over the limit: %q", line)
		}
	}
}

func TestBytesOf_is_readable(t *testing.T) {
	cases := map[int64]string{0: "0 B", 512: "512 B", 1536: "1.5 KB", 1 << 30: "1.0 GB"}
	for in, want := range cases {
		if got := bytesOf(in); got != want {
			t.Errorf("bytesOf(%d) = %q, want %q", in, got, want)
		}
	}
}

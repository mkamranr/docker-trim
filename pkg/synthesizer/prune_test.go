package synthesizer

import (
	"strings"
	"testing"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
)

func usageWithUnused(names ...string) *analyzer.Usage {
	u := &analyzer.Usage{}
	for _, n := range names {
		u.Unused = append(u.Unused, analyzer.Package{Name: n, SizeBytes: 1 << 20})
	}
	return u
}

func optimizeString(t *testing.T, src string, opts Options) (*Result, string) {
	t.Helper()
	a, err := analyzer.Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	res := Optimize(a, opts)
	out := Render(a)
	if _, err := analyzer.Parse(strings.NewReader(out)); err != nil {
		t.Fatalf("emitted Dockerfile does not parse: %v\n%s", err, out)
	}
	return res, out
}

const multiStageSrc = `FROM golang:1.25 AS builder
WORKDIR /src
RUN apt-get update && apt-get install -y gcc make git
COPY . .
RUN go build -o /src/bin/app .

FROM debian:12
RUN apt-get update && apt-get install -y ca-certificates curl vim
COPY --from=builder /src/bin/app /app
CMD ["/app"]
`

func TestPrune_drops_unused_packages_from_the_shipping_stage(t *testing.T) {
	res, out := optimizeString(t, multiStageSrc, Options{
		Base:           BaseDistroless,
		Aggressiveness: analyzer.ConfidenceLikely,
		PruneUnused:    true,
		Usage:          usageWithUnused("curl", "vim"),
	})

	if len(res.Pruned) != 2 {
		t.Fatalf("pruned = %v, want curl and vim", res.Pruned)
	}
	_, runtime, _ := strings.Cut(out, "FROM debian:12")
	for _, gone := range []string{"curl", "vim"} {
		if strings.Contains(runtime, " "+gone) {
			t.Errorf("%q survived in the shipping stage:\n%s", gone, runtime)
		}
	}
	if !strings.Contains(runtime, "ca-certificates") {
		t.Errorf("a package the trace did not mark unused was removed:\n%s", runtime)
	}
}

// The builder installs what compiling needs. A runtime trace never sees that,
// so pruning a builder on its evidence breaks the build.
func TestPrune_never_touches_a_builder_stage(t *testing.T) {
	_, out := optimizeString(t, multiStageSrc, Options{
		Base:           BaseDistroless,
		Aggressiveness: analyzer.ConfidenceLikely,
		PruneUnused:    true,
		// The trace saw none of these, because they are only needed to build.
		Usage: usageWithUnused("gcc", "make", "git"),
	})

	builder, _, _ := strings.Cut(out, "FROM debian:12")
	for _, kept := range []string{"gcc", "make", "git"} {
		if !strings.Contains(builder, kept) {
			t.Errorf("%q was pruned from the builder; the build needs it:\n%s", kept, builder)
		}
	}
}

// A single-stage file builds and ships in one stage, so its installs serve
// both. Nothing in a runtime trace can separate them.
func TestPrune_declines_a_single_stage_file(t *testing.T) {
	const src = "FROM debian:12\nRUN apt-get update && apt-get install -y gcc curl\n" +
		"COPY . .\nCMD [\"/app\"]\n"
	res, out := optimizeString(t, src, Options{
		Base:           BaseDistroless,
		Aggressiveness: analyzer.ConfidenceLikely,
		PruneUnused:    true,
		Usage:          usageWithUnused("gcc", "curl"),
	})

	if len(res.Pruned) != 0 {
		t.Errorf("pruned %v from a single-stage file, where the same install serves the build",
			res.Pruned)
	}
	if !strings.Contains(out, "gcc") {
		t.Error("gcc was removed from a stage that also builds the application")
	}
}

// A RUN that exists only to install things nothing uses should go entirely,
// rather than leaving `apt-get install -y` with no arguments.
func TestPrune_removes_an_install_with_nothing_left(t *testing.T) {
	const src = `FROM golang:1.25 AS builder
RUN go build -o /app .

FROM debian:12
RUN apt-get update && apt-get install -y vim
COPY --from=builder /app /app
CMD ["/app"]
`
	_, out := optimizeString(t, src, Options{
		Base:           BaseDistroless,
		Aggressiveness: analyzer.ConfidenceLikely,
		PruneUnused:    true,
		Usage:          usageWithUnused("vim"),
	})

	_, runtime, _ := strings.Cut(out, "FROM debian:12")
	if strings.Contains(runtime, "install -y\n") || strings.Contains(runtime, "install -y \\") {
		t.Errorf("an install with no packages was left behind:\n%s", runtime)
	}
	if strings.Contains(runtime, "vim") {
		t.Errorf("vim survived:\n%s", runtime)
	}
}

// Pruning is evidence-driven, so without evidence it must do nothing at all.
func TestPrune_does_nothing_without_a_trace_or_without_the_flag(t *testing.T) {
	base := Options{Base: BaseDistroless, Aggressiveness: analyzer.ConfidenceLikely}

	noFlag := base
	noFlag.Usage = usageWithUnused("curl", "vim")
	if res, _ := optimizeString(t, multiStageSrc, noFlag); len(res.Pruned) != 0 {
		t.Errorf("pruned %v without --prune-unused", res.Pruned)
	}

	noTrace := base
	noTrace.PruneUnused = true
	if res, _ := optimizeString(t, multiStageSrc, noTrace); len(res.Pruned) != 0 {
		t.Errorf("pruned %v with no trace to justify it", res.Pruned)
	}
}

// Whatever it removes, the result has to still be a Dockerfile, and running
// docker-trim on its own output must not keep changing it.
func TestPrune_output_is_stable(t *testing.T) {
	opts := Options{
		Base:           BaseDistroless,
		Aggressiveness: analyzer.ConfidenceLikely,
		PruneUnused:    true,
		Usage:          usageWithUnused("curl", "vim"),
	}
	_, first := optimizeString(t, multiStageSrc, opts)
	_, second := optimizeString(t, first, opts)
	if first != second {
		t.Errorf("a second pass changed the file:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

// Belt and braces for the same collision, one layer down: even if a language
// package reached Unused, it must not strip a real OS package from an install.
func TestPrune_ignores_language_packages(t *testing.T) {
	usage := &analyzer.Usage{Unused: []analyzer.Package{
		{Name: "curl", SizeBytes: 1 << 20},
		{Name: "vim", Version: "9.0", Ecosystem: "PyPI", SizeBytes: 1 << 20},
	}}
	res, out := optimizeString(t, multiStageSrc, Options{
		Base:           BaseDistroless,
		Aggressiveness: analyzer.ConfidenceLikely,
		PruneUnused:    true,
		Usage:          usage,
	})

	if len(res.Pruned) != 1 || res.Pruned[0] != "curl" {
		t.Errorf("pruned = %v, want curl only: vim came from a lockfile", res.Pruned)
	}
	_, runtime, _ := strings.Cut(out, "FROM debian:12")
	if !strings.Contains(runtime, "vim") {
		t.Errorf("the OS vim was stripped on evidence about a PyPI package:\n%s", runtime)
	}
}

package synthesizer

import (
	"strings"
	"testing"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
)

func optimize(t *testing.T, fixture string, base Base) (*Result, string) {
	t.Helper()
	a := parseFixture(t, fixture)
	r := Optimize(a, Options{Base: base, Aggressiveness: analyzer.ConfidenceLikely})
	out := Render(a)
	if _, err := analyzer.Parse(strings.NewReader(out)); err != nil {
		t.Fatalf("emitted Dockerfile does not parse: %v\n%s", err, out)
	}
	return r, out
}

func TestDetectEcosystem_does_not_confuse_cargo_build_with_go_build(t *testing.T) {
	// "cargo build" contains "go build" as a substring; matching on words is
	// the only way to tell them apart.
	if got := DetectEcosystem(parseFixture(t, "rust-cli.Dockerfile")); got != EcosystemRust {
		t.Errorf("ecosystem = %q, want rust", got)
	}
	if got := DetectEcosystem(parseFixture(t, "go-api.Dockerfile")); got != EcosystemGo {
		t.Errorf("ecosystem = %q, want go", got)
	}
}

func TestDetectEcosystem_covers_every_fixture(t *testing.T) {
	want := map[string]Ecosystem{
		"go-api.Dockerfile":            EcosystemGo,
		"node-express.Dockerfile":      EcosystemNode,
		"python-flask.Dockerfile":      EcosystemPython,
		"rust-cli.Dockerfile":          EcosystemRust,
		"java-spring.Dockerfile":       EcosystemJava,
		"unknown-ecosystem.Dockerfile": EcosystemUnknown,
	}
	for fixture, eco := range want {
		if got := DetectEcosystem(parseFixture(t, fixture)); got != eco {
			t.Errorf("%s: ecosystem = %q, want %q", fixture, got, eco)
		}
	}
}

// The guard that decides whether this tool gets trusted or uninstalled.
func TestOptimize_never_restructures_an_already_multistage_file(t *testing.T) {
	r, out := optimize(t, "already-multistage.Dockerfile", BaseDistroless)

	if r.Restructured {
		t.Error("restructured a file that already builds in stages")
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "already builds in multiple stages") {
		t.Errorf("notes do not explain the refusal: %v", r.Notes)
	}
	reparsed, err := analyzer.Parse(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(reparsed.Stages); got != 3 {
		t.Errorf("stage count = %d, want the original 3", got)
	}
	if strings.Contains(out, builderStageName+"\n") && !strings.Contains(out, "backend-builder") {
		t.Error("a builder stage was invented")
	}
}

func TestOptimize_refuses_to_invent_a_builder_for_an_unknown_ecosystem(t *testing.T) {
	r, out := optimize(t, "unknown-ecosystem.Dockerfile", BaseDistroless)

	if r.Restructured {
		t.Error("restructured a file with no recognisable build step")
	}
	if !strings.Contains(r.Plan.Reason, "no recognisable build step") {
		t.Errorf("reason = %q", r.Plan.Reason)
	}
	// It should still have done the safe cleanups.
	if !strings.Contains(out, "rm -rf /var/lib/apt/lists/*") {
		t.Error("cleanups were not applied to the single stage")
	}
	if !strings.Contains(out, "--no-install-recommends") {
		t.Error("--no-install-recommends was not added")
	}
}

func TestOptimize_go_produces_a_static_binary_on_a_libc_free_base(t *testing.T) {
	r, out := optimize(t, "go-api.Dockerfile", BaseDistroless)

	if !r.Restructured {
		t.Fatal("did not restructure a single-stage Go build")
	}
	if r.Plan.Runtime != distrolessStatic {
		t.Errorf("runtime = %q, want %q", r.Plan.Runtime, distrolessStatic)
	}
	if !strings.Contains(out, "ENV CGO_ENABLED=0") {
		t.Error("distroless/static has no libc, so CGO_ENABLED=0 must be forced")
	}
	if !strings.Contains(out, "COPY --from=builder --chown=nonroot:nonroot /src/bin/api /src/bin/api") {
		t.Errorf("binary is not copied at its original path:\n%s", out)
	}
	// The builder keeps the toolchain; the runtime must not.
	builder, runtime, _ := strings.Cut(out, "FROM gcr.io/distroless")
	if !strings.Contains(builder, "apt-get") {
		t.Error("builder lost its toolchain install")
	}
	if strings.Contains(runtime, "apt-get") || strings.Contains(runtime, "go build") {
		t.Errorf("runtime stage kept build machinery:\n%s", runtime)
	}
}

func TestOptimize_go_on_scratch_brings_the_certificate_bundle(t *testing.T) {
	_, out := optimize(t, "go-api.Dockerfile", BaseScratch)

	if !strings.Contains(out, "FROM scratch") {
		t.Fatalf("runtime is not scratch:\n%s", out)
	}
	if !strings.Contains(out, "ca-certificates.crt") {
		t.Error("scratch has no trust store; the bundle has to be copied in")
	}
	if !strings.Contains(out, "USER 10001:10001") {
		t.Error("scratch has no nonroot user, so a numeric id is required")
	}
}

func TestOptimize_node_prunes_dev_dependencies_and_does_not_repeat_the_interpreter(t *testing.T) {
	r, out := optimize(t, "node-express.Dockerfile", BaseDistroless)

	if r.Plan.Runtime != "gcr.io/distroless/nodejs18-debian12:nonroot" {
		t.Errorf("runtime = %q, want the nodejs18 distroless image", r.Plan.Runtime)
	}
	if !strings.Contains(out, "npm prune --omit=dev") {
		t.Error("dev dependencies are not pruned before the copy")
	}
	// The base entrypoint is already /nodejs/bin/node.
	if strings.Contains(out, `CMD ["node","dist/server.js"]`) {
		t.Error("CMD still repeats the interpreter the base image supplies")
	}
	if !strings.Contains(out, `CMD ["dist/server.js"]`) {
		t.Errorf("CMD was not adapted to the distroless entrypoint:\n%s", out)
	}
}

func TestOptimize_java_emits_exactly_one_command(t *testing.T) {
	_, out := optimize(t, "java-spring.Dockerfile", BaseDistroless)

	// The base entrypoint is ["/usr/bin/java","-jar"], so the jar path alone
	// is the whole command. Emitting both would run java -jar app.jar app.jar.
	if strings.Count(out, "ENTRYPOINT") != 0 {
		t.Errorf("runtime stage should inherit the base entrypoint:\n%s", out)
	}
	if strings.Count(out, "CMD") != 1 {
		t.Errorf("want exactly one CMD, got %d:\n%s", strings.Count(out, "CMD"), out)
	}
	if !strings.Contains(out, `CMD ["/workspace/target/app.jar"]`) {
		t.Errorf("CMD = not the bare jar path:\n%s", out)
	}
}

func TestOptimize_python_installs_into_a_copyable_tree(t *testing.T) {
	_, out := optimize(t, "python-flask.Dockerfile", BaseDistroless)

	if !strings.Contains(out, "--target=/install") {
		t.Error("pip still installs into the system prefix, which cannot be copied out cleanly")
	}
	if !strings.Contains(out, "ENV PYTHONPATH=/install") {
		t.Error("the runtime stage does not point at the copied dependency tree")
	}
	if !strings.Contains(out, "COPY --from=builder --chown=10001:10001 /install /install") {
		t.Errorf("dependency tree is not copied:\n%s", out)
	}
}

// Python resolves dependencies against the exact interpreter that runs pip,
// and environment markers key off the full patch version. Moving the installed
// tree onto a different CPython build is how you get an image that starts and
// then dies on import, so the interpreter must not change.
func TestOptimize_python_keeps_the_same_interpreter(t *testing.T) {
	r, _ := optimize(t, "python-flask.Dockerfile", BaseDistroless)

	if strings.Contains(r.Plan.Runtime, "distroless") {
		t.Errorf("runtime = %q: distroless ships a different CPython patch release than the builder",
			r.Plan.Runtime)
	}
	if r.Plan.Runtime != r.Plan.Builder {
		t.Errorf("runtime = %q, builder = %q: the interpreter must not change",
			r.Plan.Runtime, r.Plan.Builder)
	}
	if !strings.Contains(strings.Join(r.Plan.Warnings, " "), "interpreter") {
		t.Errorf("the choice is not explained to the user: %v", r.Plan.Warnings)
	}
}

// Staying on the same base is still worth it when there is a toolchain to
// leave behind, which is where Python's real saving comes from.
func TestOptimize_python_strips_the_build_toolchain(t *testing.T) {
	r, out := optimize(t, "python-flask.Dockerfile", BaseDistroless)

	if !r.Restructured {
		t.Fatalf("declined to split a build that installs gcc: %q", r.Plan.Reason)
	}
	builder, runtime, ok := strings.Cut(out, "# docker-trim(DT100)")
	if !ok {
		t.Fatalf("no runtime stage emitted:\n%s", out)
	}
	for _, tool := range []string{"gcc", "g++", "libpq-dev", "vim", "netcat-openbsd"} {
		if !strings.Contains(builder, tool) {
			t.Errorf("builder lost %q", tool)
		}
		if strings.Contains(runtime, tool) {
			t.Errorf("runtime stage still installs %q:\n%s", tool, runtime)
		}
	}
}

// Nothing to strip means nothing to gain, and docker-trim should say so rather than
// write a file that changes the structure and saves zero bytes.
func TestOptimize_declines_a_split_that_would_save_nothing(t *testing.T) {
	a, err := analyzer.Parse(strings.NewReader(
		"FROM python:3.12-slim\nWORKDIR /app\nCOPY requirements.txt .\n" +
			"RUN pip install -r requirements.txt\nCOPY . .\nCMD [\"python\",\"app.py\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	r := Optimize(a, Options{Base: BaseDistroless, Aggressiveness: analyzer.ConfidenceLikely})

	if r.Restructured {
		t.Error("split a build whose runtime base equals its builder base and installs nothing")
	}
	if !strings.Contains(r.Plan.Reason, "save") {
		t.Errorf("reason does not explain that the split gains nothing: %q", r.Plan.Reason)
	}
}

// Alpine uses musl. Anything compiled against the builder's glibc will not
// load there, so the builder has to move to alpine as well rather than the user
// being handed a warning and a broken image.
func TestOptimize_matches_the_builder_libc_to_an_alpine_runtime(t *testing.T) {
	for _, fixture := range []string{"python-flask.Dockerfile", "node-express.Dockerfile"} {
		t.Run(fixture, func(t *testing.T) {
			r, out := optimize(t, fixture, BaseAlpine)
			if !r.Restructured {
				t.Fatalf("declined: %s", r.Plan.Reason)
			}
			if !strings.Contains(r.Plan.Builder, "alpine") {
				t.Errorf("builder = %q, runtime = %q: a glibc builder feeding a musl runtime "+
					"produces an image that starts and then fails to load its dependencies",
					r.Plan.Builder, r.Plan.Runtime)
			}
			if !strings.Contains(out, "AS builder") {
				t.Errorf("no builder stage:\n%s", out)
			}
		})
	}
}

// A Go binary is the exception: made static, it runs on any of the three.
func TestOptimize_go_builds_static_for_every_base(t *testing.T) {
	for _, base := range []Base{BaseDistroless, BaseAlpine, BaseScratch} {
		_, out := optimize(t, "go-api.Dockerfile", base)
		if !strings.Contains(out, "ENV CGO_ENABLED=0") {
			t.Errorf("--base %s: binary is not forced static, so it depends on the builder's libc:\n%s",
				base, out)
		}
	}
}

// Rust has no equivalent switch: a musl build needs an explicit target, and
// docker-trim will not quietly invent one.
func TestOptimize_rust_declines_alpine_without_a_musl_target(t *testing.T) {
	r, _ := optimize(t, "rust-cli.Dockerfile", BaseAlpine)
	if r.Restructured {
		t.Error("put a glibc Rust binary on alpine, where it cannot run")
	}
	if !strings.Contains(r.Plan.Reason, "musl") {
		t.Errorf("reason does not explain the musl target: %q", r.Plan.Reason)
	}
}

func TestOptimize_declines_scratch_for_interpreted_languages(t *testing.T) {
	for _, fixture := range []string{"node-express.Dockerfile", "python-flask.Dockerfile", "java-spring.Dockerfile"} {
		r, _ := optimize(t, fixture, BaseScratch)
		if r.Restructured {
			t.Errorf("%s: restructured onto scratch, which has no interpreter", fixture)
		}
		if r.Plan.Reason == "" {
			t.Errorf("%s: declined without saying why", fixture)
		}
	}
}

// Whatever docker-trim emits, running docker-trim on it again must not keep changing it.
func TestOptimize_is_stable_under_a_second_pass(t *testing.T) {
	for _, fixture := range []string{"go-api.Dockerfile", "node-express.Dockerfile", "unknown-ecosystem.Dockerfile"} {
		t.Run(fixture, func(t *testing.T) {
			_, first := optimize(t, fixture, BaseDistroless)

			a, err := analyzer.Parse(strings.NewReader(first))
			if err != nil {
				t.Fatal(err)
			}
			Optimize(a, Options{Base: BaseDistroless, Aggressiveness: analyzer.ConfidenceLikely})
			second := Render(a)

			if first != second {
				t.Errorf("a second pass changed the file:\n--- first ---\n%s\n--- second ---\n%s", first, second)
			}
		})
	}
}

func TestOptimize_every_runtime_stage_drops_privileges(t *testing.T) {
	for _, fixture := range []string{"go-api.Dockerfile", "node-express.Dockerfile", "java-spring.Dockerfile", "rust-cli.Dockerfile"} {
		r, out := optimize(t, fixture, BaseDistroless)
		if !r.Restructured {
			continue
		}
		if !strings.Contains(out, "USER ") {
			t.Errorf("%s: runtime stage never drops privileges:\n%s", fixture, out)
		}
	}
}

// A multi-stage file builds in one stage and ships from a minimal one, so
// looking only at the final stage reports "unrecognised" for projects whose
// language is obvious. docker-trim's own Dockerfile is the case that found this.
func TestDetectEcosystem_looks_past_a_minimal_final_stage(t *testing.T) {
	a, err := analyzer.Parse(strings.NewReader(
		"FROM golang:1.24-alpine AS builder\nWORKDIR /src\nCOPY . .\nRUN go build -o /src/bin/app .\n\n" +
			"FROM alpine:3.21\nRUN adduser -D -u 10001 app\n" +
			"COPY --from=builder /src/bin/app /usr/local/bin/app\nENTRYPOINT [\"app\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := DetectEcosystem(a); got != EcosystemGo {
		t.Errorf("ecosystem = %q, want go: the builder stage runs `go build`", got)
	}
	// Restructuring still keys off the final stage alone, and must not treat
	// this alpine runtime as a Go build to split.
	if got := buildPlanEcosystem(a); got != EcosystemUnknown {
		t.Errorf("buildPlanEcosystem = %q, want unknown for the shipping stage", got)
	}
}

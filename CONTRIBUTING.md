# Contributing

## The most valuable contribution

**A Dockerfile dtrim rewrote badly.** A rewrite that does not build, an image that starts and
then dies, a saving that turns out to be a mirage, a file dtrim mangled that it should have
left alone. There is a [bad-rewrite issue template](.github/ISSUE_TEMPLATE/bad-rewrite.yml)
for exactly this. Paste the input, paste what dtrim emitted, and say what broke.

This tool rewrites other people's builds. It only gets to keep doing that if the cases where
it gets things wrong come back.

## Documentation

| Document | What it covers |
| :--- | :--- |
| [docs/usage.md](docs/usage.md) | Flags, recipes, exit codes |
| [docs/heuristics.md](docs/heuristics.md) | What dtrim will and will not change, and why |
| [docs/architecture.md](docs/architecture.md) | The pipeline, and how to add a rule |
| [docs/library.md](docs/library.md) | The Go API |
| [docs/tracing.md](docs/tracing.md) | Runtime tracing design |

## Setup

```sh
git clone https://github.com/mkamranr/dtrim && cd dtrim
make build
make test
```

Go 1.25 or later. A Docker engine is needed only for `make integration`.

## Adding a rule

Rules live in `pkg/analyzer/rules.go`. Each is a small type implementing `Rule`; if it can
repair what it finds, it also implements `Fix`. Register it in `registry()` — that is the
only place.

Three rules that are not negotiable:

1. **Match on command words, never substrings.** Use `Commands`, `IsCmd`, `HasSubcommand`
   and `HasFlag` from `pkg/analyzer/shell.go`. `cargo build` contains `go build`; that bug
   has already shipped here once.
2. **A `Fix` must be idempotent.** `TestFix_is_idempotent` runs every fixer twice and
   requires the second pass to change nothing.
3. **A `Fix` must clear `Raw`** on every instruction it rewrites, or the emitter will print
   the original text and silently discard your change.

`docs/architecture.md` has the longer version, including how to add an ecosystem.

## Tests

| Kind | Where | What it protects |
| :--- | :--- | :--- |
| Unit | `*_test.go` beside each package | Individual rules, the parser, the base mapping |
| Round trip | `pkg/synthesizer/emit_test.go` | An untouched file comes back byte-for-byte, and output always re-parses |
| Golden | `tests/golden_test.go` | The exact Dockerfile emitted for every fixture at every base |
| Integration | `tests/integration_test.go` | The built binary: flags, exit codes, JSON shape |
| Reduction bands | `tests/reduction_test.go` | The percentages in the README, by building real images |

```sh
make test          # everything that does not need Docker
make integration   # builds real images; takes several minutes
make lint
```

**Golden files are reviewed, not regenerated.** `go test ./tests -update` rewrites them, and
a golden diff is dtrim telling you the Dockerfile it emits has changed. Read every line
before accepting it. Reviewing the goldens is how the glibc-builder-with-musl-runtime bug
was caught before release.

## Commits and pull requests

Conventional commit subjects (`feat:`, `fix:`, `perf:`, `docs:`, `test:`, `ci:`, `build:`),
lowercase, no trailing period. Write a body explaining *why*, with the concrete evidence that
led you there — the reasoning is the part that is hard to reconstruct later.

Before opening a pull request:

```sh
make lint && make test
```

and, if you changed the synthesizer, `make integration`.

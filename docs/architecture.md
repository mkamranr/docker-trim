# Architecture

```
  Dockerfile ──► AST parser ──► rule engine ──► synthesizer ──► emitter ──► Dockerfile.trimmed
                 (buildkit)     (DT001…)        (ecosystem       (lossless)         │
                                                 + base map)                        │
                                                                                    ▼
  Image ───────► layer inspector ──► package inventory ──► attack surface ──►    report
                 (pure Go, streams   (dpkg / apk)          (embedded ruleset)   (text/JSON/
                  every layer tar)         │                                     markdown)
                                           ▼                                        │
                 --tracer proc ──► run it and sample /proc ──► what went unused ─────┤
                                  (no capabilities needed)                          │
                                                                                    │
                                          --verify ──► build both, measure, start ──┘
```

Usage attribution is the one place two halves of the pipeline meet: the trace produces
paths, the package inventory says who owns them, and `analyzer.AttributeUsage` joins the two.
That is why `--tracer` switches image inspection to `InspectImageWithOwnership`, which reads
the per-package file lists that a plain size report does not need.

## Packages

| Package | Responsibility |
| :--- | :--- |
| `main` | Flags only. Maps them onto a `docker-trim.Config` and renders the result. No logic. |
| `pkg/docker-trim` | The library surface and the pipeline driver. Re-exports the PRD's types. |
| `pkg/analyzer` | Dockerfile parsing, the rule registry, layer inspection, package databases. |
| `pkg/synthesizer` | Ecosystem detection, base mapping, the multi-stage transform, the emitter. |
| `pkg/security` | Attack-surface scoring from an embedded ruleset. |
| `pkg/reporter` | Terminal output, JSON, unified diff, Markdown. |
| `pkg/tracer` | Docker engine operations: build, measure, start, and the `/proc` sampler that observes a running container. |

The dependency graph runs one way: `analyzer` depends on nothing of ours, `synthesizer`
depends on `analyzer`, and `docker-trim` depends on all of them.

## Where the PRD's types live

The specification declares `DockerfileAST`, `Instruction`, `TraceManifest` and
`OptimizationResult` in `package main`. They are defined in `pkg/analyzer`, the leaf every
stage can import, and re-exported from `pkg/docker-trim` as aliases under the specified names. The
declared interface is preserved; the mechanism underneath is the one that avoids an import
cycle.

## Lossless rendering

Each `Instruction` carries three things the parser does not keep on its own:

- `Raw`, the exact source text spanning `Line` to `EndLine`. buildkit's `Original` collapses
  line continuations and drops heredoc bodies; slicing the source does not.
- `Lead`, the verbatim text between the previous instruction and this one — comments, blank
  lines, and the spacing between them.
- `Exec`, whether the instruction used the JSON array form.

The emitter writes `Raw` when it is present and renders from parts only when a rule cleared
it. So an instruction nobody touched comes back byte-for-byte, and `--optimize` on an
already-clean file produces an empty diff instead of a reformatting storm.

Two tests enforce this: `TestRender_round_trips_an_untouched_file_exactly` and
`TestRender_output_reparses`.

## Adding a rule

1. Write a type in `pkg/analyzer/rules.go` implementing `Rule`: `ID`, `Title`, `Severity`,
   `Confidence`, and `Check`. If it can repair what it finds, also implement `Fix` and
   return the findings it resolved.
2. Append it to `registry()`. That is the only registration point.
3. Use the helpers in `pkg/analyzer/shell.go` — `Commands`, `IsCmd`, `HasSubcommand`,
   `HasFlag`, `InstalledPackages` — rather than matching substrings. `cargo build` contains
   `go build`; that mistake has already been made once here.
4. A `Fix` must be idempotent. `TestFix_is_idempotent` runs every fixer twice and requires
   the second pass to change nothing.
5. A `Fix` must clear `Raw` on any instruction it rewrites, so the emitter re-renders it.
6. Add a test. Then run `go test ./tests -update` and **read the golden diff line by line**
   before accepting it.

## Adding an ecosystem

1. Add the constant and its detection to `DetectEcosystem` in `pkg/synthesizer/bases.go`,
   matching on the command word.
2. Write a `plan<Name>` function that decides the runtime base per `--base`, the artifacts to
   copy, and any builder preparation. Set `Supported = false` with a `Reason` when you cannot
   determine what the build produces — declining is always better than guessing.
3. Check the runtime base's published entrypoint before assuming the original `CMD` still
   works on it. Set `ReplaceCommand` when the base supplies its own.
4. Add a fixture in `tests/fixtures`, regenerate the goldens, and review them.

## Performance

Dockerfile parsing and rewriting take milliseconds. Image inspection is bound by the Docker
daemon's export rate, about 25 MB/s on Docker Desktop; the layer walk itself is roughly 30 ms
per layer. Reading from a registry avoids the export. The numbers and the missed target are
recorded in the changelog.

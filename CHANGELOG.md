# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- **The eBPF backend**, for the same fidelity as `ptrace` at lower overhead, on hosts whose
  kernel exposes BTF.
- **`trivy` and `grype` adapters**, used automatically when either is on `PATH`, for
  ecosystems OSV does not cover and for language dependencies rather than OS packages.
- **rpm package inventory**, so RHEL, Fedora and Amazon Linux images get the same package
  reporting that Debian and Alpine images already get.
- Merging consecutive `RUN` instructions (DT012 currently reports them without fixing them).

## [0.5.0] - 2026-09-25

### Added

- **`--osv`**, which looks every installed package up at osv.dev and reports what is known to
  affect it. The report was printing `n/a` for CVEs since 0.1.0 because dtrim had no
  vulnerability data and would not guess; now it has some.

  Advisories become findings, so `--fail-on` gates on them without a second threshold: a
  pipeline that already refuses a Dockerfile shipping a shell can refuse one shipping a
  critical CVE, and says so the same way. On a real Debian 13 image: 18 advisories across 87
  packages, 4 high and 10 medium, in 16 seconds.

  Severity is computed from the advisory's CVSS v3 vector using the formula in the
  specification, including its own rounding rule, and checked against scores published by
  NVD. An advisory with no vector dtrim can read is counted and listed as `unknown` and
  cannot trip `--fail-on`: banding it would be a guess, and a guess either fires a gate for
  nothing or stays quiet when it should not.

  This is the only part of dtrim that sends anything anywhere, which is why it is opt-in. The
  query carries the name and version of every package in the image.

- **A corpus survey** (`scripts/fetch-corpus.sh` and `tests/corpus_test.go`). The rest of the
  suite runs against fixtures this project wrote, which only contains shapes dtrim was
  designed for. This runs the same guarantees against Dockerfiles written by other people.

  Across 66 real files at all three bases, 195 rewrites in total: no panics, no unparseable
  output, and no file altered when dtrim had nothing to change. The two properties the README
  claims survive contact with strangers' Dockerfiles.

  It also measured what the rewrite actually applies to, which was less than the README
  implied: **23% restructured**, while 50% already build in stages, 17% build nothing at all
  and only package a binary CI produced, and 9% would land on the base they started from. The
  README now states this, along with the corpus's own bias.

### Known limitations

- **`--osv` covers operating-system packages, not language dependencies.** The packages in
  `requirements.txt` or `package.json` are not looked up, so a clean report is not a clean
  image. `trivy` and `grype` adapters are planned for that.
- **Debian, Ubuntu and Alpine only.** Any other distribution is refused rather than queried,
  because a lookup in the wrong ecosystem returns nothing and looks exactly like a clean
  image.
- **It reports the current image, not a before and after.** `OriginalCVEs` is populated;
  `RemainingCVEs` needs the trimmed image built and inspected, which is a `--verify`
  composition that is not wired up yet.
- **The answer moves.** The advisory database changes daily, so two runs of the same image
  can differ for reasons that have nothing to do with the Dockerfile.

## [0.4.0] - 2026-09-25

### Added

- **The tracer now informs the rewrite.** They were two halves that did not talk: dtrim could
  see which packages went untouched and could write a minimal Dockerfile, but could not write
  one that used what it saw.

  A trace knows which binaries a program actually executes, so dtrim now checks the rewrite
  against it and reports a **runtime gap** when the chosen base will not contain something the
  program ran. This is the failure dtrim is most capable of causing: a Go service that shells
  out, rewritten onto distroless, goes from 909 MB to 4.8 MB and then prints
  `fork/exec /bin/sh: no such file or directory`. It builds cleanly, so nothing catches it
  until production. An integration test builds that broken image deliberately and confirms
  dtrim predicted it.

- **`--prune-unused`** drops packages a trace never saw used from the install commands that
  name them. It removes them from the install rather than purging them afterwards, because a
  purge in a later layer makes the image bigger while looking like a cleanup, which is what
  dtrim reports as DT002 in other people's files. It only touches a stage that ships: a
  runtime trace says nothing about what building the image required, so pruning a builder on
  that evidence would break the build, and a single-stage file's install serves both.

### Changed

- **`synthesizer.Optimize` takes an options struct** rather than three positional arguments,
  so trace data can reach it. A library caller passing `(a, base, confidence)` becomes
  `(a, synthesizer.Options{Base: base, Aggressiveness: confidence})`.

### Known limitations

- **Runtime gaps are only as good as the workload.** dtrim can only warn about a binary it
  saw run. A code path the trace never reached can still shell out to something the new base
  lacks, so `--trace` with a representative workload matters more here than anywhere else.
- **`--prune-unused` applies to a narrow case**: the final stage of a file that already builds
  in stages. Builders and single-stage files are refused, for reasons in
  `docs/heuristics.md`. Packages pulled in as dependencies, rather than named in the
  Dockerfile, cannot be dropped this way either.

## [0.3.1] - 2026-09-25

### Fixed

- **`--tracer`'s help text no longer says ptrace is planned.** It shipped in 0.3.0 while the
  flag description still described it as future work, so the binary contradicted its own
  documentation. The test meant to catch this only required the word "planned" to appear on
  the line, which "ptrace and ebpf are planned" satisfied; it now requires every backend to
  be named and checks that ptrace is not among the ones called planned.

## [0.3.0] - 2026-09-25

### Added

- **The `ptrace` tracing backend** (`--tracer ptrace`). Where the sampler takes snapshots and
  can miss whatever happens between two of them, this stops the traced process at every
  syscall and records `execve` and `openat` on the way out, so a call that failed is never
  counted as a use. The same Python command six times: `proc` observed 19 to 23 files and
  caught the dynamically loaded `_sqlite3` in four runs of six; `ptrace` observed 53 files
  and caught it in all six. It costs `CAP_SYS_PTRACE`, an unconfined seccomp profile, and
  about twice the runtime on a syscall-heavy workload, which is why `proc` stays the default.

  Entry and exit stops are distinguished with `PTRACE_GET_SYSCALL_INFO` rather than by
  alternating, because alternating breaks the moment a process forks and silently drops
  everything the child touches. Asking the kernel also means no per-architecture register
  decoding: the same code is correct on x86-64 and arm64.

### Fixed

- **Library paths are reconciled with the package database.** A traced open records what the
  loader asked for, usually `/lib/x86_64-linux-gnu/libc.so.6`, while dpkg records the same
  file under `/usr/lib/...` because `/lib` is a symlink. Every library looked unowned and
  every library package looked removable, which is the most dangerous way this could be
  wrong.

### Known limitations

- **ptrace is not free.** It needs `CAP_SYS_PTRACE` and an unconfined seccomp profile, which
  some environments will not grant, and costs roughly twice the runtime on a syscall-heavy
  workload. `proc` remains the default for exactly that reason.
- **It needs Linux 5.3 or later**, for `PTRACE_GET_SYSCALL_INFO`. An older kernel is detected
  and reported, pointing at `--tracer proc`.
- **A trace still only covers what you exercised.** ptrace removes the sampling race, not the
  need for a representative workload. dtrim still removes nothing on its own.

## [0.2.0] - 2026-09-25

### Added

- **Runtime tracing** (`--tracer proc`, `--trace`, `--trace-timeout`). dtrim builds an
  ephemeral copy of the image with a sensor wrapping its entrypoint, runs it, and samples
  `/proc/*/exe`, `/proc/*/maps` and `/proc/*/fd` to record every binary that ran and every
  library that loaded. Those files are attributed back to the packages that installed them
  through the dpkg and apk databases, so the report says how many packages were exercised and
  what was never touched. On a 599MB Python image: 9 of 189 packages used, 139 never touched,
  484MB of them, led by gcc, git, vim and perl.

  The sensor needs no capabilities, no seccomp changes and no kernel features, which is what
  makes it work on Docker Desktop and on hardened runners. Its source is embedded and
  compiled inside the ephemeral build, so it is always the right architecture and no binary
  lives in the repository. See [docs/tracing.md](docs/tracing.md).

  Removal stays manual. dtrim reports what to consider dropping; it does not delete packages
  on the strength of one trace.

- **`--fail-on <severity>`**, so a pipeline can reject a Dockerfile that bakes in a
  credential or ships a shell, without piping the JSON report through `jq`. Only unfixed
  findings count, and the output names the rules responsible.

### Changed

- **Only dpkg priority `required` counts as structural**, not `important`. Debian's
  `important` means "expected on a Unix-like system" and covers `vim-tiny`, `nano`, `less`
  and `procps`, all of which a container can lose; treating them as untouchable hid most of
  what a trace is for. Priority was never what protected the packages that matter anyway:
  `libc6` is priority `optional`, and the loader, trust store and time zone data are excluded
  by name instead.

- **Exit code `1` now means "findings met the `--fail-on` threshold".** Previously there
  were only two codes; `2` still means dtrim itself could not run. Keeping them apart is
  what lets a pipeline tell a bad Dockerfile from a broken tool. Nothing changes for a run
  without `--fail-on`.

### Fixed

- **DT010 no longer flags a base image that already drops privileges.** An image whose tag
  says `nonroot`, as Google's distroless and Chainguard's images do, sets a non-root user in
  the image itself, so a Dockerfile using one needs no `USER` line. dtrim was reporting that
  as "container runs as root" at high severity, which meant flagging the exact arrangement it
  recommends everywhere else, and meant dtrim's own Dockerfile failed its own `--fail-on
  high` gate. An explicit `USER root` is still reported, since that overrides whatever the
  base set.

### Known limitations

- **A trace is evidence, not proof.** Sampling `/proc` races with short-lived processes: the
  same 40ms command traced six times caught between three and ten dynamically loaded Python
  modules, and a shorter sampling interval does not help. What is reliable is anything mapped
  for the life of the process, which is the interpreter, everything it links against, and
  every long-lived worker. dtrim reports how long the traced command ran and warns when that
  was under a second, and it never removes a package on the strength of a trace.
- **Only the `proc` backend exists.** `--tracer ptrace` and `--tracer ebpf` are accepted and
  rejected, naming the backend that works.
- **CVE counts are still unavailable.** `--fail-on` gates on dtrim's own findings, not on
  vulnerabilities, because dtrim has no vulnerability data to gate on yet.

## [0.1.0] - 2026-09-22

First release.

### Added

- **Dockerfile analysis.** A buildkit-based parser produces the PRD's `DockerfileAST`, and a
  registry of fifteen rules (`DT001`–`DT015`) reports cache bloat, missing cleanup, floating
  base tags, root execution, shell and network tooling in production images, and
  credential-shaped build arguments. Rules that can repair what they find do so, gated by
  `--aggressiveness`.
- **Multi-stage synthesis.** Single-stage builds for Go, Node, Python, Rust and Java are
  rewritten into a builder stage and a minimal runtime stage on distroless, alpine or
  scratch. Artifacts are copied to the same absolute path they had in the builder, which is
  what lets `WORKDIR`, `ENV`, `EXPOSE`, `ENTRYPOINT` and `CMD` carry over untouched.
- **Image and layer inspection.** Layers are streamed and accounted for in process, with no
  dependency on skopeo, dive or `docker save` parsing by hand. Reports build caches,
  documentation, locales, bytecode, compiler toolchains, bytes written and then overwritten,
  bytes deleted by a later layer but still shipped, setuid binaries, and the installed
  package inventory from dpkg or apk.
- **Attack-surface scoring** from an embedded ruleset, comparing the original against the
  rewrite.
- **`--verify`**, which builds both Dockerfiles, measures both images, and starts the trimmed
  one. Sizes are labelled `measured` only when they came from here, and `estimated` otherwise.
- **Reports** as terminal output, a versioned JSON document (`--quiet`), a unified diff, and
  Markdown for a pull request comment.
- Measured reductions of 99.0% (Go), 90.5% (Node) and 77.7% (Python) on the sample projects
  in `tests/projects`, enforced as floors by `tests/reduction_test.go`.

### Known limitations

- **The `< 1.5 s` target holds for Dockerfile analysis but not for image inspection.**
  Analysing and rewriting a synthetic 2,004-line Dockerfile takes **0.13 s** at about 24 MB
  of peak memory (`scripts/bench-large.sh`, macOS, Intel i7-6820HQ), so real files are
  effectively instant. Inspecting a *built image* is another matter: it is bound by how fast
  the Docker daemon can export the image, about **25 MB/s** on Docker Desktop for macOS —
  roughly 10 seconds for a 260 MB image and minutes for a multi-gigabyte one. The layer walk
  itself is around 30 ms per layer; the export is all of the rest. Reading from a registry
  instead of the local daemon skips the export and is faster.
- **No CVE counts.** The report says `n/a` rather than printing a vulnerability number dtrim
  did not measure. Attack-surface metrics are reported instead.
- **No rpm support.** RHEL-family images are detected and reported as unsupported for package
  inventory; size and layer analysis are unaffected.
- **Python does not reach distroless.** `gcr.io/distroless/python3-debian12` ships a different
  CPython patch release than the `python:3.x-slim` images, and Python resolves dependencies
  against the exact interpreter that runs pip. A requirement guarded by
  `python_full_version < "3.11.3"` is skipped on the builder and then required at runtime,
  which produces an image that builds, starts, and dies on import. dtrim keeps Python on the
  interpreter it built against and takes its saving from the build toolchain instead.
- **Rust on alpine is declined** unless the build already targets
  `x86_64-unknown-linux-musl`, rather than silently producing a glibc binary that cannot run.
- **`--verify` starting an image is evidence, not proof.** A container that survives the
  fifteen-second window has not crashed; it has not been exercised. A service that needs a
  database it cannot reach will exit, and dtrim says so without claiming the rewrite is at
  fault.
- **The Go toolchain requirement is 1.25, above the PRD's 1.22.** The buildkit Dockerfile
  parser needs 1.23, and `golang.org/x/sys` (pulled in transitively by the container
  registry client) needs 1.25.

[Unreleased]: https://github.com/mkamranr/dtrim/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/mkamranr/dtrim/releases/tag/v0.5.0
[0.4.0]: https://github.com/mkamranr/dtrim/releases/tag/v0.4.0
[0.3.1]: https://github.com/mkamranr/dtrim/releases/tag/v0.3.1
[0.3.0]: https://github.com/mkamranr/dtrim/releases/tag/v0.3.0
[0.2.0]: https://github.com/mkamranr/dtrim/releases/tag/v0.2.0
[0.1.0]: https://github.com/mkamranr/dtrim/releases/tag/v0.1.0

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`--fail-on <severity>`**, so a pipeline can reject a Dockerfile that bakes in a
  credential or ships a shell, without piping the JSON report through `jq`. Only unfixed
  findings count, and the output names the rules responsible.

### Changed

- **Exit code `1` now means "findings met the `--fail-on` threshold".** Previously there
  were only two codes; `2` still means dtrim itself could not run. Keeping them apart is
  what lets a pipeline tell a bad Dockerfile from a broken tool. Nothing changes for a run
  without `--fail-on`.

### Planned for 0.2

- **Runtime tracing** (`--trace`, `--tracer`). A static sensor injected into the container
  records which binaries and shared libraries the process actually loads, so unused packages
  can be removed with evidence rather than heuristics. The `proc` backend samples
  `/proc/*/exe`, `/proc/*/maps` and `/proc/*/fd` and needs no added capabilities, which is
  what makes it work on Docker Desktop; `ptrace` and `ebpf` follow for exact `openat` data on
  hosts that can support them. See [docs/tracing.md](docs/tracing.md).
- **Real CVE counts** (`--osv`). Query api.osv.dev from the package inventory dtrim already
  builds, and use `trivy` or `grype` automatically when either is on `PATH`.
- **rpm package inventory**, so RHEL, Fedora and Amazon Linux images get the same package
  reporting that Debian and Alpine images already get.
- Merging consecutive `RUN` instructions (DT012 currently reports them without fixing them).

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
- **No runtime tracing.** `--trace` and `--tracer` are accepted and rejected with a pointer
  here rather than silently doing nothing. Everything in 0.1 is static analysis.
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

[Unreleased]: https://github.com/mkamranr/dtrim/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mkamranr/dtrim/releases/tag/v0.1.0

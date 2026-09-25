<div align="center">

# dtrim

**Shrink container images and cut their attack surface, with numbers you can check.**

[![CI](https://github.com/mkamranr/dtrim/actions/workflows/ci.yml/badge.svg)](https://github.com/mkamranr/dtrim/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/mkamranr/dtrim)](https://github.com/mkamranr/dtrim/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8)](https://go.dev)
[![Size](https://img.shields.io/badge/binary-~14MB-lightgrey)](https://github.com/mkamranr/dtrim/releases)

[Install](#install) · [What it does](#what-it-actually-does) · [Measured reduction](#measured-reduction) · [Usage](#usage) · [Docs](docs/) · [Contributing](CONTRIBUTING.md)

</div>

---

A `node:18` application image is about 1.2 GB. Roughly 100 MB of that is the application;
the rest is a compiler toolchain, a package manager, dev dependencies, apt's index, and a
shell. You pay for it on every CI pull, in registry storage, and in the fact that anyone
who reaches your container finds `curl`, `bash` and `gcc` waiting for them.

`dtrim` reads the Dockerfile, works out what the build actually produces, and rewrites it
as a multi-stage build whose final stage contains the application and nothing else. Then,
if you ask it to, it builds both images and tells you what really changed.

```console
$ dtrim --file ./Dockerfile --optimize --verify
[dtrim] Analyzed ./Dockerfile (Node.js, single stage)
[dtrim] Building the original image to measure it...
[dtrim] Building the trimmed image...
[dtrim] Created Multi-Stage Dockerfile -> Dockerfile.trimmed
[dtrim] Built both images; trimmed image still running after 15s
-------------------------------------------------------------
Original Image Size : 1.2 GB    (node:18)
Optimized Image Size: 118 MB    (gcr.io/distroless/nodejs18-debian12:nonroot)
Size Reduction      : -90.5% (measured)
Attack Surface      : Removed 4 unused OS packages, 2 shells, 2 package managers,
                      1 compiler, 2 network tools, 1 developer tool
-------------------------------------------------------------
```

```diff
-FROM node:18
+FROM node:18 AS builder
 WORKDIR /app
-RUN apt-get update && apt-get install -y curl wget git build-essential
+RUN apt-get update \
+ && apt-get install --no-install-recommends -y curl wget git build-essential \
+ && rm -rf /var/lib/apt/lists/*
 COPY . .
-RUN npm install
+RUN npm install \
+ && npm cache clean --force
 RUN npm run build
-CMD ["node", "dist/server.js"]
+# dtrim(DT103): added by dtrim so the runtime stage can be minimal
+RUN npm prune --omit=dev
+
+# dtrim(DT100): runtime stage carries the application and nothing else
+FROM gcr.io/distroless/nodejs18-debian12:nonroot
+WORKDIR /app
+# dtrim(DT101): only the build output crosses the stage boundary
+COPY --from=builder --chown=nonroot:nonroot /app /app
+# dtrim(DT010): drop privileges before the process starts
+USER nonroot:nonroot
+CMD ["dist/server.js"]
```

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/mkamranr/dtrim/main/install.sh | sh
```

<details>
<summary><b>Other ways to install</b></summary>

```sh
# Homebrew
brew install mkamranr/tap/dtrim

# Go
go install github.com/mkamranr/dtrim@latest

# Docker
docker run --rm -v "$PWD:/work" -w /work ghcr.io/mkamranr/dtrim:latest --analyze-only

# From source
git clone https://github.com/mkamranr/dtrim && cd dtrim && make build
```

The install script honours `DTRIM_VERSION` to pin a release and `DTRIM_BIN_DIR` to choose
where the binary lands.

</details>

## What it actually does

| It finds | And does this |
| :--- | :--- |
| A single-stage build with a toolchain in it | Splits it into a builder stage and a runtime stage, copying only the build output across |
| `apt-get install` with no `--no-install-recommends` | Adds the flag |
| apt's package index left in the layer | Appends `rm -rf /var/lib/apt/lists/*` to the *same* `RUN`, because a later one cannot shrink an earlier layer |
| `pip install` without `--no-cache-dir`, `apk add` without `--no-cache` | Adds them |
| `npm install` shipping dev dependencies and its cache | Adds `npm cache clean --force`, and prunes dev dependencies before the copy |
| A container running as root | Injects `USER nonroot` or `USER 10001:10001` before the entrypoint |
| `curl`, `wget`, `nc`, `git`, `gcc`, `sudo` in the final image | Reports each one and what it gives an attacker; the runtime stage leaves them behind |
| A credential-shaped `ENV` or `ARG` | Reports it: every layer keeps it, so `docker history` reveals it |
| A running container (`--tracer`) | Runs it and records what it actually touches, then attributes those files back to the packages that installed them, so you can see what was never used. `proc` samples `/proc` and needs no privileges; `ptrace` observes every syscall and misses nothing |
| A built image | Streams its layers and reports where the bytes went: caches, docs, locales, bytecode, files written then overwritten, files deleted but still shipped |

When a trace is available, it also checks its own work. A Go service that shells out, rewritten
onto distroless, goes from 909 MB to 4.8 MB and then prints
`fork/exec /bin/sh: no such file or directory`. It builds cleanly, so nothing catches it until
production — unless something watched the program run first:

```
Runtime gaps
  the trace saw these run, and the new base will not have them
  ! The trace saw `/bin/sh` executed, but a distroless base has no shell and no general
    userland, so that binary will not exist there.
```

It also knows when to do nothing. A Dockerfile that already builds in stages is left alone,
because the author has already made those decisions. A build it cannot identify does not
get a builder stage invented for it.

### How often does the rewrite apply?

Against 66 real Dockerfiles — 24 from projects like Grafana, Airflow, Immich and the official
images, the rest from one developer's machine — dtrim restructured **23%** of them. The other
three quarters it declined, and the reasons matter more than the number:

| | |
| --: | :--- |
| 50% | already build in multiple stages, so there is nothing to restructure |
| 17% | build nothing at all: they copy a binary that CI produced and package it |
| 9% | would land on the same base they started from, saving nothing |
| 23% | **restructured** |

So the multi-stage rewrite is the right answer for roughly one Dockerfile in four. For the
other three, dtrim is a linter and an analyser: it still applies the cleanups, reports where
an image's bytes and attack surface come from, and with `--tracer` tells you which installed
packages nothing ever touches.

That corpus is small and skewed — two thirds of it is one person's projects, which makes it
Python-heavy. Reproduce it with `scripts/fetch-corpus.sh` and check your own numbers. What
did hold across all 66 files, at every base, was the part that matters: no crashes, no
unparseable output, and no file changed when dtrim had nothing to change.

## Measured reduction

Three sample projects live in [`tests/projects`](tests/projects). `make integration` builds
each one twice, measures both images, and starts the trimmed one. The percentages below are
enforced as floors by [`tests/reduction_test.go`](tests/reduction_test.go), so this table
cannot quietly drift away from reality.

| Project | Before | After | Reduction | Runtime base |
| :--- | ---: | ---: | ---: | :--- |
| Go HTTP service | 966 MB | 9.8 MB | **−99.0%** | `distroless/static-debian12` |
| Node/Express service | 1.18 GB | 112 MB | **−90.5%** | `distroless/nodejs18-debian12` |
| Python/Flask service | 571 MB | 128 MB | **−77.7%** | `python:3.12-slim` |

Measured on 2026-09-22 with Docker 24.0.6. Your numbers will differ; run `--verify` and get
your own.

The Python figure is the honest one to look at. Its saving comes from leaving the build
toolchain behind, not from changing base image: dtrim deliberately keeps Python on the same
interpreter it built against, because moving an installed dependency tree onto a different
CPython build is how you get an image that starts and then dies on import.
[`docs/heuristics.md`](docs/heuristics.md) explains why.

## Usage

```
dtrim [OPTIONS] [DOCKERFILE_PATH or IMAGE_NAME]
```

| Flag | Short | Default | Description |
| :--- | :--- | :--- | :--- |
| `--file` | `-f` | `Dockerfile` | Dockerfile to parse and optimize |
| `--image` | `-i` | | Built image to inspect, from the local daemon or a registry |
| `--optimize` | | `false` | Rewrite the Dockerfile and write the result |
| `--output` | `-o` | `Dockerfile.trimmed` | Where to write the rewritten Dockerfile |
| `--base` | `-b` | `distroless` | Target runtime base: `distroless`, `alpine`, `scratch` |
| `--verify` | | `false` | Build both images, measure them, and start the trimmed one |
| `--analyze-only` | | `false` | Report only; never writes anything |
| `--fail-on` | | | Exit 1 when a finding of this severity or worse survives |
| `--prune-unused` | | `false` | Drop packages a trace never saw used; needs `--tracer` |
| `--aggressiveness` | | `likely` | How much to change: `safe`, `likely`, `aggressive` |
| `--quiet` | `-q` | `false` | Emit the JSON report on stdout and nothing else |
| `--markdown` | | `false` | Emit a report for a pull request comment |
| `--verbose` | | `false` | Show every finding, and the underlying build output |
| `--no-diff` | | `false` | Skip the diff |
| `--no-color` | | `false` | Disable colour (also honours `NO_COLOR`) |
| `--trace` | `-t` | | Command to run inside the container while tracing |
| `--tracer` | | `none` | Tracing backend: `proc` (no privileges) or `ptrace` (exact) |
| `--trace-timeout` | | `30s` | How long to let a traced container run |
| `--osv` | | `false` | Real CVE lookup — not implemented yet |

Exit codes: `0` clean, `1` when `--fail-on` was given and something met the threshold, `2`
when dtrim itself could not run. Full details in [`docs/usage.md`](docs/usage.md).

As a CI gate:

```sh
dtrim --analyze-only --fail-on critical    # refuse a baked credential
dtrim --analyze-only --fail-on high        # also refuse a shell, or running as root
```

## How it works

```
  Dockerfile ──► AST parser ──► rule engine ──► synthesizer ──► emitter ──► Dockerfile.trimmed
                 (buildkit)     (DT001…)        (ecosystem       (lossless)         │
                                                 + base map)                        │
                                                                                    ▼
  Image ───────► layer inspector ──► package inventory ──► attack surface ──►    report
                 (pure Go, streams   (dpkg / apk)          (embedded ruleset)   (text/JSON/
                  every layer tar)         │                                     markdown)
                                           ▼                                        │
                 --tracer ──────► run it and watch ──────────► what went unused ─────┤
                                  (proc samples /proc,                              │
                                   ptrace sees every syscall)                       │
                                                                                    │
                                          --verify ──► build both, measure, start ──┘
```

Two properties hold, and are tested:

- **Whatever dtrim emits parses.** Every fixture, at every base, is re-parsed after rewriting.
- **A file dtrim did not change comes back byte-for-byte.** Instructions carry their original
  source text, so only what a rule actually rewrote is re-rendered.

And one rule it will not break: **dtrim never prints a size it did not measure.** Without
`--verify` the numbers are labelled `estimated`, because a size that came from a guess is
worse than no size at all.

## Contributing

The most useful thing you can send is a Dockerfile dtrim rewrote badly. There is an issue
template for exactly that. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
Contributions are accepted under the same terms.

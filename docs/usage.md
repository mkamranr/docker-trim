# Usage

```
docker-trim [OPTIONS] [DOCKERFILE_PATH or IMAGE_NAME]
```

Linked into `~/.docker/cli-plugins/docker-trim` it is also `docker trim`, with identical
flags — the Docker CLI treats any executable named `docker-<name>` there as a subcommand:

```sh
mkdir -p ~/.docker/cli-plugins
ln -sf "$(command -v docker-trim)" ~/.docker/cli-plugins/docker-trim
docker trim --image myapp:latest --osv
```

A single positional argument is read as a Dockerfile if it is a file on disk or its name
contains `dockerfile`, and as an image reference otherwise. So `docker-trim ./Dockerfile` and
`docker-trim myapp:latest` both do the obvious thing.

With no arguments at all, docker-trim analyzes `./Dockerfile`.

## Flags

### `--file`, `-f` (default `Dockerfile`)

The Dockerfile to parse. Analysis is read-only unless `--optimize` is also given.

### `--image`, `-i`

An image to inspect. The local Docker daemon is tried first, so an image you just built and
never pushed works; a reference the daemon does not have is fetched from its registry.

```console
$ docker-trim --analyze-only myapp:latest
```

Inspection streams every layer and is bound by how fast the daemon can export the image —
about 25 MB/s on Docker Desktop. Reading from a registry skips that export and is faster.

### `--optimize`

Rewrite the Dockerfile and write the result to `--output`. Without it, docker-trim only reports.

If the rewrite would be identical to the input, nothing is written and docker-trim says so, rather
than leaving a duplicate file behind.

### `--output`, `-o` (default `Dockerfile.trimmed`)

Where the rewritten Dockerfile goes. Parent directories are created.

### `--base`, `-b` (default `distroless`)

The runtime base for the final stage: `distroless`, `alpine` or `scratch`. docker-trim maps this
onto a concrete image per ecosystem and declines combinations that cannot work —
[heuristics.md](heuristics.md) lists which and why.

### `--verify`

Build the original and the trimmed Dockerfile against the same context, measure both, and
start the trimmed one for fifteen seconds.

This is what turns an estimate into a number worth quoting. Without it, sizes are labelled
`estimated`. It needs a working Docker engine and takes as long as two builds.

A container that survives the window has not crashed. It has not been exercised, and docker-trim
does not claim otherwise. A service that needs a database it cannot reach will exit; docker-trim
reports that and tells you how to tell it apart from a packaging failure.

### `--analyze-only`

Report and change nothing, ever. It conflicts with `--verify`, which has to build.

### `--aggressiveness` (default `likely`)

`safe`, `likely` or `aggressive`. Sets the ceiling on which rules may repair what they find;
everything still reports. See [heuristics.md](heuristics.md).

### `--quiet`, `-q`

Emit the JSON report on stdout and nothing else, so it can be piped. The shape is versioned
by `schemaVersion`.

```console
$ docker-trim --analyze-only myapp:latest --quiet | jq '.image.categories'
$ docker-trim --analyze-only --quiet | jq -r '.findings[] | select(.severity=="critical") | .title'
```

### `--markdown`

A report shaped for a pull request comment: the size table, what was applied, what is still
worth fixing, and the diff in a collapsed block.

### `--verbose`

Show every finding rather than the top eight, and stream the underlying `docker build`
output during `--verify` instead of a status line.

### `--fail-on`

Exit `1` when a finding of the given severity or worse survives: `info`, `low`, `medium`,
`high` or `critical`. Without it, docker-trim reports and exits `0`, because a report is not a
failure unless you asked for one.

Only unfixed findings count. Something `--optimize` repaired is no longer in the file you
are about to build, so it does not fail the gate.

```console
$ docker-trim --analyze-only --fail-on high
...
FAIL 6 findings at high or above: DT011, DT010
$ echo $?
1
```

The output names the rules responsible, so a red pipeline explains itself without a re-run.

### `--no-diff`, `--no-color`

Skip the diff; disable colour. Colour is also disabled when `NO_COLOR` is set or stdout is
not a terminal.

### `--tracer`, `--trace`, `--trace-timeout`

Run the image and record what it actually uses.

| Backend | Needs | Use it when |
| :--- | :--- | :--- |
| `proc` | nothing | The default. Works on Docker Desktop, hardened runners, anywhere. |
| `ptrace` | `CAP_SYS_PTRACE`, unconfined seccomp | The answer has to be exact: before removing anything, or when two `proc` runs disagree. |
| `ebpf` | — | Not implemented. |

`ptrace` observes every successful `execve` and `openat` rather than sampling, so it sees
roughly 2.3x more and returns the same answer every run. It costs about twice the runtime on
a syscall-heavy workload, and needs privileges docker-trim applies only to the throwaway container
it builds for the trace. See [tracing.md](tracing.md) for the measurements.

```console
$ docker-trim --image myapp:latest --tracer proc --trace "pytest -q"
Runtime trace
  Observed            : 45 files, 2 binaries, 39 shared libraries across 2 processes, 42 samples
  Packages exercised  : 9 of 189
  Never touched       : 139 packages, 484 MB if removed
```

`--trace` is the workload, run through `/bin/sh -c` so a pipe or a quoted argument survives.
Without it, the trace covers only what the container does on startup, which is usually not
enough to conclude anything. `--trace-timeout` (default 30s) caps the run; a server never
exits on its own, so tracing one always ends there, and that is the normal path rather than
an error.

Tracing needs `--image`. It builds an ephemeral copy of that image, which takes a moment the
first time.

**Read the coverage line before acting on the unused list.** Sampling races with short-lived
processes, so docker-trim reports how long the command ran and says so when that was under a
second. `docs/heuristics.md` and [tracing.md](tracing.md) explain what it can and cannot see.
Removal is left to you: docker-trim reports what to consider dropping and deletes nothing.

### `--compare`

Measure a second image against the first, so the report shows what a rewrite removed rather
than only what the original has. Needs `--osv`.

```console
$ docker-trim --image myapp:v1 --osv --compare myapp:v2
Vulnerabilities     : 188 -> 34  -81.9% (199 and 97 packages checked)
```

`--osv --verify` does the same automatically against the image it just built, so a single
command reports both reductions:

```console
Size Reduction      : -77.7% (measured)
Vulnerabilities     : 188 -> 34  -81.9% (199 and 97 packages checked)
```

Advisories in the compared image are **informational**. `--fail-on` keeps gating on the image
named by `--image`: an advisory present in both would otherwise count twice, and one the
rewrite removed would still fail the build, which punishes the improvement.

An image whose packages docker-trim cannot read reports the plain count and says why, rather than a
reduction. A `scratch` image contains nothing enumerable, and that is not the same as
containing nothing vulnerable.

### `--prune-unused`

Drop packages a trace never saw used from the install commands that name them. Needs
`--tracer`, because without evidence there is nothing to act on.

It applies only to the final stage of a file that already builds in stages. A builder is
never touched: a runtime trace says nothing about what compiling the image required, and a
single-stage file's install serves both. `docs/heuristics.md` explains why, including why
this drops packages from the install rather than purging them later.

Pair it with `--verify`, which builds the result and starts it.

### `--osv`

Look up every installed package at [osv.dev](https://osv.dev) and report what is known to
affect it. Needs `--image`, since it reads a built image's package inventory.

This covers **operating-system packages and the application's own dependencies** — PyPI and
npm — because that is where exploitable vulnerabilities concentrate. A slim base image's
advisories are often low severity and unreachable; a three-year-old Django is not.

```console
$ docker-trim --analyze-only --image myapp:latest --osv
Vulnerabilities     : 63 in 256 packages  26 high, 25 medium, 4 low, 8 unknown
  npm               : 63 in 238 packages
      185 under /usr/local/lib/node_modules
      53 under /app/node_modules
  Alpine:v3.24      : none in 18 packages
```

The ecosystems are kept apart deliberately, and so are the install roots. A `node:22-alpine`
base ships 185 npm packages inside npm itself; an application that installed three would
otherwise be told it has 238, which is true and useless.

Advisories become findings, so **`--fail-on` gates on them** without a second threshold:

```sh
docker-trim --analyze-only --image myapp:latest --osv --fail-on critical
```

Severity comes from the CVSS v3 vector in the advisory, scored with the formula from the
specification. An advisory carrying no vector docker-trim can read is counted and listed as
`unknown`, and deliberately cannot trip `--fail-on`: banding it would mean guessing, and a
guess here either fires a gate for nothing or stays quiet when it should not.

**This is the only part of docker-trim that sends anything anywhere.** The query carries the name
and version of every package in the image, which describes that image fairly precisely. It is
opt-in for that reason. Lookups run six at a time and stop at 600 packages.

Two runs can also differ for reasons that have nothing to do with your Dockerfile, because
the advisory database moves. That is worth knowing before wiring it into a gate that blocks
deploys.

## Recipes

**Check a Dockerfile in CI and fail on a baked credential.**

```sh
docker-trim --analyze-only -f Dockerfile --fail-on critical
```

**Be stricter: refuse anything that ships a shell or runs as root.**

```sh
docker-trim --analyze-only -f Dockerfile --fail-on high
```

**Post a report on a pull request.**

```sh
docker-trim -f Dockerfile --optimize -o /tmp/Dockerfile.trimmed --markdown > report.md
gh pr comment "$PR" --body-file report.md
```

**Find out where an image's bytes actually went.**

```sh
docker-trim --analyze-only myapp:latest --quiet \
  | jq '.image | {total: .totalSizeBytes, wasted: .wastedBytes, categories}'
```

**Try every base and compare, without building anything.**

```sh
for b in distroless alpine scratch; do
  echo "== $b"
  docker-trim -f Dockerfile --optimize -b "$b" -o "Dockerfile.$b" --no-diff | tail -5
done
```

**Prove it before you commit it.**

```sh
docker-trim -f Dockerfile --optimize --verify && mv Dockerfile.trimmed Dockerfile
```

## Exit codes

| Code | Meaning |
| ---: | :--- |
| `0` | Clean run. Without `--fail-on`, this includes a run that reported problems |
| `1` | `--fail-on` was given and a finding at or above that severity survived, including a vulnerability from `--osv` |
| `2` | docker-trim could not do its job: unreadable file, bad flag, failed build |

`1` and `2` are kept apart on purpose. A pipeline needs to tell "your Dockerfile ships a
shell" from "docker-trim crashed", and collapsing both into one code means a broken tool looks
like a broken Dockerfile.

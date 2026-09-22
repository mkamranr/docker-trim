# Usage

```
dtrim [OPTIONS] [DOCKERFILE_PATH or IMAGE_NAME]
```

A single positional argument is read as a Dockerfile if it is a file on disk or its name
contains `dockerfile`, and as an image reference otherwise. So `dtrim ./Dockerfile` and
`dtrim myapp:latest` both do the obvious thing.

With no arguments at all, dtrim analyzes `./Dockerfile`.

## Flags

### `--file`, `-f` (default `Dockerfile`)

The Dockerfile to parse. Analysis is read-only unless `--optimize` is also given.

### `--image`, `-i`

An image to inspect. The local Docker daemon is tried first, so an image you just built and
never pushed works; a reference the daemon does not have is fetched from its registry.

```console
$ dtrim --analyze-only myapp:latest
```

Inspection streams every layer and is bound by how fast the daemon can export the image —
about 25 MB/s on Docker Desktop. Reading from a registry skips that export and is faster.

### `--optimize`

Rewrite the Dockerfile and write the result to `--output`. Without it, dtrim only reports.

If the rewrite would be identical to the input, nothing is written and dtrim says so, rather
than leaving a duplicate file behind.

### `--output`, `-o` (default `Dockerfile.trimmed`)

Where the rewritten Dockerfile goes. Parent directories are created.

### `--base`, `-b` (default `distroless`)

The runtime base for the final stage: `distroless`, `alpine` or `scratch`. dtrim maps this
onto a concrete image per ecosystem and declines combinations that cannot work —
[heuristics.md](heuristics.md) lists which and why.

### `--verify`

Build the original and the trimmed Dockerfile against the same context, measure both, and
start the trimmed one for fifteen seconds.

This is what turns an estimate into a number worth quoting. Without it, sizes are labelled
`estimated`. It needs a working Docker engine and takes as long as two builds.

A container that survives the window has not crashed. It has not been exercised, and dtrim
does not claim otherwise. A service that needs a database it cannot reach will exit; dtrim
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
$ dtrim --analyze-only myapp:latest --quiet | jq '.image.categories'
$ dtrim --analyze-only --quiet | jq -r '.findings[] | select(.severity=="critical") | .title'
```

### `--markdown`

A report shaped for a pull request comment: the size table, what was applied, what is still
worth fixing, and the diff in a collapsed block.

### `--verbose`

Show every finding rather than the top eight, and stream the underlying `docker build`
output during `--verify` instead of a status line.

### `--fail-on`

Exit `1` when a finding of the given severity or worse survives: `info`, `low`, `medium`,
`high` or `critical`. Without it, dtrim reports and exits `0`, because a report is not a
failure unless you asked for one.

Only unfixed findings count. Something `--optimize` repaired is no longer in the file you
are about to build, so it does not fail the gate.

```console
$ dtrim --analyze-only --fail-on high
...
FAIL 6 findings at high or above: DT011, DT010
$ echo $?
1
```

The output names the rules responsible, so a red pipeline explains itself without a re-run.

### `--no-diff`, `--no-color`

Skip the diff; disable colour. Colour is also disabled when `NO_COLOR` is set or stdout is
not a terminal.

### `--trace`, `--tracer`, `--osv`

Accepted, and rejected with a pointer to the changelog. They exist so scripts written today
keep working when runtime tracing and CVE lookup land in 0.2. See [tracing.md](tracing.md).

## Recipes

**Check a Dockerfile in CI and fail on a baked credential.**

```sh
dtrim --analyze-only -f Dockerfile --fail-on critical
```

**Be stricter: refuse anything that ships a shell or runs as root.**

```sh
dtrim --analyze-only -f Dockerfile --fail-on high
```

**Post a report on a pull request.**

```sh
dtrim -f Dockerfile --optimize -o /tmp/Dockerfile.trimmed --markdown > report.md
gh pr comment "$PR" --body-file report.md
```

**Find out where an image's bytes actually went.**

```sh
dtrim --analyze-only myapp:latest --quiet \
  | jq '.image | {total: .totalSizeBytes, wasted: .wastedBytes, categories}'
```

**Try every base and compare, without building anything.**

```sh
for b in distroless alpine scratch; do
  echo "== $b"
  dtrim -f Dockerfile --optimize -b "$b" -o "Dockerfile.$b" --no-diff | tail -5
done
```

**Prove it before you commit it.**

```sh
dtrim -f Dockerfile --optimize --verify && mv Dockerfile.trimmed Dockerfile
```

## Exit codes

| Code | Meaning |
| ---: | :--- |
| `0` | Clean run. Without `--fail-on`, this includes a run that reported problems |
| `1` | `--fail-on` was given and a finding at or above that severity survived |
| `2` | dtrim could not do its job: unreadable file, bad flag, failed build |

`1` and `2` are kept apart on purpose. A pipeline needs to tell "your Dockerfile ships a
shell" from "dtrim crashed", and collapsing both into one code means a broken tool looks
like a broken Dockerfile.

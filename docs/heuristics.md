# Heuristics

> Two rules hold for every rewrite dtrim emits:
>
> **1. The output parses.** Whatever comes out is a Dockerfile, verified by re-parsing it.
> **2. dtrim never prints a size it did not measure.** Without `--verify`, every number is
> labelled `estimated`.

A tool that rewrites your build has exactly one chance to be trusted. Everything below
follows from that.

## Confidence, and what `--aggressiveness` gates

Every rule declares how sure it is that applying its fix is safe.

| Level | Meaning | Example |
| :--- | :--- | :--- |
| `safe` | Cannot change what the build produces | Adding `--no-install-recommends`, `--no-cache-dir` |
| `likely` | Correct for conventional projects, but makes an assumption | Pruning dev dependencies; injecting `USER` |
| `aggressive` | Trades a real chance of breaking the build for size | Merging `RUN` instructions |

`--aggressiveness` (default `likely`) sets the ceiling. Rules above it still report; they
just do not act.

## When dtrim does nothing

**The file already builds in stages.** The author has already made the layering decisions,
and rearranging them is how a tool like this breaks someone's build. Cleanups still apply;
the structure is not touched.

**The build is unrecognisable.** No `go build`, `npm`, `pip`, `cargo`, `mvn` or `gradle`
means dtrim cannot tell what the runtime stage would need to copy. It says so and applies
cleanups only, rather than inventing a builder stage.

**The split would save nothing.** If the runtime base would be the same image as the builder
base and the build installs no extra system packages, both stages start from the same bytes.
dtrim reports that instead of writing a file that changes the structure and saves zero.

**The runtime cannot host the artifact.** Node, Python and Java on `scratch`; Rust on alpine
without a musl target. Each is declined with the specific reason and the specific fix.

## Matching the runtime to what the build produced

This is where a naive rewrite produces an image that builds, starts, and then fails.

**Alpine is musl, not glibc.** Anything compiled against the builder's glibc will not load
there. So when you ask for `--base alpine`, dtrim moves the *builder* to alpine too, rather
than handing you a warning and a broken image. Python wheels and node-gyp modules are then
compiled against the libc that will actually run them.

**Go is the exception**, because a static binary runs on all three targets. dtrim sets
`CGO_ENABLED=0` in the builder for every base. If a project genuinely needs cgo, that line is
the one to remove, and the runtime base has to match the builder's libc.

**Rust needs an explicit musl target.** dtrim will not add `--target
x86_64-unknown-linux-musl` on your behalf, because that changes what the compiler produces
and can need dependencies the build does not have. It declines and tells you the flag.

**Python does not go to distroless, deliberately.** This one is worth the detail.

`gcr.io/distroless/python3-debian12` ships Debian's CPython — 3.11.2 at the time of writing.
The `python:3.11-slim` image ships upstream's latest patch — 3.11.16. Python resolves
dependencies against the interpreter that runs pip, and environment markers key off the full
patch version. `redis==5.2.1` declares:

```
async-timeout>=4.0.3; python_full_version < "3.11.3"
```

On the 3.11.16 builder that marker is false, so pip does not install `async-timeout`. On the
3.11.2 runtime it is true, so redis imports it and finds nothing. The image builds. It
starts. It dies on the first import. Compiled wheels have the same problem one level down, at
the ABI.

So dtrim keeps the runtime stage on the interpreter the build ran against. Python's saving
comes from leaving the build toolchain behind, which is real — 571 MB to 128 MB on the sample
project — just not from changing base image.

## Matching the command to the runtime base

Several minimal bases supply their own entrypoint, and repeating it runs the interpreter
twice. These were read from the published image configurations, not assumed:

| Base | Entrypoint | What dtrim emits |
| :--- | :--- | :--- |
| `distroless/nodejs<N>` | `/nodejs/bin/node` | `CMD ["dist/server.js"]`, with `node` stripped |
| `distroless/java<N>` | `/usr/bin/java -jar` | `CMD ["/path/app.jar"]`, with `java` and `-jar` stripped |
| `distroless/static`, `cc` | none | The original `ENTRYPOINT` and `CMD`, unchanged |

## Checking the rewrite against what the program actually does

A minimal runtime is only correct if the program never needed what was removed. Static
analysis cannot tell: nothing in a Dockerfile says "this service shells out to `curl` in its
error path". A trace can, and when one is available the synthesizer uses it.

If the trace saw a binary execute that the chosen runtime will not contain, dtrim reports it
as a **runtime gap** before you build:

```console
$ dtrim --image myapp:latest -f Dockerfile --tracer ptrace --optimize
Runtime gaps
  the trace saw these run, and the new base will not have them
  ! The trace saw `/bin/sh` executed, but a distroless base has no shell and no general
    userland, so that binary will not exist there.
```

That example is real. The program was a Go service that shells out; the rewrite took it from
909 MB to 4.8 MB, a 99.5% reduction, and the result printed
`fork/exec /bin/sh: no such file or directory` the first time it ran. It built cleanly, which
is what makes this failure mode worth predicting: nothing catches it until production.

Gaps are reported conservatively. A binary is only flagged when its absence is a property of
the base — scratch contains nothing, distroless has no shell, alpine has no `bash` or `curl`
— and anything being copied across the stage boundary is present by definition. A warning
that fires on something that turns out to be there is how a tool teaches people to ignore its
warnings.

## Removing packages nothing used

`--prune-unused` drops packages a trace never saw used. Two constraints shape it, and both
are easy to get wrong in a way that looks like it worked:

**It removes them from the install, rather than purging them afterwards.** A purge in a later
`RUN` cannot shrink an earlier layer, so appending one makes the image *larger* while
appearing to clean up. dtrim reports exactly that as `DT002` in other people's Dockerfiles.

**It only ever touches a stage that ships, never a builder.** A trace observes the finished
image running, so it knows nothing about what compiling it required — the compiler a builder
needs is precisely the sort of thing a runtime trace never sees. For the same reason it
declines single-stage files outright: there, one install serves both the build and the
runtime, and no runtime trace can separate them.

What is left is the final stage of a file that already builds in stages, which is exactly the
case where dtrim otherwise says "I left the structure alone". Pair it with `--verify`.

## What dtrim deliberately does not do

- **It does not reorder your instructions.** `COPY . .` before a dependency install is
  reported, never silently moved: the correct rewrite depends on which files the install
  needs, and only you know that.
- **It does not pin your base image.** A floating tag is reported. Choosing the digest is a
  decision about your supply chain, not a formatting fix.
- **It does not remove packages unless you ask.** A trace reports what went unused;
  `--prune-unused` acts on it, and without that flag dtrim deletes nothing. A trace only
  covers the code paths you exercised, and the package that goes unused all week is the one
  your error handler needs.
- **It does not rewrite an already multi-stage file.**
- **It does not touch the network**, except when you pass `--image` with a reference the local
  daemon does not have, or `--verify`, which builds.
- **It does not print a CVE count.** Until it can measure one, the field says `n/a`.

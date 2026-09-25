# Runtime tracing

Static analysis can tell you a package is installed. Only running the container can tell you
whether anything uses it. That is what tracing is for, and it is what makes "remove the
packages nothing touches" safe rather than hopeful.

The `proc` backend ships. `ptrace` and `ebpf` are accepted and rejected with a pointer to
the backend that works.

```console
$ dtrim --image myapp:latest --tracer proc --trace "pytest -q"
[dtrim] building an instrumented copy of myapp:latest
[dtrim] running /bin/sh -c pytest -q under the sampler for up to 30s

Runtime trace
  Observed            : 45 files, 2 binaries, 39 shared libraries across 2 processes, 42 samples
  Packages exercised  : 9 of 189
  Never touched       : 139 packages, 484 MB if removed (as the package database reports it)
  Kept regardless     : 41 packages (libc, the loader, trust store, time zones)
      - gcc-14-x86-64-linux-gnu      70 MB
      - git                          50 MB
      - vim-runtime                  39 MB
```

## The backends

| Backend | How it observes | Privileges | Fidelity |
| :--- | :--- | :--- | :--- |
| `proc` | Samples `/proc/*/exe`, `/proc/*/maps`, `/proc/*/fd` every ~50 ms | none | Every binary executed and every shared library loaded. Misses a config file opened and closed between samples. |
| `ptrace` | `PTRACE_SEIZE` on the process tree, decoding `execve` and `openat` | `CAP_SYS_PTRACE`, unconfined seccomp | Exact: every successful open, including config files |
| `ebpf` | CO-RE probes on `sched:sched_process_exec` and `syscalls:sys_enter_openat` | privileged, and a kernel with BTF | Exact, with the lowest overhead |

## Why the default is `proc` and not eBPF

The specification names eBPF, sysdig and Tracee. All three need a Linux kernel you can load
programs into. On macOS — where a large share of developers run Docker — there is no such
kernel on the host; containers run inside Docker Desktop's LinuxKit VM, and whether that
kernel exposes `/sys/kernel/btf/vmlinux` is not something a tool should bet a core feature on.

The `proc` sampler needs no capabilities, no kernel features and no seccomp changes. It works
on Docker Desktop, on a hardened CI runner, and on a locked-down Kubernetes node. And what it
produces — the set of executed binaries and loaded shared libraries — is exactly what the
package-pruning step consumes, because that is what maps back to packages through the dpkg
and apk databases dtrim already reads.

`ptrace` and `ebpf` are better where they run. They are backends, not the foundation.

## How the sensor gets in

dtrim builds an ephemeral copy of the target image with the sensor wrapping its entrypoint:

```dockerfile
FROM golang:1.25-alpine AS dtrim-sensor
COPY sensor.go .
RUN go mod init dtrimsensor && CGO_ENABLED=0 go build -o /dtrim-sensor .

FROM <target>
COPY --from=dtrim-sensor /dtrim-sensor /.dtrim/sensor
ENTRYPOINT ["/.dtrim/sensor","--"]
CMD [<the original entrypoint and command, or your --trace command>]
```

The sensor's **source** is embedded in dtrim and compiled inside that build, rather than
shipped as a binary. It is therefore always the right architecture, needs no
cross-compilation matrix, and no executable has to live in the repository.

Wrapping the entrypoint means tracing starts at PID 1, so the loader activity during startup
is captured, which is where most of the shared-library truth is. Attaching to a container
that is already running misses it.

The manifest comes back through **stderr between markers**, not through a file or a bind
mount: the image may run as a user who cannot write anywhere, and a mount would need a
writable host path. dtrim reads the container's logs and takes what is between the markers.

## What sampling misses, measured

Sampling races with a short-lived process. Here is the same image and the same command, six
times in a row, counting the Python modules loaded on demand that the trace caught:

```
run 1: 10 modules   _sqlite3 seen
run 2:  3 modules   _sqlite3 missed
run 3:  6 modules   _sqlite3 missed
run 4:  8 modules   _sqlite3 missed
run 5: 10 modules   _sqlite3 seen
run 6:  8 modules   _sqlite3 missed
```

The command lives about forty milliseconds. A module imported near the end of it can finish
loading between two samples and appear in none of them. Shortening the interval does not
fix this: at 2ms the same set came back. On a faster machine it gets worse — the same trace
on a GitHub Actions runner observed **no** dynamically loaded module at all, because the
entire import phase fell between two samples.

What is reliable is anything mapped for the life of the process, which is the interpreter,
every library it links against, and every long-lived worker. That is also what accounts for
most of an image.

So dtrim reports **how long the traced command ran** and warns when it was under a second,
because a user who cannot tell a thorough trace from two frames of a forty-millisecond
process will read "139 packages unused" as a fact. Give it a real workload with `--trace`,
and treat the output as evidence rather than proof. `ptrace` exists on the roadmap precisely
because it has no such race.

## From a trace to a smaller image

1. The sensor produces a `TraceManifest`: accessed files, executed binaries, loaded shared
   libraries.
2. Each path is mapped to its owning package through `/var/lib/dpkg/info/*.list` or
   `/lib/apk/db/installed`, both of which dtrim already parses during layer inspection.
3. `removable = installed − used − essential`, where the essential set is never touched:
   libc, the dynamic loader, `ca-certificates`, `tzdata`, `base-files`.
4. The result is reported. **Removal stays manual**: dtrim tells you what to consider
   dropping and leaves the decision to the person who knows the workload. A trace only
   covers the code paths you exercised, and the package that goes unused all week is the one
   your error handler needs.

The never-removed set is not a heuristic about what looked unused. The dynamic loader is
read only at exec time, a trust store only when something opens a TLS connection, and time
zone data only when something formats a local time. A short trace touches none of them and
would happily suggest deleting all three, so they are excluded by name.

Note that Debian priorities are not a safe proxy here: `libc6` is priority `optional`, while
`vim-tiny` is `important`. dtrim treats only `Essential: yes` and priority `required` as
structural, and protects the rest by name.

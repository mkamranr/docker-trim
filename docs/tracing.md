# Runtime tracing

Static analysis can tell you a package is installed. Only running the container can tell you
whether anything uses it. That is what tracing is for, and it is what makes "remove the
packages nothing touches" safe rather than hopeful.

It is **not in 0.1**. `--trace` and `--tracer` are accepted and rejected with a pointer to
the changelog, so scripts written today keep working when it lands. This document explains
the design that is being built.

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

dtrim embeds a static `CGO_ENABLED=0` Linux sensor and injects it as an entrypoint wrapper
into an ephemeral image:

```dockerfile
FROM <target>
COPY dtrim-sensor /.dtrim/sensor
ENTRYPOINT ["/.dtrim/sensor", "--"]
```

Wrapping the entrypoint means tracing starts at PID 1, so the loader activity during startup
is captured — which is where most of the shared-library truth is. Attaching to a container
that is already running misses it.

## From a trace to a smaller image

1. The sensor produces a `TraceManifest`: accessed files, executed binaries, loaded shared
   libraries.
2. Each path is mapped to its owning package through `/var/lib/dpkg/info/*.list` or
   `/lib/apk/db/installed`, both of which dtrim already parses during layer inspection.
3. `removable = installed − used − essential`, where the essential set is never touched:
   libc, the dynamic loader, `ca-certificates`, `tzdata`, `base-files`.
4. The result is reported. Removal stays opt-in, because a trace only proves what the code
   paths you exercised needed. Pass a representative workload with `--trace`, and treat the
   output as evidence rather than proof.

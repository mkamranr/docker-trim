# dtrim documentation

| Document | What it covers |
| :--- | :--- |
| [usage.md](usage.md) | Every flag, the recipes people actually use, and the exit codes |
| [heuristics.md](heuristics.md) | What dtrim will and will not change, and why |
| [architecture.md](architecture.md) | How the pipeline fits together, and how to add a rule |
| [library.md](library.md) | Driving dtrim from Go instead of the command line |
| [tracing.md](tracing.md) | Runtime tracing: the backends, and why the default is not eBPF |

Start with [usage.md](usage.md) if you want to use dtrim, and
[architecture.md](architecture.md) if you want to change it. If you are wondering why dtrim
refused to do something, the answer is in [heuristics.md](heuristics.md).

# Using dtrim as a library

The command-line surface is a thin wrapper. The library carries no dependency on cobra, so it
can be driven directly.

```go
import (
    "context"
    "os"

    "github.com/mkamranr/dtrim/pkg/dtrim"
    "github.com/mkamranr/dtrim/pkg/reporter"
)

cfg := dtrim.DefaultConfig()
cfg.File = "Dockerfile"
cfg.Optimize = true
cfg.Base = dtrim.BaseDistroless

rep, err := dtrim.Run(context.Background(), cfg)
if err != nil {
    return err
}
return reporter.Text(os.Stdout, rep, reporter.Options{})
```

## Config

`dtrim.DefaultConfig()` returns the defaults from the flag matrix. The fields that matter:

| Field | Meaning |
| :--- | :--- |
| `File`, `Image` | What to analyze; at least one is required |
| `Optimize` | Rewrite rather than only report |
| `AnalyzeOnly` | Never write anything; conflicts with `Verify` |
| `Base` | `BaseDistroless`, `BaseAlpine`, `BaseScratch` |
| `Output` | Where the rewritten Dockerfile goes |
| `Verify` | Build both images and measure them |
| `Aggressiveness` | `ConfidenceSafe`, `ConfidenceLikely`, `ConfidenceAggressive` |

`Validate()` runs automatically inside `Run`.

## The report

`Run` returns a `*dtrim.Report`, the same structure `--quiet` serialises:

```go
rep.Result.ReductionRatio   // 0.905
rep.Result.Measured         // false unless Verify built both images
rep.Dockerfile.Trimmed      // the rewritten file contents
rep.Findings                // what is still worth fixing
rep.Fixed                   // what dtrim repaired
rep.Image.Categories        // where an inspected image's bytes went
rep.Security.Summary()      // "Removed 4 unused OS packages, 2 shells, ..."
```

Check `Measured` before quoting a size. It is false unless `--verify` built both images, and
presenting an estimate as a measurement is the one thing this tool will not do.

## Using the stages directly

For finer control, the stages compose on their own:

```go
a, err := analyzer.ParseFile("Dockerfile")       // -> *analyzer.Analysis
findings := analyzer.Lint(a)                     // report only, no mutation
res := synthesizer.Optimize(a, synthesizer.BaseDistroless, analyzer.ConfidenceLikely)
out := synthesizer.Render(a)                     // the rewritten Dockerfile

img, err := analyzer.InspectImage(ctx, "myapp:latest")
surface := security.EvaluateImage(img)
```

`Optimize` mutates the `Analysis` in place and reports what it decided in `res.Plan`, including
`res.Plan.Reason` when it declined to restructure.

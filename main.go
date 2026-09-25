// Command dtrim analyzes container images and Dockerfiles, and rewrites
// single-stage builds into minimal multi-stage ones.
//
// This file is the command-line surface and nothing else: it maps flags onto a
// dtrim.Config, runs the pipeline, and renders the result. All of the work
// lives in the library, which carries no dependency on cobra so it can be used
// directly; see docs/library.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/mkamranr/dtrim/internal/version"
	"github.com/mkamranr/dtrim/pkg/analyzer"
	"github.com/mkamranr/dtrim/pkg/dtrim"
	"github.com/mkamranr/dtrim/pkg/reporter"
)

// Exit codes follow the convention every linter uses: 0 is a clean run, 1 means
// the tool worked and did not like what it found, 2 means the tool itself could
// not do its job. Keeping those apart is what lets a pipeline tell "your
// Dockerfile ships a shell" from "dtrim crashed".
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The gate result travels out of band rather than as an error: a Dockerfile
	// that breaches the threshold is a successful run with an opinion, not a
	// failure, and cobra would print it as one.
	var gateFailed bool
	cmd := newRootCommand(&gateFailed)

	if err := cmd.ExecuteContext(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "dtrim: interrupted")
			return exitError
		}
		fmt.Fprintf(os.Stderr, "dtrim: %v\n", err)
		return exitError
	}
	if gateFailed {
		return exitFindings
	}
	return exitOK
}

type flags struct {
	file           string
	image          string
	trace          string
	base           string
	output         string
	analyzeOnly    bool
	quiet          bool
	optimize       bool
	verify         bool
	aggressiveness string
	tracer         string
	osv            bool
	buildContext   string
	failOn         string
	traceTimeout   time.Duration
	noColor        bool
	verbose        bool
	markdown       bool
	noDiff         bool
}

func newRootCommand(gateFailed *bool) *cobra.Command {
	var f flags

	cmd := &cobra.Command{
		Use:   "dtrim [flags] [DOCKERFILE_PATH or IMAGE_NAME]",
		Short: "Shrink container images and cut their attack surface",
		Long: "dtrim analyzes Dockerfiles and built images, reports where the bytes and the\n" +
			"attack surface come from, and rewrites single-stage builds into minimal\n" +
			"multi-stage ones.\n\n" +
			"It never reports a size it did not measure: pass --verify to have it build both\n" +
			"images and compare them, otherwise sizes are labelled as estimates.",
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(),
		Example: strings.Join([]string{
			"  dtrim --file ./Dockerfile --optimize --output Dockerfile.min",
			"  dtrim --file ./Dockerfile --optimize --base distroless --verify",
			"  dtrim --analyze-only myapp:latest",
			"  dtrim --analyze-only myapp:latest --quiet | jq .image.categories",
			"  dtrim --analyze-only --fail-on high   # exits 1 if the image ships a shell",
			"  dtrim --image myapp:latest --tracer proc --trace \"pytest -q\"",
		}, "\n"),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := configure(cmd, &f, args)
			if err != nil {
				return err
			}
			rep, err := dtrim.Run(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			if err := render(cfg, &f, rep); err != nil {
				return err
			}
			*gateFailed = len(rep.Breaches(cfg.FailOn)) > 0
			return nil
		},
	}

	// The flag matrix from the PRD, section 3.
	fl := cmd.Flags()
	fl.StringVarP(&f.file, "file", "f", "", "Path to the target Dockerfile to parse and optimize (default \"Dockerfile\")")
	fl.StringVarP(&f.image, "image", "i", "", "Target image tag to inspect and dynamically trace")
	fl.StringVarP(&f.trace, "trace", "t", "", "Command to run inside the container while tracing; needs --tracer")
	fl.StringVarP(&f.base, "base", "b", "distroless", "Target minimal base image: distroless, alpine, scratch")
	fl.StringVarP(&f.output, "output", "o", "Dockerfile.trimmed", "Path to write optimized Dockerfile")
	fl.BoolVar(&f.analyzeOnly, "analyze-only", false, "Run static analysis without modifying or generating files")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "Suppress progress output; emit the JSON report on stdout")

	// Beyond the matrix. --optimize appears in the PRD's own examples but was
	// missing from its table; the rest earn their place below.
	fl.BoolVar(&f.optimize, "optimize", false, "Rewrite the Dockerfile and write the result to --output")
	fl.BoolVar(&f.verify, "verify", false, "Build both Dockerfiles and report measured sizes, then start the trimmed image")
	fl.StringVar(&f.aggressiveness, "aggressiveness", "likely", "How much to change: safe, likely, aggressive")
	fl.StringVar(&f.tracer, "tracer", "none", "Runtime tracing backend: none, proc (ptrace and ebpf are planned)")
	fl.DurationVar(&f.traceTimeout, "trace-timeout", 30*time.Second, "How long to let a traced container run")
	fl.BoolVar(&f.osv, "osv", false, "Look up real CVEs from api.osv.dev (not implemented yet)")
	fl.StringVar(&f.buildContext, "context", "", "Build context directory (default: the Dockerfile's directory)")
	fl.StringVar(&f.failOn, "fail-on", "", "Exit 1 when a finding of this severity or worse survives: info, low, medium, high, critical")
	fl.BoolVar(&f.noColor, "no-color", false, "Disable coloured output")
	fl.BoolVar(&f.verbose, "verbose", false, "Show every finding rather than the most important ones")
	fl.BoolVar(&f.markdown, "markdown", false, "Emit a Markdown report suitable for a pull request comment")
	fl.BoolVar(&f.noDiff, "no-diff", false, "Do not print the diff of the rewritten Dockerfile")

	cmd.SetVersionTemplate("{{.Version}}\n")
	return cmd
}

// configure turns the parsed flags into a validated Config.
func configure(cmd *cobra.Command, f *flags, args []string) (dtrim.Config, error) {
	cfg := dtrim.DefaultConfig()
	cfg.Stdout = cmd.OutOrStdout()
	cfg.Stderr = cmd.ErrOrStderr()
	// Start with no file so the default below can tell "the user said nothing"
	// from "the user asked for a Dockerfile". Otherwise `dtrim --image x` also
	// analyses whatever Dockerfile happens to be in the working directory.
	cfg.File = ""

	// A single positional argument is whichever of the two it looks like, so
	// `dtrim myapp:latest` and `dtrim ./Dockerfile` both do the obvious thing.
	if len(args) == 1 {
		if looksLikeDockerfile(args[0]) {
			cfg.File = args[0]
		} else {
			cfg.Image = args[0]
		}
	}
	if f.file != "" {
		cfg.File = f.file
	}
	if f.image != "" {
		cfg.Image = f.image
	}
	// Only fall back to ./Dockerfile when nothing at all was named.
	if cfg.File == "" && cfg.Image == "" {
		cfg.File = "Dockerfile"
	}

	base, err := dtrim.ParseBase(f.base)
	if err != nil {
		return cfg, err
	}
	tracerBackend, err := dtrim.ParseTracer(f.tracer)
	if err != nil {
		return cfg, err
	}

	cfg.Base = base
	cfg.Tracer = tracerBackend
	cfg.Trace = f.trace
	cfg.Output = f.output
	cfg.AnalyzeOnly = f.analyzeOnly
	cfg.Quiet = f.quiet
	cfg.Optimize = f.optimize
	cfg.Verify = f.verify
	cfg.Aggressiveness = dtrim.Confidence(f.aggressiveness)
	cfg.OSV = f.osv
	cfg.Context = f.buildContext
	cfg.TraceTimeout = f.traceTimeout
	cfg.NoColor = f.noColor
	cfg.Verbose = f.verbose

	if f.failOn != "" {
		sev, err := analyzer.ParseSeverity(f.failOn)
		if err != nil {
			return cfg, fmt.Errorf("--fail-on: %w", err)
		}
		cfg.FailOn = sev
	}
	if f.osv {
		return cfg, errors.New("--osv is not implemented yet; see the CHANGELOG for what is planned")
	}
	if cfg.File != "" {
		if _, err := os.Stat(cfg.File); err != nil {
			return cfg, fmt.Errorf("cannot read %s: %w", cfg.File, err)
		}
	}
	return cfg, cfg.Validate()
}

// render writes the report in whichever form was asked for.
func render(cfg dtrim.Config, f *flags, rep *dtrim.Report) error {
	opt := reporter.Options{NoColor: cfg.NoColor, Verbose: f.verbose, FailOn: cfg.FailOn}

	// --quiet means the JSON report and nothing else, so it can be piped.
	if cfg.Quiet {
		return reporter.JSON(os.Stdout, rep)
	}
	if f.markdown {
		return reporter.Markdown(os.Stdout, rep)
	}
	if err := reporter.Text(os.Stdout, rep, opt); err != nil {
		return err
	}
	if !f.noDiff {
		return reporter.Diff(os.Stdout, rep, opt)
	}
	return nil
}

// looksLikeDockerfile decides what a bare positional argument meant. An image
// reference never has a path separator before its first colon and is not a file
// on disk, which is enough to tell them apart without guessing.
func looksLikeDockerfile(arg string) bool {
	if info, err := os.Stat(arg); err == nil && !info.IsDir() {
		return true
	}
	base := strings.ToLower(arg)
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return strings.Contains(base, "dockerfile")
}

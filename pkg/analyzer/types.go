package analyzer

// The data structures declared in the PRD (section 5). They live in this leaf
// package so every stage of the pipeline can use them without an import cycle;
// package dtrim re-exports them under the names the PRD uses, which is the
// interface the library presents.

import (
	"fmt"
	"time"
)

// DockerfileAST is the parsed representation of a single build stage.
//
// PRD section 5. A multi-stage Dockerfile parses into one of these per stage;
// see Analysis.Stages.
type DockerfileAST struct {
	BaseImage    string        `json:"baseImage"`
	Instructions []Instruction `json:"instructions"`
	BuildStage   string        `json:"buildStage"`
}

// Instruction is one Dockerfile directive.
//
// PRD section 5. Args holds the instruction's arguments already split on
// whitespace, so a RUN line arrives as ["apt-get","update","&&","apt-get", ...].
// Raw preserves the original source text, which the emitter needs in order to
// reproduce heredocs and line continuations byte-for-byte.
type Instruction struct {
	Keyword string   `json:"keyword"`
	Args    []string `json:"args"`
	Line    int      `json:"line"`

	// Flags are the instruction's leading --flags, e.g. --from=builder on COPY.
	Flags []string `json:"flags,omitempty"`
	// Raw is the instruction exactly as it appeared in the source file.
	Raw string `json:"-"`
	// EndLine is the last source line of the instruction; differs from Line
	// when the instruction is continued or carries a heredoc.
	EndLine int `json:"endLine,omitempty"`
	// Lead is the verbatim source between the previous instruction and this
	// one: comments, blank lines, and the spacing between them. Carrying it
	// makes rendering lossless, so a file dtrim did not change comes back out
	// byte-for-byte and `--optimize` on an already-clean file produces an
	// empty diff rather than a reformatting storm.
	Lead []string `json:"-"`
	// Exec is true for the JSON array form, RUN ["a","b"], where the words are
	// passed to execve directly instead of through a shell. The distinction
	// changes signal handling and shell expansion, so the emitter preserves it.
	Exec bool `json:"exec,omitempty"`
}

// TraceManifest is the result of watching a container actually run.
//
// PRD section 5. Populated by the tracer package; empty in v0.1, where runtime
// tracing is not yet wired up (see CHANGELOG, "Planned for 0.2").
type TraceManifest struct {
	AccessedFiles []string `json:"accessedFiles"`
	UsedBinaries  []string `json:"usedBinaries"`
	SharedLibs    []string `json:"sharedLibs"`
	ReadBytes     int64    `json:"readBytes"`
}

// OptimizationResult is the headline reduction report.
//
// PRD section 5. Sizes are only populated with measured values when --verify
// built both images; Measured records which it is, because dtrim never presents
// an estimate as though it were a measurement.
type OptimizationResult struct {
	OriginalSizeBytes    int64         `json:"originalSizeBytes"`
	TrimmedSizeBytes     int64         `json:"trimmedSizeBytes"`
	ReductionRatio       float64       `json:"reductionRatio"`
	RemovedPackagesCount int           `json:"removedPackagesCount"`
	OriginalCVEs         int           `json:"originalCVEs"`
	RemainingCVEs        int           `json:"remainingCVEs"`
	Duration             time.Duration `json:"-"`

	// Measured is true when both sizes came from images dtrim actually built.
	Measured bool `json:"measured"`
	// CVEsKnown is false when no vulnerability source was available, in which
	// case the CVE fields are meaningless and the reporter prints "n/a".
	CVEsKnown bool `json:"cvesKnown"`
	// DurationMS mirrors Duration for JSON consumers.
	DurationMS int64 `json:"durationMs"`
}

// Severity ranks a finding.
type Severity string

// How much a finding matters, from a note to something worth blocking a release for.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rank orders severities so a threshold is a comparison. Higher is worse.
func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return -1
}

// ParseSeverity validates a severity name.
func ParseSeverity(v string) (Severity, error) {
	sev := Severity(v)
	if sev.Rank() < 0 {
		return "", fmt.Errorf("unknown severity %q: want info, low, medium, high or critical", v)
	}
	return sev, nil
}

// Confidence says how sure dtrim is that applying a rule's fix is safe.
//
// It gates auto-fixing: --aggressiveness safe applies only Safe rules, likely
// applies Safe and Likely, aggressive applies everything.
type Confidence string

const (
	// ConfidenceSafe cannot change build semantics (cache cleanup, flags).
	ConfidenceSafe Confidence = "safe"
	// ConfidenceLikely is correct for conventional projects but makes an
	// assumption a strange project could violate.
	ConfidenceLikely Confidence = "likely"
	// ConfidenceAggressive trades a real chance of breaking the build for size.
	ConfidenceAggressive Confidence = "aggressive"
)

// Rank orders confidence levels so gating is a simple comparison.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceSafe:
		return 0
	case ConfidenceLikely:
		return 1
	case ConfidenceAggressive:
		return 2
	}
	return 3
}

// Finding is one thing dtrim noticed about a Dockerfile or an image.
type Finding struct {
	RuleID     string     `json:"ruleId"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Line       int        `json:"line,omitempty"`
	Fixable    bool       `json:"fixable"`
	Fixed      bool       `json:"fixed"`
	// EstimatedSaving is bytes, when the rule can estimate one. Always
	// reported as an estimate, never folded into a measured size.
	EstimatedSaving int64 `json:"estimatedSavingBytes,omitempty"`
}

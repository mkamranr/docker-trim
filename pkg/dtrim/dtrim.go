// Package dtrim is the library behind the `dtrim` command.
//
// It presents the interface the PRD declares (section 5) and drives the
// pipeline: parse, inspect, rewrite, score, report. The data structures
// themselves are defined in package analyzer, the leaf every stage depends on,
// and re-exported here as aliases so callers see the PRD's names. The sibling
// ctrim project makes the same move, keeping the specified interface as a thin
// facade over the mechanism that actually does the work.
//
// See docs/library.md for worked examples.
package dtrim

import (
	"github.com/mkamranr/dtrim/pkg/analyzer"
	"github.com/mkamranr/dtrim/pkg/synthesizer"
)

// The PRD's section 5 data structures.
type (
	DockerfileAST      = analyzer.DockerfileAST
	Instruction        = analyzer.Instruction
	TraceManifest      = analyzer.TraceManifest
	OptimizationResult = analyzer.OptimizationResult
	Finding            = analyzer.Finding
	Severity           = analyzer.Severity
	Confidence         = analyzer.Confidence

	// Base is the --base value: which minimal runtime the final stage lands
	// on. It is defined by the synthesizer, which owns the mapping.
	Base = synthesizer.Base
)

const (
	SeverityInfo     = analyzer.SeverityInfo
	SeverityLow      = analyzer.SeverityLow
	SeverityMedium   = analyzer.SeverityMedium
	SeverityHigh     = analyzer.SeverityHigh
	SeverityCritical = analyzer.SeverityCritical

	ConfidenceSafe       = analyzer.ConfidenceSafe
	ConfidenceLikely     = analyzer.ConfidenceLikely
	ConfidenceAggressive = analyzer.ConfidenceAggressive

	BaseDistroless = synthesizer.BaseDistroless
	BaseAlpine     = synthesizer.BaseAlpine
	BaseScratch    = synthesizer.BaseScratch
)

// ParseBase validates a --base value.
func ParseBase(s string) (Base, error) { return synthesizer.ParseBase(s) }

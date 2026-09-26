// Package trim is the library behind the docker-trim command.
//
// It presents the interface the PRD declares (section 5) and drives the
// pipeline: parse, inspect, rewrite, score, report. The data structures
// themselves are defined in package analyzer, the leaf every stage depends on,
// and re-exported here as aliases so callers see the PRD's names. The sibling
// ctrim project makes the same move, keeping the specified interface as a thin
// facade over the mechanism that actually does the work.
//
// See docs/library.md for worked examples.
package trim

import (
	"github.com/mkamranr/docker-trim/pkg/analyzer"
	"github.com/mkamranr/docker-trim/pkg/synthesizer"
)

// DockerfileAST is one parsed build stage. See analyzer.DockerfileAST.
type DockerfileAST = analyzer.DockerfileAST

// Instruction is one Dockerfile directive. See analyzer.Instruction.
type Instruction = analyzer.Instruction

// TraceManifest is what a traced container actually touched. See analyzer.TraceManifest.
type TraceManifest = analyzer.TraceManifest

// OptimizationResult is the headline reduction report. See analyzer.OptimizationResult.
type OptimizationResult = analyzer.OptimizationResult

// Finding is one thing docker-trim noticed. See analyzer.Finding.
type Finding = analyzer.Finding

// Severity ranks a finding. See analyzer.Severity.
type Severity = analyzer.Severity

// Confidence says how sure docker-trim is that a fix is safe. See analyzer.Confidence.
type Confidence = analyzer.Confidence

// Base is the --base value: which minimal runtime the final stage lands on. It
// is defined by the synthesizer, which owns the mapping.
type Base = synthesizer.Base

// Severity levels, re-exported from the analyzer.
const (
	SeverityInfo     = analyzer.SeverityInfo
	SeverityLow      = analyzer.SeverityLow
	SeverityMedium   = analyzer.SeverityMedium
	SeverityHigh     = analyzer.SeverityHigh
	SeverityCritical = analyzer.SeverityCritical

	ConfidenceSafe       = analyzer.ConfidenceSafe
	ConfidenceLikely     = analyzer.ConfidenceLikely
	ConfidenceAggressive = analyzer.ConfidenceAggressive
)

// Runtime bases, re-exported from the synthesizer.
const (
	BaseDistroless = synthesizer.BaseDistroless
	BaseAlpine     = synthesizer.BaseAlpine
	BaseScratch    = synthesizer.BaseScratch
)

// ParseBase validates a --base value.
func ParseBase(s string) (Base, error) { return synthesizer.ParseBase(s) }

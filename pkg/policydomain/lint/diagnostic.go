//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package lint provides structured validation and linting for PolicyDomain YAML files.
//
// The primary entry point is [Lint], which runs all validation phases and returns
// a [Result] containing [Diagnostic] values. Each diagnostic carries file path,
// line/column, severity, entity context, and message — enabling programmatic
// consumers such as editor integrations to render gutter annotations.
//
// The [mpe lint] CLI command is built on top of this package by formatting the
// structured diagnostics for terminal output.
package lint

// Severity represents the impact level of a diagnostic.
type Severity int

const (
	// SeverityError indicates a definite error that must be fixed.
	SeverityError Severity = iota
	// SeverityWarning indicates a potential issue or style violation.
	SeverityWarning
	// SeverityInfo is informational and does not require action.
	SeverityInfo
)

// String returns a human-readable severity label.
func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// Source identifies which validation pass produced a diagnostic.
type Source string

const (
	// SourceYAML indicates a YAML parse or structure error.
	SourceYAML Source = "yaml"
	// SourceReference indicates a cross-entity reference error.
	SourceReference Source = "reference"
	// SourceCycle indicates a circular dependency error.
	SourceCycle Source = "cycle"
	// SourceRego indicates a Rego syntax or parse error (OPA AST parser).
	SourceRego Source = "rego"
	// SourceOPACheck indicates a semantic error found during full OPA compilation
	// (e.g., undefined functions, type errors).
	SourceOPACheck Source = "opa-check"
	// SourceRegal indicates a Regal lint rule violation.
	SourceRegal Source = "regal"
	// SourceRegistry indicates a domain-loading or registry-construction failure
	// that is not attributable to a specific YAML syntax error.
	SourceRegistry Source = "registry"
	// SourceSelector indicates an invalid regular expression in a selector field
	// on an operation, mapper, or resource entity.
	SourceSelector Source = "selector"
	// SourceDuplicate indicates a duplicate MRN or name within a single domain.
	SourceDuplicate Source = "duplicate"
	// SourceSchema indicates a missing or empty required field (e.g. metadata.name, rego).
	SourceSchema Source = "schema"
)

// Position is a 1-based line/column location within a file.
// Zero values mean the position is unknown or not applicable.
type Position struct {
	Line   int // 1-based line number; 0 = unknown
	Column int // 1-based column number; 0 = unknown
}

// Location ties a diagnostic to a specific place in a source file.
type Location struct {
	File  string   // Path to the PolicyDomain YAML file on disk.
	Start Position // Start of the problematic region.
	End   Position // End of the problematic region; zero = unknown.
}

// Entity identifies the policy-domain entity that contains the problem.
type Entity struct {
	Domain string // Policy domain name (e.g. "iam").
	Type   string // Entity kind: "policy", "library", "mapper", "role", etc.
	ID     string // Entity MRN or name.
	Field  string // Optional sub-field (e.g. "dependencies", "rego").
}

// Diagnostic is the unified structured output type produced by all validation sources.
// All fields except Message may be zero/empty when not applicable.
type Diagnostic struct {
	Source     Source
	Severity   Severity
	Location   Location
	Entity     Entity
	Message    string
	Category   string // Regal category, OPA error code, etc.
	RegoOffset int    // For rego/opa-check/regal sources: 1-based YAML line where the Rego block starts. 0 = unknown.
}

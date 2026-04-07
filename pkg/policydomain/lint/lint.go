//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/manetu/policyengine/pkg/policydomain"
	"github.com/manetu/policyengine/pkg/policydomain/parsers"
	"github.com/manetu/policyengine/pkg/policydomain/registry"
)

// LintFromStrings performs all validation phases on in-memory PolicyDomain YAML
// strings and returns structured diagnostics.
//
// contents maps logical file names (e.g. "my-domain.yaml") to their YAML content.
// This is equivalent to [Lint] but operates on in-memory data instead of files,
// making it suitable for use in environments without filesystem access (e.g. WASM).
func LintFromStrings(ctx context.Context, contents map[string]string, opts Options) (*Result, error) {
	return lintCore(ctx, StringSource{Files: contents}, opts)
}

// Options configures a lint run.
type Options struct {
	// OPAFlags are the flags forwarded to the OPA compilation step.
	// Use "--v0-compatible" (the default) for Rego v0 behaviour.
	// Set to "" or use DisableOPA to skip the OPA check phase.
	OPAFlags string

	// DisableOPA skips the in-process OPA compilation check.
	DisableOPA bool

	// EnableRegal runs Regal lint rules in addition to standard checks.
	EnableRegal bool

	// RegalTimeout limits how long Regal linting may run.
	// Zero means no timeout (not recommended for untrusted input).
	RegalTimeout time.Duration
}

// DefaultOptions returns the standard Options used by the mpe lint command.
func DefaultOptions() Options {
	return Options{
		OPAFlags:     "--v0-compatible",
		RegalTimeout: 60 * time.Second,
	}
}

// mapperFallbackID returns a deterministic fallback ID for a mapper that has
// no explicit IDSpec.ID, based on its index within the mappers list.
// All phases (Rego AST, OPA check, Regal) use this helper so the format stays consistent.
func mapperFallbackID(i int) string {
	return fmt.Sprintf("mapper[%d]", i)
}

// Result is the complete structured output of a lint run.
type Result struct {
	// Diagnostics contains all findings from all validation phases.
	Diagnostics []Diagnostic
	// FileCount is the number of files that were processed.
	FileCount int
}

// HasErrors returns true if any diagnostic has SeverityError.
func (r *Result) HasErrors() bool {
	for _, d := range r.Diagnostics {
		if d.Severity == SeverityError {
			return true
		}
	}
	return false
}

// ErrorCount returns the number of error-severity diagnostics.
func (r *Result) ErrorCount() int {
	count := 0
	for _, d := range r.Diagnostics {
		if d.Severity == SeverityError {
			count++
		}
	}
	return count
}

// ByFile groups diagnostics by their file path.
func (r *Result) ByFile() map[string][]Diagnostic {
	byFile := make(map[string][]Diagnostic)
	for _, d := range r.Diagnostics {
		byFile[d.Location.File] = append(byFile[d.Location.File], d)
	}
	return byFile
}

// Lint performs all validation phases on the given PolicyDomain YAML files
// and returns structured diagnostics. This is the primary API for programmatic
// consumers (e.g., editor integrations, CI tools).
//
// The returned error is reserved for infrastructure failures such as being
// unable to read a file. Validation problems are always in Result.Diagnostics.
func Lint(ctx context.Context, files []string, opts Options) (*Result, error) {
	return lintCore(ctx, FileSource{Paths: files}, opts)
}

// lintCore is the shared implementation for [Lint] and [LintFromStrings].
// It reads all data from src once, pre-parses domain models, and runs all
// validation phases against the in-memory models.
func lintCore(ctx context.Context, src DataSource, opts Options) (*Result, error) {
	keys := src.Keys()
	var diagnostics []Diagnostic

	// Read all data upfront (each key read exactly once)
	rawData := make(map[string][]byte, len(keys))
	for _, key := range keys {
		data, err := src.Read(key)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{
				Source:   SourceYAML,
				Severity: SeverityError,
				Location: Location{File: key},
				Message:  "failed to read file: " + err.Error(),
			})
			continue
		}
		rawData[key] = data
	}

	// Phase 1: YAML validation
	yamlValid := make(map[string]bool)
	for key, data := range rawData {
		d := lintYAML(data, key)
		diagnostics = append(diagnostics, d...)
		yamlValid[key] = len(d) == 0
	}

	// Collect only keys with valid YAML for further phases
	var validKeys []string
	for _, key := range keys {
		if yamlValid[key] {
			validKeys = append(validKeys, key)
		}
	}

	if len(validKeys) == 0 {
		return &Result{Diagnostics: diagnostics, FileCount: len(keys)}, nil
	}

	// Parse domain models and build offset maps from already-read raw bytes
	var models []*policydomain.IntermediateModel
	domainKeyMap := make(map[string]string) // domain-name → key
	regoOffsets := make(map[string]map[string]int)

	for _, key := range validKeys {
		data := rawData[key]

		domain, err := parsers.LoadFromBytes(key, data)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{
				Source:   SourceRegistry,
				Severity: SeverityError,
				Location: Location{File: key},
				Message:  "failed to load PolicyDomain: " + err.Error(),
			})
			continue
		}
		models = append(models, domain)
		domainKeyMap[domain.Name] = key

		offsets, err := computeRegoOffsets(data)
		if err == nil {
			regoOffsets[key] = offsets
		}
	}

	if len(models) == 0 {
		return &Result{Diagnostics: diagnostics, FileCount: len(keys)}, nil
	}

	// Phase 2: Reference and cycle validation via registry
	reg, validationErrors, err := registry.NewRegistryPermissiveFromModels(models)
	if err != nil {
		diagnostics = append(diagnostics, Diagnostic{
			Source:   SourceRegistry,
			Severity: SeverityError,
			Message:  err.Error(),
		})
		return &Result{Diagnostics: diagnostics, FileCount: len(keys)}, nil
	}

	diagnostics = append(diagnostics, convertValidationErrors(validationErrors, domainKeyMap)...)

	// Phase 3: Rego syntax validation (AST parse errors with line/col)
	diagnostics = append(diagnostics, lintRegoAST(models, domainKeyMap, regoOffsets)...)

	// Phase 4: Full OPA compilation check (catches type errors, undefined refs, etc.)
	if !opts.DisableOPA && reg != nil {
		rv := regoVersionFromFlags(opts.OPAFlags)
		diagnostics = append(diagnostics, runOPACheck(reg, models, domainKeyMap, regoOffsets, rv)...)
	}

	// Phase 5: Regal lint (file-system only — requires reading .rego files directly)
	if opts.EnableRegal && reg != nil {
		regalCtx := ctx
		if opts.RegalTimeout > 0 {
			var cancel context.CancelFunc
			regalCtx, cancel = context.WithTimeout(ctx, opts.RegalTimeout)
			defer cancel()
		}
		regalDiags, err := runRegal(regalCtx, models, domainKeyMap, regoOffsets)
		if err == nil {
			diagnostics = append(diagnostics, regalDiags...)
		}
	}

	return &Result{Diagnostics: diagnostics, FileCount: len(keys)}, nil
}

// regoVersionFromFlags parses the OPA flags string to determine rego version.
func regoVersionFromFlags(opaFlags string) regoVersion {
	if strings.Contains(opaFlags, "--v0-compatible") {
		return regoV0
	}
	return regoV1
}

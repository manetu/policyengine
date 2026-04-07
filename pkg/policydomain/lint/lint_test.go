//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manetu/policyengine/pkg/policydomain"
	"github.com/manetu/policyengine/pkg/policydomain/parsers"
	"github.com/manetu/policyengine/pkg/policydomain/validation"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/ast/location"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdata returns the absolute path to a file in the shared mpe test directory.
func testdata(name string) string {
	// pkg/policydomain/lint/ → ../../../cmd/mpe/test/
	return filepath.Join("..", "..", "..", "cmd", "mpe", "test", name)
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "lint-test-*.yml")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// ---------------------------------------------------------------------------
// Severity.String()
// ---------------------------------------------------------------------------

func TestSeverityString(t *testing.T) {
	assert.Equal(t, "error", SeverityError.String())
	assert.Equal(t, "warning", SeverityWarning.String())
	assert.Equal(t, "info", SeverityInfo.String())
	assert.Equal(t, "unknown", Severity(99).String())
}

// ---------------------------------------------------------------------------
// Result.ErrorCount() and Result.ByFile()
// ---------------------------------------------------------------------------

func TestResultErrorCount(t *testing.T) {
	r := &Result{
		Diagnostics: []Diagnostic{
			{Severity: SeverityError, Location: Location{File: "a.yml"}},
			{Severity: SeverityWarning, Location: Location{File: "a.yml"}},
			{Severity: SeverityError, Location: Location{File: "b.yml"}},
		},
	}
	assert.Equal(t, 2, r.ErrorCount())
	assert.True(t, r.HasErrors())
}

func TestResultErrorCountZero(t *testing.T) {
	r := &Result{
		Diagnostics: []Diagnostic{
			{Severity: SeverityWarning},
			{Severity: SeverityInfo},
		},
	}
	assert.Equal(t, 0, r.ErrorCount())
	assert.False(t, r.HasErrors())
}

func TestResultByFile(t *testing.T) {
	r := &Result{
		Diagnostics: []Diagnostic{
			{Severity: SeverityError, Location: Location{File: "a.yml"}, Message: "err1"},
			{Severity: SeverityError, Location: Location{File: "b.yml"}, Message: "err2"},
			{Severity: SeverityWarning, Location: Location{File: "a.yml"}, Message: "warn1"},
		},
	}
	byFile := r.ByFile()
	assert.Len(t, byFile["a.yml"], 2)
	assert.Len(t, byFile["b.yml"], 1)
}

// ---------------------------------------------------------------------------
// regalSeverity()
// ---------------------------------------------------------------------------

func TestRegalSeverity(t *testing.T) {
	assert.Equal(t, SeverityError, regalSeverity("error"))
	assert.Equal(t, SeverityWarning, regalSeverity("warning"))
	assert.Equal(t, SeverityWarning, regalSeverity("WARNING")) // case-insensitive
	assert.Equal(t, SeverityInfo, regalSeverity("info"))
	assert.Equal(t, SeverityInfo, regalSeverity("notice")) // default → Info
	assert.Equal(t, SeverityInfo, regalSeverity(""))
}

// ---------------------------------------------------------------------------
// convertValidationErrors() — cycle and unknown type branches
// ---------------------------------------------------------------------------

func TestConvertValidationErrors_CycleType(t *testing.T) {
	errs := []*validation.Error{
		{Type: "cycle", Message: "circular dependency detected: a → b → a"},
	}
	diags := convertValidationErrors(errs, nil)
	require.Len(t, diags, 1)
	assert.Equal(t, SourceCycle, diags[0].Source)
	assert.Equal(t, SeverityError, diags[0].Severity)
	assert.Equal(t, "circular dependency detected: a → b → a", diags[0].Message)
}

func TestConvertValidationErrors_UnknownType(t *testing.T) {
	errs := []*validation.Error{
		{Type: "something-new", Domain: "iam", Message: "future error"},
	}
	diags := convertValidationErrors(errs, map[string]string{"iam": "iam.yml"})
	require.Len(t, diags, 1)
	// Unknown types fall back to SourceReference
	assert.Equal(t, SourceReference, diags[0].Source)
	assert.Equal(t, "iam.yml", diags[0].Location.File)
}

func TestConvertValidationErrors_Empty(t *testing.T) {
	assert.Nil(t, convertValidationErrors(nil, nil))
	assert.Nil(t, convertValidationErrors([]*validation.Error{}, nil))
}

// ---------------------------------------------------------------------------
// computeRegoOffsets() — error paths
// ---------------------------------------------------------------------------

func TestComputeRegoOffsets_InvalidYAML(t *testing.T) {
	_, err := computeRegoOffsets([]byte("key: [unclosed bracket"))
	assert.Error(t, err)
}

func TestComputeRegoOffsets_NoSpec(t *testing.T) {
	// Valid YAML but no "spec" key → returns empty map, no error
	offsets, err := computeRegoOffsets([]byte("apiVersion: v1\nkind: Something\n"))
	assert.NoError(t, err)
	assert.Empty(t, offsets)
}

// ---------------------------------------------------------------------------
// extractOffsetsFromMap() — v1beta1 map-style entity sections
// ---------------------------------------------------------------------------

func TestExtractOffsetsFromMap(t *testing.T) {
	// YAML with map-style policyLibraries (key is entity ID, value has rego:)
	yaml := `spec:
  policyLibraries:
    my-lib:
      rego: |
        package test
        default allow = false
  policies:
    my-policy:
      rego: |
        package authz
        default allow = true
`
	offsets, err := computeRegoOffsets([]byte(yaml))
	require.NoError(t, err)

	// "my-lib" rego block starts at line 4 (rego: is line 3, content line 4)
	assert.Contains(t, offsets, "library:my-lib")
	libLine := offsets["library:my-lib"]
	assert.Greater(t, libLine, 0, "should have a positive line offset for library")

	assert.Contains(t, offsets, "policy:my-policy")
	policyLine := offsets["policy:my-policy"]
	assert.Greater(t, policyLine, libLine, "policy should start after library")
}

func TestExtractOffsetsFromMap_NoRegoKey(t *testing.T) {
	// Map-style section where entries have no "rego:" key
	yaml := `spec:
  policyLibraries:
    empty-lib:
      description: no rego here
`
	offsets, err := computeRegoOffsets([]byte(yaml))
	require.NoError(t, err)
	assert.Empty(t, offsets)
}

// ---------------------------------------------------------------------------
// extractOffsets() — non-mapping spec node
// ---------------------------------------------------------------------------

func TestExtractOffsets_SpecIsSequence(t *testing.T) {
	// "spec" is a sequence rather than a mapping — should not panic or error
	yaml := `spec:
  - item1
  - item2
`
	offsets, err := computeRegoOffsets([]byte(yaml))
	require.NoError(t, err)
	assert.Empty(t, offsets)
}

// ---------------------------------------------------------------------------
// extractOffsetsFromList() — list entries missing mrn/id or rego
// ---------------------------------------------------------------------------

func TestExtractOffsets_ListEntryNoID(t *testing.T) {
	// List entry has rego but neither mrn nor id field → skip it
	yaml := `spec:
  policies:
    - name: unnamed-policy
      rego: |
        package authz
`
	offsets, err := computeRegoOffsets([]byte(yaml))
	require.NoError(t, err)
	// No entry should be recorded since there's no ID
	assert.Empty(t, offsets)
}

func TestExtractOffsets_ListEntryNoRego(t *testing.T) {
	// List entry has mrn but no rego field
	yaml := `spec:
  policies:
    - mrn: "mrn:iam:policy:no-rego"
      description: "no rego here"
`
	offsets, err := computeRegoOffsets([]byte(yaml))
	require.NoError(t, err)
	assert.Empty(t, offsets)
}

// ---------------------------------------------------------------------------
// convertCompilerErrors() — module-ID-not-found fallback + no-offset branch
// ---------------------------------------------------------------------------

func TestConvertCompilerErrors_UnknownModule(t *testing.T) {
	// Error whose Location.File doesn't match any module in the list →
	// should produce a Diagnostic without entity info
	loc := location.Location{File: "unknown-module", Row: 1, Col: 1}
	errs := ast.Errors{
		&ast.Error{Code: "rego_type_error", Message: "some error", Location: &loc},
	}
	diags := convertCompilerErrors(errs, nil, nil)
	require.Len(t, diags, 1)
	assert.Equal(t, SourceOPACheck, diags[0].Source)
	assert.Equal(t, "some error", diags[0].Message)
	assert.Equal(t, "", diags[0].Location.File) // no file info
}

func TestConvertCompilerErrors_NoOffsetFallback(t *testing.T) {
	// Error whose module IS in the list but has no YAML offset stored →
	// Start.Line should equal the raw Rego line (no +offset)
	loc := location.Location{File: "policy:my-policy", Row: 5, Col: 3}
	errs := ast.Errors{
		&ast.Error{Code: "rego_type_error", Message: "undefined fn", Location: &loc},
	}
	modules := []parsedModule{{
		file:   "domain.yml",
		entity: Entity{Type: "policy", ID: "my-policy"},
	}}
	// Pass empty regoOffsets so offset = 0 → fallback branch
	diags := convertCompilerErrors(errs, modules, nil)
	require.Len(t, diags, 1)
	assert.Equal(t, 5, diags[0].Location.Start.Line) // raw row, no offset
	assert.Equal(t, 3, diags[0].Location.Start.Column)
}

// ---------------------------------------------------------------------------
// Lint() with mapper Rego (exercises checkMappers + lintRegoAST mapper path)
// ---------------------------------------------------------------------------

func TestLint_WithMappers(t *testing.T) {
	// consolidated.yml contains mapper Rego — exercises checkMappers()
	result, err := Lint(context.Background(), []string{testdata("consolidated.yml")}, DefaultOptions())
	require.NoError(t, err)
	assert.Equal(t, 1, result.FileCount)
	// consolidated.yml should pass all checks
	assert.False(t, result.HasErrors(), "consolidated.yml should be valid, got: %v", result.Diagnostics)
}

func TestLint_MapperRegoError(t *testing.T) {
	// YAML with a mapper that has invalid Rego
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: bad-mapper-domain
spec:
  mappers:
    - name: bad-mapper
      selector:
        - ".*"
      rego: "bad rego content"
`
	f := writeTempFile(t, yaml)
	result, err := Lint(context.Background(), []string{f}, DefaultOptions())
	require.NoError(t, err)
	assert.True(t, result.HasErrors())

	regoErrs := filterBySource(result.Diagnostics, SourceRego)
	assert.NotEmpty(t, regoErrs, "should have Rego parse errors for mapper")
}

// ---------------------------------------------------------------------------
// runRegal() — no-rego-files early return
// ---------------------------------------------------------------------------

func TestRegal_NoRegoContent(t *testing.T) {
	skipIfFIPS(t)
	// Domain with no Rego at all → runRegal returns nil early
	const yamlContent = `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: empty-domain
spec: {}
`
	domain, err := parsers.LoadFromBytes("empty-domain.yaml", []byte(yamlContent))
	require.NoError(t, err)
	domainKeyMap := map[string]string{domain.Name: "empty-domain.yaml"}
	diags, err := runRegal(context.Background(), []*policydomain.IntermediateModel{domain}, domainKeyMap, nil)
	assert.NoError(t, err)
	assert.Nil(t, diags)
}

// ---------------------------------------------------------------------------
// Lint() with OPA v1 mode (regoVersionFromFlags non-v0 branch)
// ---------------------------------------------------------------------------

func TestLint_RegoV1Mode(t *testing.T) {
	opts := Options{OPAFlags: ""} // no --v0-compatible → uses RegoV1
	result, err := Lint(context.Background(), []string{testdata("lint-valid-simple.yml")}, opts)
	require.NoError(t, err)
	// v0 syntax may produce errors in v1 mode; we just verify it doesn't panic
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// Lint() — DisableOPA path
// ---------------------------------------------------------------------------

func TestLint_DisableOPA(t *testing.T) {
	opts := Options{DisableOPA: true}
	result, err := Lint(context.Background(), []string{testdata("fail-opa-check.yml")}, opts)
	require.NoError(t, err)
	// With OPA disabled, the undefined-function error should NOT appear
	opaErrs := filterBySource(result.Diagnostics, SourceOPACheck)
	assert.Empty(t, opaErrs, "OPA check errors should be absent when DisableOPA=true")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SyntheticRegoName() — direct unit test now that it is exported
// ---------------------------------------------------------------------------

func TestSyntheticRegoName(t *testing.T) {
	name := SyntheticRegoName("path/to/domain.yml", "policy", "my-policy")
	assert.Equal(t, "path/to/domain.yml_policy_my-policy.rego", name)

	// Colons and slashes in entity IDs are sanitised to underscores
	name = SyntheticRegoName("domain.yml", "library", "mrn:iam:lib:auth")
	assert.Equal(t, "domain.yml_library_mrn_iam_lib_auth.rego", name)

	name = SyntheticRegoName("domain.yml", "mapper", "cross/slash")
	assert.Equal(t, "domain.yml_mapper_cross_slash.rego", name)
}

// ---------------------------------------------------------------------------
// LintFromStrings — all YAML invalid (empty validKeys early-exit, lint.go:132)
// ---------------------------------------------------------------------------

func TestLintFromStrings_AllInvalidYAML(t *testing.T) {
	files := map[string]string{
		"bad1.yml": "key: [unclosed",
		"bad2.yml": ": invalid: yaml: :",
	}
	result, err := LintFromStrings(context.Background(), files, DefaultOptions())
	require.NoError(t, err)
	// Two files were processed, both invalid
	assert.Equal(t, 2, result.FileCount)
	// Should have YAML errors for each file
	yamlErrs := filterBySource(result.Diagnostics, SourceYAML)
	assert.Len(t, yamlErrs, 2)
	// No Rego/OPA diagnostics since we never reached those phases
	assert.Empty(t, filterBySource(result.Diagnostics, SourceRego))
	assert.Empty(t, filterBySource(result.Diagnostics, SourceOPACheck))
}

// ---------------------------------------------------------------------------
// LintFromStrings — valid YAML but unknown apiVersion (parser error path, lint.go:145)
// ---------------------------------------------------------------------------

func TestLintFromStrings_UnknownAPIVersion(t *testing.T) {
	// Valid YAML, kind=PolicyDomain, but unrecognised apiVersion → parsers.LoadFromBytes fails.
	// Before this fix the error was silently swallowed; now it should surface as SourceRegistry.
	yaml := `apiVersion: example.io/v99
kind: PolicyDomain
metadata:
  name: future-domain
spec: {}
`
	result, err := LintFromStrings(context.Background(), map[string]string{"future.yml": yaml}, DefaultOptions())
	require.NoError(t, err)
	assert.Equal(t, 1, result.FileCount)
	registryErrs := filterBySource(result.Diagnostics, SourceRegistry)
	require.NotEmpty(t, registryErrs, "expected a SourceRegistry diagnostic for unknown apiVersion")
	assert.Equal(t, "future.yml", registryErrs[0].Location.File)
	assert.Contains(t, registryErrs[0].Message, "unsupported")
}

func filterBySource(diagnostics []Diagnostic, source Source) []Diagnostic {
	var out []Diagnostic
	for _, d := range diagnostics {
		if d.Source == source {
			out = append(out, d)
		}
	}
	return out
}

func skipIfFIPS(t *testing.T) {
	t.Helper()
	if strings.Contains(os.Getenv("GODEBUG"), "fips140") {
		t.Skip("skipping Regal test: crypto.md5 not permitted in FIPS 140-only mode")
	}
}

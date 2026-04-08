//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validSelectorDomain is a well-formed v1beta1 PolicyDomain with valid selector
// patterns on an operation, a mapper, and a resource.
const validSelectorDomain = `
apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: test-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      rego: |
        package authz
        default allow = 1

  resource-groups:
    - mrn: "mrn:iam:resource-group:default"
      policy: "mrn:iam:policy:allow-all"
      default: true

  operations:
    - name: default-op
      selector:
        - ".*"
      policy: "mrn:iam:policy:allow-all"

  mappers:
    - name: default-mapper
      selector:
        - ".*"
      rego: |
        package mapper
        porc := {"principal": {}, "operation": "op", "resource": {"id": "r", "group": "mrn:iam:resource-group:default"}, "context": input}

  resources:
    - name: default-resource
      selector:
        - "mrn:data:.*"
      group: "mrn:iam:resource-group:default"
`

// domainWithInvalidSelector builds a minimal domain with one invalid selector
// on the named entity type.
func domainWithInvalidSelector(entityType, name, badPattern string) string {
	var sb strings.Builder
	sb.WriteString(`
apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: test-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      rego: |
        package authz
        default allow = 1

  resource-groups:
    - mrn: "mrn:iam:resource-group:default"
      policy: "mrn:iam:policy:allow-all"
      default: true

`)
	switch entityType {
	case "operation":
		sb.WriteString("  operations:\n")
		sb.WriteString("    - name: " + name + "\n")
		sb.WriteString("      selector:\n")
		sb.WriteString("        - " + `"` + badPattern + `"` + "\n")
		sb.WriteString("      policy: \"mrn:iam:policy:allow-all\"\n")
	case "mapper":
		sb.WriteString("  mappers:\n")
		sb.WriteString("    - name: " + name + "\n")
		sb.WriteString("      selector:\n")
		sb.WriteString("        - " + `"` + badPattern + `"` + "\n")
		sb.WriteString("      rego: |\n")
		sb.WriteString("        package mapper\n")
		sb.WriteString(`        porc := {"principal": {}, "operation": "op", "resource": {"id": "r", "group": "mrn:iam:resource-group:default"}, "context": input}`)
		sb.WriteString("\n")
	case "resource":
		sb.WriteString("  resources:\n")
		sb.WriteString("    - name: " + name + "\n")
		sb.WriteString("      selector:\n")
		sb.WriteString("        - " + `"` + badPattern + `"` + "\n")
		sb.WriteString("      group: \"mrn:iam:resource-group:default\"\n")
	}
	return sb.String()
}

// filterSelector returns only diagnostics with SourceSelector.
func filterSelector(diags []Diagnostic) []Diagnostic {
	var out []Diagnostic
	for _, d := range diags {
		if d.Source == SourceSelector {
			out = append(out, d)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// lintSelectors unit tests
// ---------------------------------------------------------------------------

func TestLintSelectors_ValidSelectorsProduceNoDiagnostics(t *testing.T) {
	diags := lintSelectors([]byte(validSelectorDomain), "test.yml")
	selectorDiags := filterSelector(diags)
	assert.Empty(t, selectorDiags)
}

func TestLintSelectors_InvalidOperationSelector(t *testing.T) {
	yaml := domainWithInvalidSelector("operation", "my-op", "[invalid")
	diags := lintSelectors([]byte(yaml), "test.yml")

	require.Len(t, diags, 1)
	d := diags[0]
	assert.Equal(t, SourceSelector, d.Source)
	assert.Equal(t, SeverityError, d.Severity)
	assert.Equal(t, "operation", d.Entity.Type)
	assert.Equal(t, "my-op", d.Entity.ID)
	assert.Equal(t, "selector", d.Entity.Field)
	assert.Equal(t, "test-domain", d.Entity.Domain)
	assert.Equal(t, "test.yml", d.Location.File)
	assert.NotZero(t, d.Location.Start.Line)
	assert.Contains(t, d.Message, "[invalid")
}

func TestLintSelectors_InvalidMapperSelector(t *testing.T) {
	yaml := domainWithInvalidSelector("mapper", "my-mapper", "[bad")
	diags := lintSelectors([]byte(yaml), "test.yml")

	require.Len(t, diags, 1)
	d := diags[0]
	assert.Equal(t, SourceSelector, d.Source)
	assert.Equal(t, SeverityError, d.Severity)
	assert.Equal(t, "mapper", d.Entity.Type)
	assert.Equal(t, "my-mapper", d.Entity.ID)
	assert.Equal(t, "selector", d.Entity.Field)
	assert.Contains(t, d.Message, "[bad")
}

func TestLintSelectors_InvalidResourceSelector(t *testing.T) {
	yaml := domainWithInvalidSelector("resource", "my-resource", "[broken")
	diags := lintSelectors([]byte(yaml), "test.yml")

	require.Len(t, diags, 1)
	d := diags[0]
	assert.Equal(t, SourceSelector, d.Source)
	assert.Equal(t, SeverityError, d.Severity)
	assert.Equal(t, "resource", d.Entity.Type)
	assert.Equal(t, "my-resource", d.Entity.ID)
	assert.Equal(t, "selector", d.Entity.Field)
	assert.Contains(t, d.Message, "[broken")
}

func TestLintSelectors_MultipleInvalidSelectorsOnOneEntity(t *testing.T) {
	yaml := `
apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: test-domain
spec:
  operations:
    - name: multi-op
      selector:
        - "[bad1"
        - "[bad2"
        - "valid.*"
      policy: "mrn:iam:policy:allow-all"
`
	diags := lintSelectors([]byte(yaml), "test.yml")
	require.Len(t, diags, 2)
	assert.Contains(t, diags[0].Message, "[bad1")
	assert.Contains(t, diags[1].Message, "[bad2")
}

func TestLintSelectors_MixedValidAndInvalidSelectors(t *testing.T) {
	yaml := `
apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: test-domain
spec:
  operations:
    - name: ok-op
      selector:
        - ".*"
      policy: "mrn:iam:policy:allow-all"
    - name: bad-op
      selector:
        - "[invalid"
      policy: "mrn:iam:policy:allow-all"
`
	diags := lintSelectors([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, "bad-op", diags[0].Entity.ID)
}

func TestLintSelectors_EntityIDFromNameField(t *testing.T) {
	yaml := domainWithInvalidSelector("mapper", "named-mapper", "[bad")
	diags := lintSelectors([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, "named-mapper", diags[0].Entity.ID)
}

func TestLintSelectors_EntityIDFallbackToIndex(t *testing.T) {
	// Entity with no name field gets an index-based fallback ID.
	yaml := `
apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: test-domain
spec:
  operations:
    - selector:
        - "[invalid"
      policy: "mrn:iam:policy:allow-all"
`
	diags := lintSelectors([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, "operation[0]", diags[0].Entity.ID)
}

func TestLintSelectors_DomainNamePopulated(t *testing.T) {
	yaml := domainWithInvalidSelector("operation", "op", "[bad")
	diags := lintSelectors([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, "test-domain", diags[0].Entity.Domain)
}

func TestLintSelectors_LineNumberAccuracy(t *testing.T) {
	// The bad selector is on a known line; verify Start.Line is non-zero and
	// points somewhere in the selector block (not line 1).
	yaml := domainWithInvalidSelector("operation", "op", "[bad")
	diags := lintSelectors([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Greater(t, diags[0].Location.Start.Line, 1)
}

func TestLintSelectors_InvalidYAMLReturnsNoDiagnostics(t *testing.T) {
	// If the YAML is unparseable, lintSelectors should not panic and return empty.
	diags := lintSelectors([]byte(":\t: bad yaml {{{"), "test.yml")
	assert.Empty(t, diags)
}

func TestLintSelectors_EmptyInputReturnsNoDiagnostics(t *testing.T) {
	diags := lintSelectors([]byte(""), "test.yml")
	assert.Empty(t, diags)
}

// ---------------------------------------------------------------------------
// selectorAnchorPattern unit tests
// ---------------------------------------------------------------------------

func TestSelectorAnchorPattern_AddsAnchors(t *testing.T) {
	assert.Equal(t, "^foo$", selectorAnchorPattern("foo"))
}

func TestSelectorAnchorPattern_PreservesExistingAnchors(t *testing.T) {
	assert.Equal(t, "^foo$", selectorAnchorPattern("^foo$"))
	assert.Equal(t, "^foo$", selectorAnchorPattern("^foo"))
	assert.Equal(t, "^foo$", selectorAnchorPattern("foo$"))
}

// ---------------------------------------------------------------------------
// Integration tests via LintFromStrings
// ---------------------------------------------------------------------------

func TestLintFromStrings_InvalidOperationSelectorProducesSelectorDiagnostic(t *testing.T) {
	yaml := domainWithInvalidSelector("operation", "bad-op", "[broken")
	result, err := LintFromStrings(context.Background(), map[string]string{"test.yml": yaml}, DefaultOptions())
	require.NoError(t, err)

	selectorDiags := filterSelector(result.Diagnostics)
	require.NotEmpty(t, selectorDiags, "expected at least one SourceSelector diagnostic")
	d := selectorDiags[0]
	assert.Equal(t, SourceSelector, d.Source)
	assert.Equal(t, SeverityError, d.Severity)
	assert.Equal(t, "operation", d.Entity.Type)
	assert.Equal(t, "bad-op", d.Entity.ID)
	assert.Equal(t, "selector", d.Entity.Field)
	assert.Equal(t, "test-domain", d.Entity.Domain)
	assert.Equal(t, "test.yml", d.Location.File)
	assert.NotZero(t, d.Location.Start.Line)
	assert.Contains(t, d.Message, "[broken")
}

func TestLintFromStrings_InvalidMapperSelectorProducesSelectorDiagnostic(t *testing.T) {
	yaml := domainWithInvalidSelector("mapper", "bad-mapper", "[oops")
	result, err := LintFromStrings(context.Background(), map[string]string{"test.yml": yaml}, DefaultOptions())
	require.NoError(t, err)

	selectorDiags := filterSelector(result.Diagnostics)
	require.NotEmpty(t, selectorDiags)
	assert.Equal(t, "mapper", selectorDiags[0].Entity.Type)
	assert.Equal(t, "bad-mapper", selectorDiags[0].Entity.ID)
}

func TestLintFromStrings_InvalidResourceSelectorProducesSelectorDiagnostic(t *testing.T) {
	yaml := domainWithInvalidSelector("resource", "bad-resource", "[nope")
	result, err := LintFromStrings(context.Background(), map[string]string{"test.yml": yaml}, DefaultOptions())
	require.NoError(t, err)

	selectorDiags := filterSelector(result.Diagnostics)
	require.NotEmpty(t, selectorDiags)
	assert.Equal(t, "resource", selectorDiags[0].Entity.Type)
	assert.Equal(t, "bad-resource", selectorDiags[0].Entity.ID)
}

func TestLintFromStrings_ValidSelectorsProduceNoSelectorDiagnostics(t *testing.T) {
	result, err := LintFromStrings(context.Background(), map[string]string{"test.yml": validSelectorDomain}, DefaultOptions())
	require.NoError(t, err)

	selectorDiags := filterSelector(result.Diagnostics)
	assert.Empty(t, selectorDiags)
}

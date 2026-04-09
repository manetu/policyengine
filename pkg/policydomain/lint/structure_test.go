//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLintStructure_MissingMetadataName(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: ""
spec: {}
`
	diags := lintStructure([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, SourceSchema, diags[0].Source)
	assert.Equal(t, SeverityError, diags[0].Severity)
	assert.Contains(t, diags[0].Message, "metadata.name")
	assert.Greater(t, diags[0].Location.Start.Line, 0)
}

func TestLintStructure_MissingMetadataSection(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
spec: {}
`
	diags := lintStructure([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, SourceSchema, diags[0].Source)
	assert.Contains(t, diags[0].Message, "metadata")
}

func TestLintStructure_ValidDomain(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      rego: |
        package authz
        default allow = true
`
	diags := lintStructure([]byte(yaml), "test.yml")
	assert.Empty(t, diags)
}

func TestLintStructure_DuplicatePolicyMRN(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      rego: |
        package authz
        default allow = true
    - mrn: "mrn:iam:policy:allow-all"
      rego: |
        package authz
        default allow = false
`
	diags := lintStructure([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, SourceDuplicate, diags[0].Source)
	assert.Equal(t, SeverityError, diags[0].Severity)
	assert.Equal(t, "policy", diags[0].Entity.Type)
	assert.Equal(t, "mrn:iam:policy:allow-all", diags[0].Entity.ID)
	assert.Greater(t, diags[0].Location.Start.Line, 0)
}

func TestLintStructure_DuplicateRoleMRN(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      rego: |
        package authz
        default allow = true
  roles:
    - mrn: "mrn:iam:role:admin"
      policy: "mrn:iam:policy:allow-all"
    - mrn: "mrn:iam:role:admin"
      policy: "mrn:iam:policy:allow-all"
`
	diags := lintStructure([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, SourceDuplicate, diags[0].Source)
	assert.Equal(t, "role", diags[0].Entity.Type)
	assert.Equal(t, "mrn:iam:role:admin", diags[0].Entity.ID)
}

func TestLintStructure_MissingRegoOnPolicy(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:no-rego"
`
	diags := lintStructure([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, SourceSchema, diags[0].Source)
	assert.Equal(t, "policy", diags[0].Entity.Type)
	assert.Equal(t, "rego", diags[0].Entity.Field)
}

func TestLintStructure_EmptyRegoOnPolicy(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:empty-rego"
      rego: ""
`
	diags := lintStructure([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, SourceSchema, diags[0].Source)
	assert.Equal(t, "rego", diags[0].Entity.Field)
}

func TestLintStructure_MissingSelectorOnOperation(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      rego: |
        package authz
        default allow = true
  operations:
    - mrn: "mrn:iam:operation:read"
      policy: "mrn:iam:policy:allow-all"
`
	diags := lintStructure([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, SourceSchema, diags[0].Source)
	assert.Equal(t, "operation", diags[0].Entity.Type)
	assert.Equal(t, "selector", diags[0].Entity.Field)
}

func TestLintStructure_MissingMRNOnRole(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  roles:
    - policy: "mrn:iam:policy:allow-all"
`
	diags := lintStructure([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, SourceSchema, diags[0].Source)
	assert.Equal(t, "role", diags[0].Entity.Type)
}

func TestLintStructure_MultipleIssues(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: ""
spec:
  policies:
    - mrn: "mrn:iam:policy:a"
      rego: |
        package authz
        default allow = true
    - mrn: "mrn:iam:policy:a"
      rego: |
        package authz
        default allow = false
    - mrn: "mrn:iam:policy:no-rego"
`
	diags := lintStructure([]byte(yaml), "test.yml")
	// Expect: empty name error + duplicate policy + missing rego on third policy
	assert.GreaterOrEqual(t, len(diags), 3)
	sources := make(map[Source]int)
	for _, d := range diags {
		sources[d.Source]++
	}
	assert.Greater(t, sources[SourceSchema], 0)
	assert.Greater(t, sources[SourceDuplicate], 0)
}

func TestLintStructure_ValidMetaNoSpec(t *testing.T) {
	// Valid metadata.name but no spec section → only the name diagnostic is absent,
	// function returns diagnostics (no spec) without panicking.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
`
	diags := lintStructure([]byte(yaml), "test.yml")
	assert.Empty(t, diags)
}

func TestLintStructure_SpecIsScalar(t *testing.T) {
	// spec is a scalar string rather than a mapping — should return early.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec: "not-a-mapping"
`
	diags := lintStructure([]byte(yaml), "test.yml")
	assert.Empty(t, diags)
}

func TestLintStructureList_NonMappingItem(t *testing.T) {
	// A sequence entry that is a scalar (not a mapping) should be silently skipped.
	seq := &yaml.Node{
		Kind: yaml.SequenceNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "just-a-string"},
			{Kind: yaml.MappingNode, Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "mrn"},
				{Kind: yaml.ScalarNode, Value: "mrn:iam:policy:ok"},
				{Kind: yaml.ScalarNode, Value: "rego"},
				{Kind: yaml.ScalarNode, Value: "package authz"},
			}},
		},
	}
	diags := lintStructureList(seq, "policy", "my-domain", "test.yml", true, false)
	// Second item is valid — no dup, has rego. First item is skipped.
	assert.Empty(t, diags)
}

func TestLintStructure_BadYAML(t *testing.T) {
	// Bad YAML should produce no structural diagnostics (lintYAML handles those).
	diags := lintStructure([]byte("{{{{invalid yaml"), "test.yml")
	assert.Empty(t, diags)
}

func TestLintStructure_EmptyDocument(t *testing.T) {
	// Empty/null YAML produces a non-document root node — early return with no diagnostics.
	diags := lintStructure([]byte(""), "test.yml")
	assert.Empty(t, diags)
}

func TestLintStructure_RootIsScalar(t *testing.T) {
	// YAML document whose root content is a scalar (not a mapping) — early return.
	diags := lintStructure([]byte("42"), "test.yml")
	assert.Empty(t, diags)
}

// --- v1beta1-style map section tests (lintStructureMap) ---

func TestLintStructure_V1beta1MapDuplicatePolicy(t *testing.T) {
	// v1beta1 uses map-style sections keyed by name; yaml.v3 preserves both
	// duplicate keys in Content, so duplication is detectable.
	yaml := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policies:
    allow-all:
      rego: |
        package authz
        default allow = true
    allow-all:
      rego: |
        package authz
        default allow = false
`
	diags := lintStructure([]byte(yaml), "test.yml")
	dupDiags := filterSource(diags, SourceDuplicate)
	require.Len(t, dupDiags, 1)
	assert.Equal(t, "policy", dupDiags[0].Entity.Type)
	assert.Equal(t, "allow-all", dupDiags[0].Entity.ID)
	assert.Greater(t, dupDiags[0].Location.Start.Line, 0)
}

func TestLintStructure_V1beta1MapMissingRego(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policies:
    no-rego-policy:
      dependencies: []
`
	diags := lintStructure([]byte(yaml), "test.yml")
	schemaDiags := filterSource(diags, SourceSchema)
	require.NotEmpty(t, schemaDiags)
	hasRego := false
	for _, d := range schemaDiags {
		if d.Entity.Field == "rego" {
			hasRego = true
		}
	}
	assert.True(t, hasRego, "expected SourceSchema diagnostic for missing rego")
}

func TestLintStructure_V1beta1MapValidPolicies(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policies:
    allow-all:
      rego: |
        package authz
        default allow = true
    deny-all:
      rego: |
        package authz
        default allow = false
`
	diags := lintStructure([]byte(yaml), "test.yml")
	assert.Empty(t, diags)
}

func TestLintStructure_V1beta1MapEmptySelector(t *testing.T) {
	// Mapper with an empty selector sequence.
	yaml := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  mappers:
    my-mapper:
      rego: |
        package mapper
      selector: []
`
	diags := lintStructure([]byte(yaml), "test.yml")
	schemaDiags := filterSource(diags, SourceSchema)
	require.NotEmpty(t, schemaDiags)
	hasSel := false
	for _, d := range schemaDiags {
		if d.Entity.Field == "selector" {
			hasSel = true
		}
	}
	assert.True(t, hasSel, "expected SourceSchema diagnostic for empty selector")
}

func TestLintStructure_EmptySelectorSequence(t *testing.T) {
	// List-style operation with an explicitly empty selector sequence.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  operations:
    - mrn: "mrn:iam:operation:read"
      selector: []
      policy: "mrn:iam:policy:allow-all"
`
	diags := lintStructure([]byte(yaml), "test.yml")
	require.Len(t, diags, 1)
	assert.Equal(t, SourceSchema, diags[0].Source)
	assert.Equal(t, "selector", diags[0].Entity.Field)
	assert.Greater(t, diags[0].Location.Start.Line, 0)
}

func TestLintStructure_V1beta1MapEmptyKey(t *testing.T) {
	// yaml.v3 cannot actually produce an empty key from normal YAML, but the
	// MappingNode walker handles it defensively. We test via lintStructureMap
	// directly using a hand-crafted node.
	m := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: ""},              // empty key
			{Kind: yaml.MappingNode, Content: nil},          // value
			{Kind: yaml.ScalarNode, Value: "good-id"},       // valid key
			{Kind: yaml.ScalarNode, Value: "not-a-mapping"}, // scalar value → skipped
		},
	}
	diags := lintStructureMap(m, "policy", "my-domain", "test.yml", false, false)
	require.Len(t, diags, 1)
	assert.Equal(t, SourceSchema, diags[0].Source)
	assert.Contains(t, diags[0].Message, "empty key")
}

func TestLintStructure_V1beta1MapNonMappingValue(t *testing.T) {
	// If a map entry's value is a scalar (not a mapping), it should be skipped
	// without panicking.
	m := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "my-policy"},
			{Kind: yaml.ScalarNode, Value: "not-a-mapping"},
		},
	}
	diags := lintStructureMap(m, "policy", "my-domain", "test.yml", true, false)
	// No rego check because value isn't a mapping — no crash, no diagnostics.
	assert.Empty(t, diags)
}

// filterSource is a test helper that returns only diagnostics with the given source.
func filterSource(diags []Diagnostic, src Source) []Diagnostic {
	var out []Diagnostic
	for _, d := range diags {
		if d.Source == src {
			out = append(out, d)
		}
	}
	return out
}

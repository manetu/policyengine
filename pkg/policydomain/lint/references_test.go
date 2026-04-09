//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseIndexID(t *testing.T) {
	tests := []struct {
		id     string
		want   int
		wantOK bool
	}{
		{"operation[0]", 0, true},
		{"resource[3]", 3, true},
		{"operation[10]", 10, true},
		{"mrn:iam:role:admin", 0, false},
		{"noindex", 0, false},
		{"bad[]", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, ok := parseIndexID(tt.id)
			assert.Equal(t, tt.wantOK, ok)
			if ok {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestFindReferencePosition_Role(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  roles:
    - mrn: "mrn:iam:role:admin"
      policy: "mrn:iam:policy:nonexistent"
`
	pos := findReferencePosition([]byte(yaml), "role", "mrn:iam:role:admin", "policy")
	assert.Greater(t, pos.Line, 0, "expected non-zero line for policy field")
}

func TestFindReferencePosition_Operation(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  operations:
    - mrn: "mrn:iam:operation:read"
      selector:
        - ".*"
      policy: "mrn:iam:policy:nonexistent"
`
	pos := findReferencePosition([]byte(yaml), "operation", "operation[0]", "policy")
	assert.Greater(t, pos.Line, 0, "expected non-zero line for operation policy field")
}

func TestFindReferencePosition_Resource(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  resources:
    - selector:
        - ".*"
      group: "mrn:iam:resource-group:nonexistent"
`
	pos := findReferencePosition([]byte(yaml), "resource", "resource[0]", "group")
	assert.Greater(t, pos.Line, 0, "expected non-zero line for resource group field")
}

func TestFindReferencePosition_Library(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policy-libraries:
    - mrn: "mrn:iam:library:mylib"
      rego: |
        package lib
      dependencies:
        - "mrn:iam:library:nonexistent"
`
	pos := findReferencePosition([]byte(yaml), "library", "mrn:iam:library:mylib", "dependencies")
	assert.Greater(t, pos.Line, 0, "expected non-zero line for library dependencies field")
}

func TestFindReferencePosition_Group(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  groups:
    - mrn: "mrn:iam:group:admins"
      roles:
        - "mrn:iam:role:nonexistent"
`
	pos := findReferencePosition([]byte(yaml), "group", "mrn:iam:group:admins", "roles[0]")
	assert.Greater(t, pos.Line, 0, "expected non-zero line for group roles field")
}

func TestFindReferencePosition_NotFound(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  roles:
    - mrn: "mrn:iam:role:admin"
      policy: "mrn:iam:policy:allow-all"
`
	// Entity not present should return zero position.
	pos := findReferencePosition([]byte(yaml), "role", "mrn:iam:role:nonexistent", "policy")
	assert.Equal(t, 0, pos.Line)
}

func TestEnrichReferenceLocations_PopulatesLine(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  roles:
    - mrn: "mrn:iam:role:admin"
      policy: "mrn:iam:policy:nonexistent"
`
	rawData := map[string][]byte{"test.yml": []byte(yaml)}
	domainKeyMap := map[string]string{"my-domain": "test.yml"}

	diagnostics := []Diagnostic{
		{
			Source:   SourceReference,
			Severity: SeverityError,
			Entity:   Entity{Domain: "my-domain", Type: "role", ID: "mrn:iam:role:admin", Field: "policy"},
			Location: Location{File: "test.yml"},
			Message:  "policy not found",
		},
	}

	enriched := enrichReferenceLocations(diagnostics, rawData, domainKeyMap)
	assert.Greater(t, enriched[0].Location.Start.Line, 0, "expected line to be populated")
}

func TestEnrichReferenceLocations_SkipsNonReference(t *testing.T) {
	diagnostics := []Diagnostic{
		{
			Source:   SourceCycle,
			Severity: SeverityError,
			Message:  "cycle error",
		},
	}

	rawData := map[string][]byte{}
	domainKeyMap := map[string]string{}

	enriched := enrichReferenceLocations(diagnostics, rawData, domainKeyMap)
	// Cycle diagnostics should be unchanged (line stays 0).
	assert.Equal(t, 0, enriched[0].Location.Start.Line)
}

func TestEnrichReferenceLocations_UnknownDomain(t *testing.T) {
	// Domain not in domainKeyMap → fileKey is empty → skip enrichment.
	diagnostics := []Diagnostic{
		{
			Source:   SourceReference,
			Severity: SeverityError,
			Entity:   Entity{Domain: "unknown-domain", Type: "role", ID: "x", Field: "policy"},
			Location: Location{File: "test.yml"},
			Message:  "missing",
		},
	}
	enriched := enrichReferenceLocations(diagnostics, map[string][]byte{}, map[string]string{})
	assert.Equal(t, 0, enriched[0].Location.Start.Line)
}

func TestEnrichReferenceLocations_SkipsAlreadyPositioned(t *testing.T) {
	diagnostics := []Diagnostic{
		{
			Source:   SourceReference,
			Severity: SeverityError,
			Entity:   Entity{Domain: "my-domain", Type: "role", ID: "mrn:iam:role:admin", Field: "policy"},
			Location: Location{File: "test.yml", Start: Position{Line: 42, Column: 5}},
			Message:  "already has position",
		},
	}

	rawData := map[string][]byte{}
	domainKeyMap := map[string]string{"my-domain": "test.yml"}

	enriched := enrichReferenceLocations(diagnostics, rawData, domainKeyMap)
	// Should not modify pre-populated position.
	assert.Equal(t, 42, enriched[0].Location.Start.Line)
}

func TestEnrichReferenceLocations_MissingFileKey(t *testing.T) {
	// Domain exists in domainKeyMap but rawData has no entry → skip enrichment.
	diagnostics := []Diagnostic{
		{
			Source:   SourceReference,
			Severity: SeverityError,
			Entity:   Entity{Domain: "ghost-domain", Type: "role", ID: "mrn:iam:role:x", Field: "policy"},
			Location: Location{File: "ghost.yml"},
			Message:  "missing",
		},
	}
	rawData := map[string][]byte{}
	domainKeyMap := map[string]string{"ghost-domain": "ghost.yml"}

	enriched := enrichReferenceLocations(diagnostics, rawData, domainKeyMap)
	assert.Equal(t, 0, enriched[0].Location.Start.Line)
}

func TestFindReferencePosition_Scope(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  scopes:
    - mrn: "mrn:iam:scope:read"
      policy: "mrn:iam:policy:nonexistent"
`
	pos := findReferencePosition([]byte(yaml), "scope", "mrn:iam:scope:read", "policy")
	assert.Greater(t, pos.Line, 0)
}

func TestFindReferencePosition_ResourceGroup(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  resource-groups:
    - mrn: "mrn:iam:resource-group:files"
      policy: "mrn:iam:policy:nonexistent"
`
	pos := findReferencePosition([]byte(yaml), "resource-group", "mrn:iam:resource-group:files", "policy")
	assert.Greater(t, pos.Line, 0)
}

func TestFindReferencePosition_ResourceGroupAltKey(t *testing.T) {
	// v1beta1-style uses "resourceGroups" (camelCase) as section key.
	yaml := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  resourceGroups:
    - mrn: "mrn:iam:resource-group:files"
      policy: "mrn:iam:policy:nonexistent"
`
	pos := findReferencePosition([]byte(yaml), "resource-group", "mrn:iam:resource-group:files", "policy")
	assert.Greater(t, pos.Line, 0)
}

func TestFindReferencePosition_V1beta1MapLibrary(t *testing.T) {
	// v1beta1-style policy-libraries as a map (uses "policyLibraries" key).
	yaml := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policyLibraries:
    my-lib:
      rego: |
        package lib
      dependencies:
        - "mrn:iam:library:nonexistent"
`
	pos := findReferencePosition([]byte(yaml), "library", "my-lib", "dependencies")
	assert.Greater(t, pos.Line, 0)
}

func TestFindReferencePosition_BadYAML(t *testing.T) {
	pos := findReferencePosition([]byte("{{{{invalid"), "role", "x", "policy")
	assert.Equal(t, 0, pos.Line)
}

func TestFindReferencePosition_UnknownEntityType(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec: {}
`
	pos := findReferencePosition([]byte(yaml), "unknown-type", "some-id", "field")
	assert.Equal(t, 0, pos.Line)
}

func TestFindReferencePosition_NoSpec(t *testing.T) {
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
`
	pos := findReferencePosition([]byte(yaml), "role", "mrn:iam:role:admin", "policy")
	assert.Equal(t, 0, pos.Line)
}

func TestFindReferencePosition_FieldFallbackToEntity(t *testing.T) {
	// Field doesn't exist on entity — should fall back to entity mapping position.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  roles:
    - mrn: "mrn:iam:role:admin"
      policy: "mrn:iam:policy:allow-all"
`
	pos := findReferencePosition([]byte(yaml), "role", "mrn:iam:role:admin", "nonexistent-field")
	// Falls back to entity line.
	assert.Greater(t, pos.Line, 0)
}

func TestFindReferencePosition_Policy(t *testing.T) {
	// Exercises the "policy" → "policies" branch in entitySectionKey.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      rego: |
        package authz
      dependencies:
        - "mrn:iam:library:nonexistent"
`
	pos := findReferencePosition([]byte(yaml), "policy", "mrn:iam:policy:allow-all", "dependencies")
	assert.Greater(t, pos.Line, 0)
}

func TestFindReferencePosition_SectionMissing(t *testing.T) {
	// Entity type whose section doesn't exist in the YAML at all → zero pos.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  roles:
    - mrn: "mrn:iam:role:admin"
      policy: "mrn:iam:policy:allow-all"
`
	// "scope" section is absent — both primary and alt key return nil.
	pos := findReferencePosition([]byte(yaml), "scope", "mrn:iam:scope:read", "policy")
	assert.Equal(t, 0, pos.Line)
}

func TestFindFieldInList_NameFallback(t *testing.T) {
	// Entities without "mrn" but with "name" should be matched by name.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  operations:
    - name: "my-op"
      selector:
        - ".*"
      policy: "mrn:iam:policy:nonexistent"
`
	pos := findReferencePosition([]byte(yaml), "operation", "operation[0]", "policy")
	assert.Greater(t, pos.Line, 0)
}

func TestFindFieldInList_LookupByName(t *testing.T) {
	// When entity uses "name" instead of "mrn", MRN-based lookup falls back to name.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  roles:
    - name: "my-role"
      policy: "mrn:iam:policy:nonexistent"
`
	// Entity ID matches "name" field (not an index-based ID).
	pos := findReferencePosition([]byte(yaml), "role", "my-role", "policy")
	assert.Greater(t, pos.Line, 0)
}

func TestFindReferencePosition_EmptyBytes(t *testing.T) {
	// Empty input produces a zero-kind root (not DocumentNode) — return zero.
	pos := findReferencePosition([]byte(""), "role", "x", "policy")
	assert.Equal(t, 0, pos.Line)
}

func TestFindReferencePosition_RootIsSequence(t *testing.T) {
	// YAML root is a sequence, not a document with a mapping — should return zero.
	yaml := `- item1
- item2
`
	pos := findReferencePosition([]byte(yaml), "role", "x", "policy")
	assert.Equal(t, 0, pos.Line)
}

func TestFindReferencePosition_SectionIsScalar(t *testing.T) {
	// Section key exists but is a scalar, not a sequence or mapping — returns zero.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  roles: "not-a-sequence"
`
	pos := findReferencePosition([]byte(yaml), "role", "mrn:iam:role:x", "policy")
	assert.Equal(t, 0, pos.Line)
}

func TestFindFieldInList_NonMappingItem(t *testing.T) {
	// A scalar item in a sequence should be skipped without panicking.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  roles:
    - "just-a-scalar"
    - mrn: "mrn:iam:role:admin"
      policy: "mrn:iam:policy:allow-all"
`
	// Entity not found (scalar skipped, "my-role" doesn't match) → zero pos.
	pos := findReferencePosition([]byte(yaml), "role", "mrn:iam:role:nonexistent", "policy")
	assert.Equal(t, 0, pos.Line)
}

func TestFindFieldInList_IndexOutOfBounds(t *testing.T) {
	// Requesting index 99 on a single-entry list → zero position.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  operations:
    - mrn: "mrn:iam:operation:read"
      selector:
        - ".*"
      policy: "mrn:iam:policy:allow-all"
`
	pos := findReferencePosition([]byte(yaml), "operation", "operation[99]", "policy")
	assert.Equal(t, 0, pos.Line)
}

func TestFindFieldInMap_EntityNotFound(t *testing.T) {
	// Looking up a non-existent entity ID in a v1beta1 map section → zero pos.
	yaml := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: my-domain
spec:
  policyLibraries:
    existing-lib:
      rego: |
        package lib
`
	pos := findReferencePosition([]byte(yaml), "library", "nonexistent-lib", "dependencies")
	assert.Equal(t, 0, pos.Line)
}

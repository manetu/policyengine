//
//  Copyright © Manetu Inc. All rights reserved.
//

package v1alpha3

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ValidPolicyDomain(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: test-domain
spec:
  policy-libraries:
    - mrn: "mrn:iam:library:utils"
      name: utils
      description: "Utility functions"
      rego: |
        package utils
        helper := true
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      name: allow-all
      description: "Allow all policy"
      rego: |
        package authz
        default allow = true
    - mrn: "mrn:iam:policy:with-deps"
      name: with-deps
      description: "Policy with dependencies"
      dependencies:
        - "mrn:iam:library:utils"
      rego: |
        package authz
        import data.utils
        allow { utils.helper }
  roles:
    - mrn: "mrn:iam:role:admin"
      name: admin
      description: "Admin role"
      default: true
      policy: "mrn:iam:policy:allow-all"
      annotations:
        - name: level
          value: "\"high\""
  groups:
    - mrn: "mrn:iam:group:admins"
      name: admins
      description: "Admin group"
      roles:
        - "mrn:iam:role:admin"
      annotations:
        - name: team
          value: "\"platform\""
  resource-groups:
    - mrn: "mrn:iam:resource-group:default"
      name: default
      description: "Default resource group"
      default: true
      policy: "mrn:iam:policy:allow-all"
  scopes:
    - mrn: "mrn:iam:scope:api"
      name: api
      description: "API scope"
      policy: "mrn:iam:policy:allow-all"
  operations:
    - name: read-ops
      selector:
        - ".*:read"
        - ".*:get"
      policy: "mrn:iam:policy:allow-all"
  mappers:
    - name: test-mapper
      selector:
        - ".*"
      rego: |
        package mapper
        porc := {"principal": {}, "operation": "test", "resource": {}, "context": {}}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	model, err := Load(tmpFile)
	require.NoError(t, err)

	// Verify name
	assert.Equal(t, "test-domain", model.Name)

	// Verify policy libraries
	assert.Len(t, model.PolicyLibraries, 1)
	lib, ok := model.PolicyLibraries["mrn:iam:library:utils"]
	assert.True(t, ok)
	assert.Equal(t, "mrn:iam:library:utils", lib.IDSpec.ID)
	assert.Contains(t, lib.Rego, "package utils")

	// Verify policies
	assert.Len(t, model.Policies, 2)
	policy, ok := model.Policies["mrn:iam:policy:allow-all"]
	assert.True(t, ok)
	assert.Contains(t, policy.Rego, "default allow = true")

	policyWithDeps, ok := model.Policies["mrn:iam:policy:with-deps"]
	assert.True(t, ok)
	assert.Contains(t, policyWithDeps.Dependencies, "mrn:iam:library:utils")

	// Verify roles
	assert.Len(t, model.Roles, 1)
	role, ok := model.Roles["mrn:iam:role:admin"]
	assert.True(t, ok)
	assert.Equal(t, "mrn:iam:policy:allow-all", role.Policy)
	assert.True(t, role.Default)
	assert.Contains(t, role.Annotations, "level")

	// Verify groups
	assert.Len(t, model.Groups, 1)
	group, ok := model.Groups["mrn:iam:group:admins"]
	assert.True(t, ok)
	assert.Contains(t, group.Roles, "mrn:iam:role:admin")
	assert.Contains(t, group.Annotations, "team")

	// Verify resource groups
	assert.Len(t, model.ResourceGroups, 1)
	rg, ok := model.ResourceGroups["mrn:iam:resource-group:default"]
	assert.True(t, ok)
	assert.True(t, rg.Default)

	// Verify scopes
	assert.Len(t, model.Scopes, 1)
	scope, ok := model.Scopes["mrn:iam:scope:api"]
	assert.True(t, ok)
	assert.Equal(t, "mrn:iam:policy:allow-all", scope.Policy)

	// Verify operations
	assert.Len(t, model.Operations, 1)
	assert.Equal(t, "read-ops", model.Operations[0].IDSpec.ID)
	assert.Len(t, model.Operations[0].Selectors, 2)

	// Verify mappers
	assert.Len(t, model.Mappers, 1)
	assert.Equal(t, "test-mapper", model.Mappers[0].IDSpec.ID)
	assert.Contains(t, model.Mappers[0].Rego, "package mapper")
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/file.yml")
	assert.Error(t, err)
}

func TestLoad_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid.yml")
	err := os.WriteFile(tmpFile, []byte("invalid: yaml: : content"), 0644)
	require.NoError(t, err)

	_, err = Load(tmpFile)
	assert.Error(t, err)
}

func TestLoad_InvalidOperationSelector(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: test
spec:
  policies:
    - mrn: "mrn:iam:policy:test"
      name: test
      rego: |
        package authz
        default allow = true
  operations:
    - name: invalid-op
      selector:
        - "[invalid regex"
      policy: "mrn:iam:policy:test"
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid-selector.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	_, err = Load(tmpFile)
	assert.Error(t, err)
}

func TestLoad_InvalidMapperSelector(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: test
spec:
  mappers:
    - name: invalid-mapper
      selector:
        - "[invalid regex"
      rego: |
        package mapper
        porc := {}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid-mapper.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	_, err = Load(tmpFile)
	assert.Error(t, err)
}

func TestAnchorPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no anchors",
			input:    ".*",
			expected: "^.*$",
		},
		{
			name:     "start anchor only",
			input:    "^test",
			expected: "^test$",
		},
		{
			name:     "end anchor only",
			input:    "test$",
			expected: "^test$",
		},
		{
			name:     "both anchors",
			input:    "^test$",
			expected: "^test$",
		},
		{
			name:     "complex pattern",
			input:    "mrn:.*:read",
			expected: "^mrn:.*:read$",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := anchorPattern(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExportDefinition(t *testing.T) {
	def := PolicyDefinition{
		Mrn:          "mrn:iam:policy:test",
		Name:         "test",
		Description:  "Test policy",
		Rego:         "package authz\ndefault allow = true",
		Dependencies: []string{"mrn:iam:library:utils"},
	}

	result := exportDefinition(def)
	assert.Equal(t, "mrn:iam:policy:test", result.IDSpec.ID)
	assert.NotEmpty(t, result.IDSpec.Fingerprint)
	assert.Equal(t, def.Rego, result.Rego)
	assert.Equal(t, def.Dependencies, result.Dependencies)
}

func TestExportDefinitions(t *testing.T) {
	defs := []PolicyDefinition{
		{Mrn: "mrn:policy:1", Rego: "package authz\ndefault allow = true"},
		{Mrn: "mrn:policy:2", Rego: "package authz\ndefault allow = false"},
	}

	result := exportDefinitions(defs)
	assert.Len(t, result, 2)
	assert.Contains(t, result, "mrn:policy:1")
	assert.Contains(t, result, "mrn:policy:2")
}

func TestExportReference(t *testing.T) {
	ref := PolicyReference{
		Mrn:     "mrn:iam:role:admin",
		Name:    "admin",
		Default: true,
		Policy:  "mrn:iam:policy:allow-all",
		Annotations: []Annotation{
			{Name: "level", Value: "\"high\""},
		},
	}

	result := exportReference(ref)
	assert.Equal(t, "mrn:iam:role:admin", result.IDSpec.ID)
	assert.Equal(t, "mrn:iam:policy:allow-all", result.Policy)
	assert.True(t, result.Default)
	assert.Contains(t, result.Annotations, "level")
	assert.Equal(t, "\"high\"", result.Annotations["level"].Value)
}

func TestExportReferences(t *testing.T) {
	refs := []PolicyReference{
		{Mrn: "mrn:role:1", Policy: "mrn:policy:1"},
		{Mrn: "mrn:role:2", Policy: "mrn:policy:2"},
	}

	result := exportReferences(refs)
	assert.Len(t, result, 2)
	assert.Contains(t, result, "mrn:role:1")
	assert.Contains(t, result, "mrn:role:2")
}

func TestExportGroup(t *testing.T) {
	grp := Group{
		Mrn:   "mrn:iam:group:admins",
		Name:  "admins",
		Roles: []string{"mrn:iam:role:admin"},
		Annotations: []Annotation{
			{Name: "team", Value: "\"platform\""},
		},
	}

	result := exportGroup(grp)
	assert.Equal(t, "mrn:iam:group:admins", result.IDSpec.ID)
	assert.Contains(t, result.Roles, "mrn:iam:role:admin")
	assert.Contains(t, result.Annotations, "team")
}

func TestExportGroups(t *testing.T) {
	groups := []Group{
		{Mrn: "mrn:group:1", Roles: []string{"mrn:role:1"}},
		{Mrn: "mrn:group:2", Roles: []string{"mrn:role:2"}},
	}

	result := exportGroups(groups)
	assert.Len(t, result, 2)
	assert.Contains(t, result, "mrn:group:1")
	assert.Contains(t, result, "mrn:group:2")
}

func TestExportOperation(t *testing.T) {
	op := Operation{
		Name:     "read-ops",
		Selector: []string{".*:read", ".*:get"},
		Policy:   "mrn:iam:policy:read-only",
	}

	result, err := exportOperation(op)
	require.NoError(t, err)
	assert.Equal(t, "read-ops", result.IDSpec.ID)
	assert.Equal(t, "mrn:iam:policy:read-only", result.Policy)
	assert.Len(t, result.Selectors, 2)
}

func TestExportOperation_InvalidSelector(t *testing.T) {
	op := Operation{
		Name:     "invalid",
		Selector: []string{"[invalid"},
		Policy:   "mrn:policy:test",
	}

	_, err := exportOperation(op)
	assert.Error(t, err)
}

func TestExportOperations(t *testing.T) {
	ops := []Operation{
		{Name: "op1", Selector: []string{".*"}, Policy: "mrn:policy:1"},
		{Name: "op2", Selector: []string{"test.*"}, Policy: "mrn:policy:2"},
	}

	result, err := exportOperations(ops)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestExportOperations_InvalidSelector(t *testing.T) {
	ops := []Operation{
		{Name: "valid", Selector: []string{".*"}, Policy: "mrn:policy:1"},
		{Name: "invalid", Selector: []string{"[invalid"}, Policy: "mrn:policy:2"},
	}

	_, err := exportOperations(ops)
	assert.Error(t, err)
}

func TestExportMapper(t *testing.T) {
	mapper := Mapper{
		Name:     "test-mapper",
		Selector: []string{".*", "test.*"},
		Rego:     "package mapper\nporc := {}",
	}

	result, err := exportMapper(mapper)
	require.NoError(t, err)
	assert.Equal(t, "test-mapper", result.IDSpec.ID)
	assert.NotEmpty(t, result.IDSpec.Fingerprint)
	assert.Len(t, result.Selectors, 2)
	assert.Equal(t, mapper.Rego, result.Rego)
}

func TestExportMapper_InvalidSelector(t *testing.T) {
	mapper := Mapper{
		Name:     "invalid",
		Selector: []string{"[invalid"},
		Rego:     "package mapper",
	}

	_, err := exportMapper(mapper)
	assert.Error(t, err)
}

func TestExportMappers(t *testing.T) {
	mappers := []Mapper{
		{Name: "mapper1", Selector: []string{".*"}, Rego: "package mapper\nporc := {}"},
		{Name: "mapper2", Selector: []string{"test.*"}, Rego: "package mapper\nporc := {}"},
	}

	result, err := exportMappers(mappers)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestExportMappers_InvalidSelector(t *testing.T) {
	mappers := []Mapper{
		{Name: "valid", Selector: []string{".*"}, Rego: "package mapper"},
		{Name: "invalid", Selector: []string{"[invalid"}, Rego: "package mapper"},
	}

	_, err := exportMappers(mappers)
	assert.Error(t, err)
}

func TestLoad_EmptySpec(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: empty-domain
spec: {}
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	model, err := Load(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, "empty-domain", model.Name)
	assert.Empty(t, model.Policies)
	assert.Empty(t, model.Roles)
	assert.Empty(t, model.Operations)
}

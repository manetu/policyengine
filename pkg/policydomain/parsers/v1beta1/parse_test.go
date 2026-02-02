//
//  Copyright © Manetu Inc. All rights reserved.
//

package v1beta1

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ValidPolicyDomain(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: test-domain
spec:
  annotation-defaults:
    merge: deep
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
          value: high
          merge: replace
        - name: priority
          value: 100
  groups:
    - mrn: "mrn:iam:group:admins"
      name: admins
      description: "Admin group"
      roles:
        - "mrn:iam:role:admin"
      annotations:
        - name: team
          value: platform
          merge: append
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
  resources:
    - name: sensitive-data
      description: "Sensitive resources"
      selector:
        - "mrn:data:sensitive:.*"
      group: "mrn:iam:resource-group:default"
      annotations:
        - name: classification
          value: HIGH
          merge: replace
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	model, err := Load(tmpFile)
	require.NoError(t, err)

	// Verify name
	assert.Equal(t, "test-domain", model.Name)

	// Verify annotation defaults
	assert.Equal(t, "deep", model.AnnotationDefaults.MergeStrategy)

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

	// Verify roles with native annotations and merge strategy
	assert.Len(t, model.Roles, 1)
	role, ok := model.Roles["mrn:iam:role:admin"]
	assert.True(t, ok)
	assert.Equal(t, "mrn:iam:policy:allow-all", role.Policy)
	assert.True(t, role.Default)
	assert.Contains(t, role.Annotations, "level")
	assert.Equal(t, "high", role.Annotations["level"].Value) // Native string, not JSON-encoded
	assert.Equal(t, "replace", role.Annotations["level"].MergeStrategy)
	assert.Contains(t, role.Annotations, "priority")
	assert.Equal(t, 100, role.Annotations["priority"].Value) // Native number

	// Verify groups with annotations
	assert.Len(t, model.Groups, 1)
	group, ok := model.Groups["mrn:iam:group:admins"]
	assert.True(t, ok)
	assert.Contains(t, group.Roles, "mrn:iam:role:admin")
	assert.Contains(t, group.Annotations, "team")
	assert.Equal(t, "platform", group.Annotations["team"].Value) // Native string
	assert.Equal(t, "append", group.Annotations["team"].MergeStrategy)

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

	// Verify resources
	assert.Len(t, model.Resources, 1)
	assert.Equal(t, "sensitive-data", model.Resources[0].IDSpec.ID)
	assert.Equal(t, "mrn:iam:resource-group:default", model.Resources[0].Group)
	assert.Len(t, model.Resources[0].Selectors, 1)
	assert.Contains(t, model.Resources[0].Annotations, "classification")
	assert.Equal(t, "HIGH", model.Resources[0].Annotations["classification"].Value) // Native string
	assert.Equal(t, "replace", model.Resources[0].Annotations["classification"].MergeStrategy)
}

func TestLoad_NativeAnnotationTypes(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: native-annotations-test
spec:
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      name: allow-all
      rego: |
        package authz
        default allow = true
  roles:
    - mrn: "mrn:iam:role:test"
      name: test
      policy: "mrn:iam:policy:allow-all"
      annotations:
        - name: string_val
          value: hello
        - name: number_val
          value: 42
        - name: float_val
          value: 3.14
        - name: bool_val
          value: true
        - name: null_val
          value: null
        - name: array_val
          value:
            - 1
            - 2
            - 3
        - name: object_val
          value:
            key: value
            nested:
              a: 1
              b: 2
  resource-groups:
    - mrn: "mrn:iam:resource-group:default"
      name: default
      default: true
      policy: "mrn:iam:policy:allow-all"
  operations:
    - name: default
      selector:
        - ".*"
      policy: "mrn:iam:policy:allow-all"
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "native-annotations.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	model, err := Load(tmpFile)
	require.NoError(t, err)

	role, ok := model.Roles["mrn:iam:role:test"]
	require.True(t, ok)

	// Test string value
	assert.Equal(t, "hello", role.Annotations["string_val"].Value)

	// Test number value
	assert.Equal(t, 42, role.Annotations["number_val"].Value)

	// Test float value
	assert.Equal(t, 3.14, role.Annotations["float_val"].Value)

	// Test boolean value
	assert.Equal(t, true, role.Annotations["bool_val"].Value)

	// Test null value
	assert.Nil(t, role.Annotations["null_val"].Value)

	// Test array value
	arrayVal, ok := role.Annotations["array_val"].Value.([]interface{})
	require.True(t, ok, "array_val should be a slice")
	assert.Len(t, arrayVal, 3)
	assert.Equal(t, 1, arrayVal[0])
	assert.Equal(t, 2, arrayVal[1])
	assert.Equal(t, 3, arrayVal[2])

	// Test object value
	objVal, ok := role.Annotations["object_val"].Value.(map[string]interface{})
	require.True(t, ok, "object_val should be a map")
	assert.Equal(t, "value", objVal["key"])
	nested, ok := objVal["nested"].(map[string]interface{})
	require.True(t, ok, "nested should be a map")
	assert.Equal(t, 1, nested["a"])
	assert.Equal(t, 2, nested["b"])
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
	content := `apiVersion: iamlite.manetu.io/v1beta1
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
	content := `apiVersion: iamlite.manetu.io/v1beta1
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

func TestLoad_InvalidResourceSelector(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: test
spec:
  resources:
    - name: invalid-resource
      selector:
        - "[invalid regex"
      group: "mrn:iam:resource-group:default"
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid-resource.yml")
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
			{Name: "level", Value: "high", Merge: "replace"}, // Native value, not JSON
		},
	}

	result := exportReference(ref)
	assert.Equal(t, "mrn:iam:role:admin", result.IDSpec.ID)
	assert.Equal(t, "mrn:iam:policy:allow-all", result.Policy)
	assert.True(t, result.Default)
	assert.Contains(t, result.Annotations, "level")
	assert.Equal(t, "high", result.Annotations["level"].Value) // Native value preserved
	assert.Equal(t, "replace", result.Annotations["level"].MergeStrategy)
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
			{Name: "team", Value: "platform", Merge: "append"}, // Native value
		},
	}

	result := exportGroup(grp)
	assert.Equal(t, "mrn:iam:group:admins", result.IDSpec.ID)
	assert.Contains(t, result.Roles, "mrn:iam:role:admin")
	assert.Contains(t, result.Annotations, "team")
	assert.Equal(t, "platform", result.Annotations["team"].Value) // Native value
	assert.Equal(t, "append", result.Annotations["team"].MergeStrategy)
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

func TestExportResource(t *testing.T) {
	resource := Resource{
		Name:        "sensitive-data",
		Description: "Sensitive resources",
		Selector:    []string{"mrn:data:sensitive:.*", "mrn:secret:.*"},
		Group:       "mrn:iam:resource-group:sensitive",
		Annotations: []Annotation{
			{Name: "classification", Value: "HIGH", Merge: "replace"}, // Native value
			{Name: "audit", Value: true},                              // Native boolean
		},
	}

	result, err := exportResource(resource)
	require.NoError(t, err)
	assert.Equal(t, "sensitive-data", result.IDSpec.ID)
	assert.Equal(t, "mrn:iam:resource-group:sensitive", result.Group)
	assert.Len(t, result.Selectors, 2)
	assert.Contains(t, result.Annotations, "classification")
	assert.Equal(t, "HIGH", result.Annotations["classification"].Value) // Native value
	assert.Equal(t, "replace", result.Annotations["classification"].MergeStrategy)
	assert.Contains(t, result.Annotations, "audit")
	assert.Equal(t, true, result.Annotations["audit"].Value) // Native boolean
}

func TestExportResource_InvalidSelector(t *testing.T) {
	resource := Resource{
		Name:     "invalid",
		Selector: []string{"[invalid"},
		Group:    "mrn:group:test",
	}

	_, err := exportResource(resource)
	assert.Error(t, err)
}

func TestExportResources(t *testing.T) {
	resources := []Resource{
		{Name: "res1", Selector: []string{"mrn:res1:.*"}, Group: "mrn:group:1"},
		{Name: "res2", Selector: []string{"mrn:res2:.*"}, Group: "mrn:group:2"},
	}

	result, err := exportResources(resources)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestExportResources_InvalidSelector(t *testing.T) {
	resources := []Resource{
		{Name: "valid", Selector: []string{".*"}, Group: "mrn:group:1"},
		{Name: "invalid", Selector: []string{"[invalid"}, Group: "mrn:group:2"},
	}

	_, err := exportResources(resources)
	assert.Error(t, err)
}

func TestLoad_EmptySpec(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v1beta1
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
	assert.Empty(t, model.Resources)
}

func TestLoad_MultipleResources(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: multi-resource
spec:
  resource-groups:
    - mrn: "mrn:iam:resource-group:default"
      name: default
      default: true
      policy: "mrn:iam:policy:allow-all"
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      name: allow-all
      rego: |
        package authz
        default allow = true
  resources:
    - name: public
      selector:
        - "mrn:public:.*"
      group: "mrn:iam:resource-group:default"
    - name: internal
      selector:
        - "mrn:internal:.*"
        - "mrn:private:.*"
      group: "mrn:iam:resource-group:default"
      annotations:
        - name: visibility
          value: internal
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "multi.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	model, err := Load(tmpFile)
	require.NoError(t, err)
	assert.Len(t, model.Resources, 2)
	assert.Equal(t, "public", model.Resources[0].IDSpec.ID)
	assert.Equal(t, "internal", model.Resources[1].IDSpec.ID)
	assert.Len(t, model.Resources[1].Selectors, 2)
	assert.Equal(t, "internal", model.Resources[1].Annotations["visibility"].Value) // Native string
}

func TestLoad_ComplexNestedAnnotations(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v1beta1
kind: PolicyDomain
metadata:
  name: complex-annotations
spec:
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      name: allow-all
      rego: |
        package authz
        default allow = true
  roles:
    - mrn: "mrn:iam:role:test"
      name: test
      policy: "mrn:iam:policy:allow-all"
      annotations:
        - name: config
          value:
            timeouts:
              read: 30
              write: 60
            retries: 3
            features:
              - auth
              - logging
              - metrics
        - name: regions
          value:
            - us-west
            - us-east
            - eu-west
          merge: union
  resource-groups:
    - mrn: "mrn:iam:resource-group:default"
      name: default
      default: true
      policy: "mrn:iam:policy:allow-all"
  operations:
    - name: default
      selector:
        - ".*"
      policy: "mrn:iam:policy:allow-all"
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "complex.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	model, err := Load(tmpFile)
	require.NoError(t, err)

	role, ok := model.Roles["mrn:iam:role:test"]
	require.True(t, ok)

	// Test complex nested object
	configVal, ok := role.Annotations["config"].Value.(map[string]interface{})
	require.True(t, ok, "config should be a map")

	timeouts, ok := configVal["timeouts"].(map[string]interface{})
	require.True(t, ok, "timeouts should be a map")
	assert.Equal(t, 30, timeouts["read"])
	assert.Equal(t, 60, timeouts["write"])
	assert.Equal(t, 3, configVal["retries"])

	features, ok := configVal["features"].([]interface{})
	require.True(t, ok, "features should be an array")
	assert.Len(t, features, 3)
	assert.Equal(t, "auth", features[0])

	// Test array with merge strategy
	regions, ok := role.Annotations["regions"].Value.([]interface{})
	require.True(t, ok, "regions should be an array")
	assert.Len(t, regions, 3)
	assert.Equal(t, "union", role.Annotations["regions"].MergeStrategy)
}

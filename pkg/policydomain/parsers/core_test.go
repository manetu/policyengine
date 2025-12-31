//
//  Copyright © Manetu Inc. All rights reserved.
//

package parsers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_V1Alpha3(t *testing.T) {
	// Create a temporary v1alpha3 policy domain file
	content := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: test-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      name: allow-all
      description: "Allow all policy"
      rego: |
        package authz
        default allow = true
  roles:
    - mrn: "mrn:iam:role:admin"
      name: admin
      policy: "mrn:iam:policy:allow-all"
  groups:
    - mrn: "mrn:iam:group:admins"
      name: admins
      roles:
        - "mrn:iam:role:admin"
  operations:
    - name: api
      selector:
        - ".*"
      policy: "mrn:iam:policy:allow-all"
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test-v1alpha3.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	model, err := Load(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, "test-domain", model.Name)
	assert.Len(t, model.Policies, 1)
	assert.Contains(t, model.Policies, "mrn:iam:policy:allow-all")
	assert.Len(t, model.Roles, 1)
	assert.Len(t, model.Groups, 1)
	assert.Len(t, model.Operations, 1)
}

func TestLoad_V1Alpha4(t *testing.T) {
	// Create a temporary v1alpha4 policy domain file
	content := `apiVersion: iamlite.manetu.io/v1alpha4
kind: PolicyDomain
metadata:
  name: test-domain-v4
spec:
  annotation-defaults:
    merge: deep
  policies:
    - mrn: "mrn:iam:policy:allow-all"
      name: allow-all
      description: "Allow all policy"
      rego: |
        package authz
        default allow = true
  roles:
    - mrn: "mrn:iam:role:admin"
      name: admin
      policy: "mrn:iam:policy:allow-all"
      annotations:
        - name: level
          value: "\"high\""
          merge: replace
  resources:
    - name: sensitive
      selector:
        - "mrn:data:sensitive:.*"
      group: "mrn:iam:resource-group:default"
      annotations:
        - name: classification
          value: "\"HIGH\""
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test-v1alpha4.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	model, err := Load(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, "test-domain-v4", model.Name)
	assert.Equal(t, "deep", model.AnnotationDefaults.MergeStrategy)
	assert.Len(t, model.Policies, 1)
	assert.Len(t, model.Roles, 1)
	assert.Len(t, model.Resources, 1)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/file.yml")
	assert.Error(t, err)
}

func TestLoad_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid.yml")
	err := os.WriteFile(tmpFile, []byte("invalid: yaml: content:"), 0644)
	require.NoError(t, err)

	_, err = Load(tmpFile)
	assert.Error(t, err)
}

func TestLoad_WrongKind(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v1alpha4
kind: NotPolicyDomain
metadata:
  name: test
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "wrong-kind.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	_, err = Load(tmpFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected PolicyDomain")
}

func TestLoad_UnsupportedVersion(t *testing.T) {
	content := `apiVersion: iamlite.manetu.io/v999
kind: PolicyDomain
metadata:
  name: test
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "unsupported.yml")
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	require.NoError(t, err)

	_, err = Load(tmpFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported PolicyDomain API Version")
}

func TestLoad_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "empty.yml")
	err := os.WriteFile(tmpFile, []byte(""), 0644)
	require.NoError(t, err)

	_, err = Load(tmpFile)
	assert.Error(t, err)
}

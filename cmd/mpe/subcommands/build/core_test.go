//
//  Copyright © Manetu Inc. All rights reserved.
//

package build

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper functions
func createTempFileFromTestData(t *testing.T, testdataFile string) string {
	// Read the testdata file from the test directory
	content, err := os.ReadFile(filepath.Join("test", testdataFile))
	require.NoError(t, err, "Failed to read testdata file: %s", testdataFile)

	// Create temp file with the content
	tmpfile, err := os.CreateTemp("", "test-*.yml")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tmpfile.Name()) })

	_, err = tmpfile.Write(content)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	return tmpfile.Name()
}

func createTempFileWithContent(t *testing.T, content string) string {
	tmpfile, err := os.CreateTemp("", "test-*.yml")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tmpfile.Name()) })

	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	return tmpfile.Name()
}

// TestBuildFile_HappyPath tests the complete happy path with all features
func TestBuildFile_HappyPath(t *testing.T) {
	inputFile := createTempFileFromTestData(t, "beta-ref.yml")

	// Build the file
	result := File(inputFile, "")

	// Verify success
	assert.True(t, result.Success, "Build should succeed")
	assert.Nil(t, result.Error, "Should have no error")
	assert.NotEmpty(t, result.OutputFile, "Should have output file")

	// Cleanup output file
	defer os.Remove(result.OutputFile)

	// Read and verify output
	outputData, err := os.ReadFile(result.OutputFile)
	require.NoError(t, err)
	outputStr := string(outputData)

	// Verify kind changed to PolicyDomain
	assert.Contains(t, outputStr, "kind: PolicyDomain")
	assert.NotContains(t, outputStr, "kind: PolicyDomainReference")

	// Verify no rego_filename remains
	assert.NotContains(t, outputStr, "rego_filename")

	// Verify all rego content is present
	assert.Contains(t, outputStr, "package authz")
	assert.Contains(t, outputStr, "package mapper")

	// Verify YAML style is clean (| not |+ or |-)
	assert.Contains(t, outputStr, "rego: |")
	assert.NotContains(t, outputStr, "rego: |+")
	assert.NotContains(t, outputStr, "rego: |-")

	// Verify inline rego is preserved
	assert.Contains(t, outputStr, "default allow = true")  // allow-all policy
	assert.Contains(t, outputStr, "default allow = false") // no-access policy

	// Verify external rego was loaded (mainapi.rego)
	assert.Contains(t, outputStr, "jwt_ok")
	assert.Contains(t, outputStr, "input.principal != {}")

	// Verify mapper rego was loaded (common-mapper.rego)
	assert.Contains(t, outputStr, "get_default(val, key, _)")
	assert.Contains(t, outputStr, "io.jwt.decode(token)")

	// Verify YAML structure is preserved (roles, groups, etc.)
	assert.Contains(t, outputStr, "roles:")
	assert.Contains(t, outputStr, "groups:")
	assert.Contains(t, outputStr, "resource-groups:")
	assert.Contains(t, outputStr, "scopes:")
	assert.Contains(t, outputStr, "operations:")
	assert.Contains(t, outputStr, "mappers:")

	// Verify output filename generation
	assert.Contains(t, result.OutputFile, "-built.yml")
}

// TestBuildFile_MultipleFiles tests building multiple PolicyDomainReference files
func TestBuildFile_MultipleFiles(t *testing.T) {
	// Build both alpha and beta files
	alphaFile := createTempFileFromTestData(t, "alpha-ref.yml")
	betaFile := createTempFileFromTestData(t, "beta-ref.yml")

	alphaResult := File(alphaFile, "")
	betaResult := File(betaFile, "")

	// Both should succeed
	assert.True(t, alphaResult.Success, "Alpha build should succeed")
	assert.True(t, betaResult.Success, "Beta build should succeed")

	defer os.Remove(alphaResult.OutputFile)
	defer os.Remove(betaResult.OutputFile)

	// Verify alpha output
	alphaData, err := os.ReadFile(alphaResult.OutputFile)
	require.NoError(t, err)
	alphaStr := string(alphaData)

	assert.Contains(t, alphaStr, "kind: PolicyDomain")
	assert.Contains(t, alphaStr, "name: alpha")
	assert.Contains(t, alphaStr, "package utils")
	assert.Contains(t, alphaStr, "package helpers")
	assert.Contains(t, alphaStr, "# This is a test comment that should be preserved")

	// Verify beta output
	betaData, err := os.ReadFile(betaResult.OutputFile)
	require.NoError(t, err)
	betaStr := string(betaData)

	assert.Contains(t, betaStr, "kind: PolicyDomain")
	assert.Contains(t, betaStr, "name: beta")
	assert.Contains(t, betaStr, "package authz")
	assert.Contains(t, betaStr, "package mapper")
}

func TestBuildFile_SameNodeErrorCase(t *testing.T) {
	inputFile := createTempFileFromTestData(t, "error-same-node.yml")

	result := File(inputFile, "")

	// Build should fail
	assert.False(t, result.Success, "Build should fail")
	assert.NotNil(t, result.Error, "Should have error")

	//Error encountered should be "both rego and rego_filename"
	assert.Contains(t, result.Error.Error(), "cannot specify both 'rego' and 'rego_filename'")
}
func TestBuildFile_MissingRegoErrorCase(t *testing.T) {
	inputFile := createTempFileFromTestData(t, "error-missing-rego.yml")

	result := File(inputFile, "")

	// Build should fail
	assert.False(t, result.Success, "Build should fail")
	assert.NotNil(t, result.Error, "Should have error")

	// Error encountered should be "failed to read rego file '/nonexistent/path/missing.rego'"
	assert.Contains(t, result.Error.Error(), "failed to read rego file '/nonexistent/path/missing.rego'")
}
func TestBuildFile_EmptyRegoErrorCase(t *testing.T) {
	inputFile := createTempFileFromTestData(t, "error-empty-rego.yml")

	result := File(inputFile, "")

	// Build should fail
	assert.False(t, result.Success, "Build should fail")
	assert.NotNil(t, result.Error, "Should have error")

	// Error encountered should be "rego_filename cannot be empty"
	assert.Contains(t, result.Error.Error(), "rego_filename cannot be empty")
}

// TestBuildFile_CustomOutputFilename tests specifying a custom output filename
func TestBuildFile_CustomOutputFilename(t *testing.T) {
	inputFile := createTempFileFromTestData(t, "alpha-ref.yml")

	// Create temp output file path
	tmpDir := t.TempDir()
	customOutput := filepath.Join(tmpDir, "custom-output.yml")

	result := File(inputFile, customOutput)

	assert.True(t, result.Success)
	assert.Equal(t, customOutput, result.OutputFile)

	// Verify file exists
	_, err := os.Stat(customOutput)
	assert.NoError(t, err, "Custom output file should exist")
}

// TestGenerateOutputFilename tests the output filename generation
func TestGenerateOutputFilename(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"example.yml", "example-built.yml"},
		{"test/example.yaml", "test/example-built.yaml"},
		{"example-ref.yml", "example-ref-built.yml"},
		{"/absolute/path/file.yml", "/absolute/path/file-built.yml"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := generateOutputFilename(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestBuildFile_InvalidYAML tests building with invalid YAML
func TestBuildFile_InvalidYAML(t *testing.T) {
	yamlContent := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomainReference
metadata:
  name: test
  invalid yaml here: : :
`
	inputFile := createTempFileWithContent(t, yamlContent)

	result := File(inputFile, "")

	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "failed to parse YAML")
}

// TestBuildFile_RelativePath tests that relative paths work correctly
func TestBuildFile_RelativePath(t *testing.T) {
	// Create a rego file in a temp directory
	tmpDir := t.TempDir()
	regoPath := filepath.Join(tmpDir, "test.rego")
	err := os.WriteFile(regoPath, []byte("package authz\ndefault allow = false\n"), 0644)
	require.NoError(t, err)

	// Change to temp directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(oldWd)

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	yamlContent := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomainReference
metadata:
  name: test
spec:
  policies:
    - mrn: "mrn:iam:policy:test"
      name: test
      rego_filename: "./test.rego"
`
	inputFile := createTempFileWithContent(t, yamlContent)

	result := File(inputFile, "")

	assert.True(t, result.Success, "Build with relative path should succeed")
	defer os.Remove(result.OutputFile)

	outputData, err := os.ReadFile(result.OutputFile)
	require.NoError(t, err)
	outputStr := string(outputData)

	assert.Contains(t, outputStr, "package authz")
	assert.Contains(t, outputStr, "default allow = false")
}

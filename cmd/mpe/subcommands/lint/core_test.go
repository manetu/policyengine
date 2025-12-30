//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper functions
func createTempFileFromTestData(t *testing.T, testdataFile string) string {
	// Read the testdata file from mpe-cli/test directory
	content, err := os.ReadFile(filepath.Join("../../test", testdataFile))
	require.NoError(t, err, "Failed to read testdata file: %s", testdataFile)

	// Create temp file with the content
	tmpfile, err := os.CreateTemp("", "test-*.yml")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(tmpfile.Name()) })

	_, err = tmpfile.Write(content)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	return tmpfile.Name()
}

func createTempFileWithContent(t *testing.T, content string) string {
	tmpfile, err := os.CreateTemp("", "test-*.yml")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(tmpfile.Name()) })

	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	return tmpfile.Name()
}

// TestLintFile_ValidYAML tests linting a valid YAML file
func TestLintFile_ValidYAML(t *testing.T) {
	validFile := createTempFileFromTestData(t, "lint-valid-simple.yml")

	// Test YAML validation
	result := lintFile(validFile)
	assert.True(t, result.Valid, "Valid YAML should pass linting")
	assert.Nil(t, result.Error, "Valid YAML should have no error")
	assert.Empty(t, result.Message, "Valid YAML should have no message")

	errorCount := lintRegoUsingExistingValidation([]string{validFile}, "--v0-compatible")
	assert.Equal(t, 0, errorCount, "Should have no Rego errors")
}

// TestLintFile_ValidYAML_ExistingTestFile tests with existing test files
func TestLintFile_ValidYAML_ExistingTestFile(t *testing.T) {
	testCases := []struct {
		name           string
		filename       string
		expectRegoLint bool // whether this file should have Rego linting results
		expectedRego   int  // expected number of Rego modules
		expectErrors   bool // whether some Rego modules should have errors
	}{
		{"Alpha domain", "alpha.yml", true, 2, false},
		{"Beta domain", "beta-no-anchor.yml", true, 6, true},
		{"Consolidated domain", "consolidated.yml", true, 8, false},
		{"Valid alpha", "valid-alpha.yml", true, 2, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validFile := createTempFileFromTestData(t, tc.filename)

			// Test YAML validation
			result := lintFile(validFile)
			assert.True(t, result.Valid, "File %s should be valid YAML", tc.filename)
			assert.Nil(t, result.Error, "File %s should have no error", tc.filename)

			// Test Rego validation using the new approach
			if tc.expectRegoLint {
				errorCount := lintRegoUsingExistingValidation([]string{validFile}, "--v0-compatible")

				if tc.expectErrors {
					assert.Greater(t, errorCount, 0, "File %s should have Rego errors", tc.filename)
				} else {
					assert.Equal(t, errorCount, 0, "File %s should have no Rego errors", tc.filename)
				}
			}
		})
	}
}

// TestLintFile_InvalidSyntax tests linting a YAML file with syntax errors
func TestLintFile_InvalidSyntax(t *testing.T) {
	invalidFile := createTempFileFromTestData(t, "lint-invalid-syntax.yml")

	result := lintFile(invalidFile)

	assert.False(t, result.Valid, "Invalid YAML should fail linting")
	assert.NotNil(t, result.Error, "Invalid YAML should have an error")

	errorMsg := formatYAMLError(result.Error)
	assert.Contains(t, errorMsg, "mapping values are not allowed", "Error should mention mapping issue")
}

// TestLintFile_InvalidIndentation tests linting a YAML file with indentation errors
func TestLintFile_InvalidIndentation(t *testing.T) {
	invalidFile := createTempFileFromTestData(t, "lint-invalid-indentation.yml")

	result := lintFile(invalidFile)

	assert.False(t, result.Valid, "YAML with indentation errors should fail linting")
	assert.NotNil(t, result.Error, "YAML with indentation errors should have an error")
}

// TestLintFile_MultipleErrors tests linting a YAML file with multiple errors
func TestLintFile_MultipleErrors(t *testing.T) {
	invalidFile := createTempFileFromTestData(t, "lint-multiple-errors.yml")

	result := lintFile(invalidFile)

	assert.False(t, result.Valid, "YAML with multiple errors should fail linting")
	assert.NotNil(t, result.Error, "YAML with multiple errors should have an error")
}

// TestLintFile_FileNotFound tests linting a non-existent file
func TestLintFile_FileNotFound(t *testing.T) {
	result := lintFile("/nonexistent/file.yml")

	assert.False(t, result.Valid, "Non-existent file should fail linting")
	assert.NotEmpty(t, result.Message, "Non-existent file should have a message")
	assert.Contains(t, result.Message, "Failed to read file", "Message should indicate read failure")
}

// TestLintFile_EmptyFile tests linting an empty file
func TestLintFile_EmptyFile(t *testing.T) {
	emptyFile := createTempFileWithContent(t, "")

	result := lintFile(emptyFile)

	// Empty file is technically valid YAML (parses to nil)
	assert.True(t, result.Valid, "Empty file should be valid YAML")
}

// TestLintFile_MalformedYAML tests various malformed YAML scenarios
func TestLintFile_MalformedYAML(t *testing.T) {
	testCases := []struct {
		name    string
		content string
		errMsg  string
	}{
		{
			name:    "Unclosed bracket",
			content: "key: [value1, value2",
			errMsg:  "did not find expected",
		},
		{
			name:    "Invalid mapping",
			content: "key: value: another",
			errMsg:  "mapping values are not allowed",
		},
		{
			name:    "Tab character in indentation",
			content: "key:\n\tvalue: test",
			errMsg:  "found character that cannot start any token",
		},
		{
			name:    "Unclosed quote",
			content: "key: \"unclosed string",
			errMsg:  "unexpected end of stream",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			file := createTempFileWithContent(t, tc.content)
			result := lintFile(file)

			assert.False(t, result.Valid, "Malformed YAML should fail linting")
			assert.NotNil(t, result.Error, "Malformed YAML should have an error")

			errorMsg := formatYAMLError(result.Error)
			assert.Contains(t, errorMsg, tc.errMsg, "Error message should contain expected text")
		})
	}
}

// TestFormatYAMLError tests the error formatting function
func TestFormatYAMLError(t *testing.T) {
	testCases := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "Simple syntax error",
			content:  "key: value: another",
			expected: "yaml:",
		},
		{
			name:     "Indentation error",
			content:  "key:\nvalue: test",
			expected: "yaml:",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			file := createTempFileWithContent(t, tc.content)
			result := lintFile(file)

			if result.Error != nil {
				formatted := formatYAMLError(result.Error)
				assert.Contains(t, formatted, tc.expected, "Formatted error should contain expected text")
			}
		})
	}
}

// TestLintFile_FailOpaCheck tests a file that passes compilation but fails opa check
func TestLintFile_FailOpaCheck(t *testing.T) {
	validFile := createTempFileFromTestData(t, "fail-opa-check.yml")

	// Test YAML validation - should pass
	result := lintFile(validFile)
	assert.True(t, result.Valid, "YAML should be valid")
	assert.Nil(t, result.Error, "YAML should have no error")

	// Test Rego validation - should fail at opa check stage
	errorCount := lintRegoUsingExistingValidation([]string{validFile}, "--v0-compatible")
	assert.Greater(t, errorCount, 0, "Should have OPA check errors (undefined function)")
}

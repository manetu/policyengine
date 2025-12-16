//
//  Copyright © Manetu Inc. All rights reserved.
//

package registry

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manetu/policyengine/pkg/policydomain/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper functions
func createTempFileFromTestData(t *testing.T, testdataFile string) string {
	// Read the testdata file
	content, err := os.ReadFile(filepath.Join("../../../cmd/mpe/test", testdataFile))
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

// Test ValidationError struct
func TestValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      *validation.Error
		expected string
	}{
		{
			name: "Complete error with all fields",
			err: &validation.Error{
				Domain:   "alpha",
				Entity:   "policy",
				EntityID: "mrn:iam:policy:test",
				Field:    "dependencies",
				Message:  "reference 'missing' not found in domain 'alpha'",
			},
			expected: "in domain 'alpha' policy 'mrn:iam:policy:test' field 'dependencies': reference 'missing' not found in domain 'alpha'",
		},
		{
			name: "Error with minimal fields",
			err: &validation.Error{
				Message: "simple error message",
			},
			expected: "simple error message",
		},
		{
			name: "Error with domain and entity only",
			err: &validation.Error{
				Domain:   "beta",
				Entity:   "role",
				EntityID: "admin",
				Message:  "policy reference invalid",
			},
			expected: "in domain 'beta' role 'admin': policy reference invalid",
		},
		{
			name: "Cycle error",
			err: &validation.Error{
				Type:    "cycle",
				Message: "circular dependency detected: alpha/lib-a → beta/lib-b → alpha/lib-a",
			},
			expected: "circular dependency detected: alpha/lib-a → beta/lib-b → alpha/lib-a",
		},
		{
			name: "Rego error",
			err: &validation.Error{
				Domain:   "test",
				Type:     "rego",
				Entity:   "policy",
				EntityID: "bad",
				Field:    "rego",
				Message:  "rego compilation failed in policy 'bad': package expected",
			},
			expected: "in domain 'test' policy 'bad' field 'rego': rego compilation failed in policy 'bad': package expected",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.err.Error()
			assert.Equal(t, test.expected, result)
		})
	}
}

// Test ValidationErrors collection
func TestValidationErrors(t *testing.T) {
	t.Run("Empty collection", func(t *testing.T) {
		errors := validation.NewValidationErrors()
		assert.False(t, errors.HasErrors())
		assert.Equal(t, 0, errors.Count())
		assert.Equal(t, "no validation errors", errors.Error())
	})

	t.Run("Single error", func(t *testing.T) {
		errors := validation.NewValidationErrors()
		errors.AddReferenceError("alpha", "policy", "test", "dependencies", "missing reference")

		assert.True(t, errors.HasErrors())
		assert.Equal(t, 1, errors.Count())
		assert.Contains(t, errors.Error(), "missing reference")
	})

	t.Run("Multiple errors", func(t *testing.T) {
		errors := validation.NewValidationErrors()
		errors.AddReferenceError("alpha", "policy", "test1", "dependencies", "missing ref 1")
		errors.AddReferenceError("beta", "role", "admin", "policy", "missing ref 2")

		assert.True(t, errors.HasErrors())
		assert.Equal(t, 2, errors.Count())
		assert.Contains(t, errors.Error(), "validation failed with 2 errors:")
		assert.Contains(t, errors.Error(), "missing ref 1")
		assert.Contains(t, errors.Error(), "missing ref 2")
	})

	t.Run("Group by domain", func(t *testing.T) {
		errors := validation.NewValidationErrors()
		errors.AddReferenceError("alpha", "policy", "test1", "dependencies", "error 1")
		errors.AddReferenceError("alpha", "role", "admin", "policy", "error 2")
		errors.AddReferenceError("beta", "scope", "api", "policy", "error 3")

		byDomain := errors.ErrorsByDomain()
		assert.Len(t, byDomain, 2)
		assert.Len(t, byDomain["alpha"], 2)
		assert.Len(t, byDomain["beta"], 1)
	})

	t.Run("Group by type", func(t *testing.T) {
		errors := validation.NewValidationErrors()
		errors.Add(&validation.Error{Type: "reference", Message: "ref error 1"})
		errors.Add(&validation.Error{Type: "reference", Message: "ref error 2"})
		errors.AddCycleError("cycle error")
		errors.AddRegoError("test", "policy", "bad", "rego compilation failed")

		byType := errors.ErrorsByType()
		assert.Len(t, byType, 3)
		assert.Len(t, byType["reference"], 2)
		assert.Len(t, byType["cycle"], 1)
		assert.Len(t, byType["rego"], 1)
	})

	t.Run("Summary", func(t *testing.T) {
		errors := validation.NewValidationErrors()
		errors.AddReferenceError("alpha", "policy", "test1", "dependencies", "error 1")
		errors.AddReferenceError("beta", "role", "admin", "policy", "error 2")
		errors.AddCycleError("cycle error")

		summary := errors.Summary()
		assert.Contains(t, summary, "Validation Summary: 3 errors found")
		assert.Contains(t, summary, "By Domain:")
		assert.Contains(t, summary, "alpha: 1 errors")
		assert.Contains(t, summary, "beta: 1 errors")
		assert.Contains(t, summary, "By Type:")
	})
}

// Test bad rego validation using the test data file
func TestBadRegoValidation(t *testing.T) {
	// Use the bad-rego.yml test data file
	badRegoFile := createTempFileFromTestData(t, "bad-rego.yml")

	// Test registry creation - should fail with rego compilation error
	registry, err := NewRegistry([]string{badRegoFile})
	assert.Nil(t, registry, "Backend should be nil when rego compilation fails")
	assert.Error(t, err, "Should return validation errors")

	// Verify it's a ValidationErrors type
	var validationErrors *validation.Errors
	ok := errors.As(err, &validationErrors)
	require.True(t, ok, "Error should be ValidationErrors type")
	assert.True(t, validationErrors.HasErrors())

	// Check for specific rego compilation errors from the output
	errorText := err.Error()
	assert.Contains(t, errorText, "rego", "Should mention rego in error")
	assert.Contains(t, errorText, "package expected", "Should show 'package expected' error")
	assert.Contains(t, errorText, "var cannot be used for rule name", "Should show 'var cannot be used for rule name' error")

	// Verify error is properly categorized
	byType := validationErrors.ErrorsByType()
	assert.Contains(t, byType, "rego", "Should have rego error type")

	// Check the specific rego error details
	regoErrors := byType["rego"]
	assert.Len(t, regoErrors, 1, "Should have exactly one rego error")

	regoError := regoErrors[0]
	assert.Equal(t, "test", regoError.Domain, "Should identify correct domain")
	assert.Equal(t, "policy", regoError.Entity, "Should identify correct entity type")
	assert.Equal(t, "bad", regoError.EntityID, "Should identify correct entity ID")
	assert.Equal(t, "rego", regoError.Field, "Should identify rego field")

	// The error message should contain both parse errors
	assert.Contains(t, regoError.Message, "package expected", "Should contain first parse error")

	t.Logf("Bad rego validation error (expected): %s", err.Error())
}

// Test mapper rego validation using consolidated.yml
func TestMapperRegoValidation(t *testing.T) {
	// Use the consolidated.yml test data file which contains mapper rego
	consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

	// Test registry creation - should succeed with valid mapper rego
	registry, err := NewRegistry([]string{consolidatedFile})
	assert.NoError(t, err, "Consolidated domain with valid mapper rego should succeed")
	assert.NotNil(t, registry, "Backend should be created successfully")

	// Verify that mappers are present and validated
	isValid, summary := registry.ValidateWithSummary()
	assert.True(t, isValid, "Domain with valid mapper rego should be valid")
	assert.Contains(t, summary, "successfully", "Summary should indicate success")

	t.Logf("Mapper validation succeeded: %s", summary)
}

// Test validation with intentionally broken domain files
func TestMultipleValidationErrors_BrokenDomains(t *testing.T) {
	// Create temp files from testdata
	alphaFile := createTempFileFromTestData(t, "broken-alpha.yml")
	betaFile := createTempFileFromTestData(t, "broken-beta.yml")

	// Test registry creation - should accumulate all errors
	registry, err := NewRegistry([]string{alphaFile, betaFile})
	assert.Nil(t, registry, "Backend should be nil when validation fails")
	assert.Error(t, err, "Should return validation errors")

	// Verify it's a ValidationErrors type
	validationErrors, ok := err.(*validation.Errors)
	require.True(t, ok, "Error should be ValidationErrors type")
	assert.True(t, validationErrors.HasErrors())
	assert.Greater(t, validationErrors.Count(), 4, "Should have multiple validation errors")

	// Check for specific error types in the full error output
	errorText := err.Error()
	assert.Contains(t, errorText, "circular dependency detected", "Should detect 3-level cycle")
	assert.Contains(t, errorText, "not found", "Should detect missing references")
	assert.Contains(t, errorText, "[cycle]", "Should show cycle type in output")
	assert.Contains(t, errorText, "[reference]", "Should show reference type in output")

	// Verify the 3-level cycle is properly detected
	if strings.Contains(errorText, "circular dependency detected") {
		// Verify cycle shows proper 3-level recursion
		cycleParts := []string{
			"alpha/mrn:iam:library:loopy-a",
			"beta/mrn:iam:library:loopy-b",
			"alpha/mrn:iam:library:loopy-c",
		}
		cycleFound := false
		for _, part := range cycleParts {
			if strings.Contains(errorText, part) {
				cycleFound = true
				break
			}
		}
		assert.True(t, cycleFound, "Should detect 3-level cycle with proper path")
	}

	// Verify error grouping and typing
	byDomain := validationErrors.ErrorsByDomain()
	assert.Contains(t, byDomain, "alpha", "Should have alpha domain errors")
	assert.Contains(t, byDomain, "beta", "Should have beta domain errors")

	byType := validationErrors.ErrorsByType()
	assert.Contains(t, byType, "cycle", "Should categorize cycle errors")
	assert.Contains(t, byType, "reference", "Should categorize reference errors")

	// Verify alpha domain has reference errors
	if alphaErrors, hasAlpha := byDomain["alpha"]; hasAlpha {
		referenceErrorCount := 0
		for _, err := range alphaErrors {
			if err.Type == "reference" {
				referenceErrorCount++
			}
		}
		// Should have reference errors (policy and role references)
		assert.Greater(t, referenceErrorCount, 0, "Alpha should have reference-related errors")
	}

	// Ensure cycle errors are properly typed
	cycleErrors := byType["cycle"]
	assert.Len(t, cycleErrors, 1, "Should have exactly one cycle error")
	assert.Equal(t, "cycle", cycleErrors[0].Type, "Cycle error should have correct type")

	// Ensure reference errors are properly typed
	referenceErrors := byType["reference"]
	assert.Greater(t, len(referenceErrors), 0, "Should have reference errors")
	for _, err := range referenceErrors {
		assert.Equal(t, "reference", err.Type, "All reference errors should have correct type")
	}

	t.Logf("Total validation errors found: %d", validationErrors.Count())
	t.Logf("Error summary:\n%s", validationErrors.Summary())

	// Single log statement that shows the detailed errors with types
	t.Logf("Detailed errors:\n%s", err.Error())
}

// Test validation with valid domains (no errors)
func TestValidation_ValidDomains(t *testing.T) {
	// Create temp file from testdata
	alphaFile := createTempFileFromTestData(t, "valid-alpha.yml")

	// Test registry creation - should succeed
	registry, err := NewRegistry([]string{alphaFile})
	assert.NoError(t, err, "Valid domain should not return errors")
	assert.NotNil(t, registry, "Backend should be created successfully")

	// Test validation methods
	isValid, summary := registry.ValidateWithSummary()
	assert.True(t, isValid, "Domain should be valid")
	assert.Contains(t, summary, "successfully", "Summary should indicate success")

	validationErrors := registry.GetAllValidationErrors()
	assert.Nil(t, validationErrors, "Should have no validation errors")
}

// Test individual domain validation
func TestValidateDomain(t *testing.T) {
	// Create temp files from testdata
	validFile := createTempFileFromTestData(t, "mixed-valid.yml")
	invalidFile := createTempFileFromTestData(t, "mixed-invalid.yml")

	// This will fail during NewRegistry due to invalid domain, but let's test the concept
	_, err := NewRegistry([]string{validFile, invalidFile})
	assert.Error(t, err, "Should fail due to invalid domain")

	// Test with just valid domain
	registry, err := NewRegistry([]string{validFile})
	require.NoError(t, err)

	// Test ValidateDomain on valid domain
	err = registry.ValidateDomain("valid")
	assert.NoError(t, err, "Valid domain should pass validation")

	// Test ValidateDomain on nonexistent domain
	err = registry.ValidateDomain("nonexistent")
	assert.Error(t, err, "Nonexistent domain should fail validation")
	assert.Contains(t, err.Error(), "not found", "Should indicate domain not found")
}

// Test error accumulation vs fail-fast behavior
func TestErrorAccumulation(t *testing.T) {
	// Create temp file from testdata
	file := createTempFileFromTestData(t, "multi-error.yml")

	_, err := NewRegistry([]string{file})
	assert.Error(t, err, "Should return validation errors")

	validationErrors, ok := err.(*validation.Errors)
	require.True(t, ok, "Should be ValidationErrors type")

	// Should accumulate many errors, not just stop at first one
	assert.Greater(t, validationErrors.Count(), 5, "Should accumulate multiple errors")

	// Verify different types of errors are captured
	errorText := err.Error()
	assert.Contains(t, errorText, "missing1", "Should contain first missing reference")
	assert.Contains(t, errorText, "missing2", "Should contain second missing reference")

	// Test that errors are properly categorized and typed
	byDomain := validationErrors.ErrorsByDomain()
	assert.Contains(t, byDomain, "multi-error", "Should have errors in multi-error domain")

	byType := validationErrors.ErrorsByType()
	assert.Contains(t, byType, "reference", "Should have reference errors")

	// Verify all errors are properly typed as reference errors
	referenceErrors := byType["reference"]
	assert.Equal(t, validationErrors.Count(), len(referenceErrors), "All errors should be reference errors")
	for _, err := range referenceErrors {
		assert.Equal(t, "reference", err.Type, "All errors should have reference type")
	}

	// Log the accumulated errors for inspection
	t.Logf("Accumulated %d validation errors:", validationErrors.Count())
	for i, validationErr := range validationErrors.Errors {
		t.Logf("  %d: [%s] %s", i+1, validationErr.Type, validationErr.Error())
	}
}

//
//  Copyright © Manetu Inc. All rights reserved.
//

package common

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper function
func createTempFileFromTestData(t *testing.T, testdataFile string) string {
	// Read the testdata file from the test directory
	content, err := os.ReadFile(filepath.Join("test", testdataFile))
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

func TestAutoBuildReferenceFiles_EmptyInput(t *testing.T) {
	result, err := AutoBuildReferenceFiles([]string{})
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestAutoBuildReferenceFiles_OnlyPolicyDomain(t *testing.T) {
	policyDomainFile := createTempFileFromTestData(t, "simple-domain.yml")

	result, err := AutoBuildReferenceFiles([]string{policyDomainFile})
	require.NoError(t, err)
	assert.Equal(t, []string{policyDomainFile}, result)
}

func TestAutoBuildReferenceFiles_OnlyPolicyDomainReference(t *testing.T) {
	refFile := createTempFileFromTestData(t, "simple-ref.yml")

	result, err := AutoBuildReferenceFiles([]string{refFile})
	require.NoError(t, err)

	// Should return the built file
	require.Len(t, result, 1)
	assert.Contains(t, result[0], "-built.yml")

	// Verify the built file exists
	_, err = os.Stat(result[0])
	assert.NoError(t, err)

	// Cleanup
	defer func() { _ = os.Remove(result[0]) }()
}

func TestAutoBuildReferenceFiles_MixedFiles(t *testing.T) {
	refFile := createTempFileFromTestData(t, "simple-ref.yml")
	domainFile := createTempFileFromTestData(t, "simple-domain.yml")

	result, err := AutoBuildReferenceFiles([]string{refFile, domainFile})
	require.NoError(t, err)

	// Should return built file first, then the domain file
	require.Len(t, result, 2)
	assert.Contains(t, result[0], "-built.yml")
	assert.Equal(t, domainFile, result[1])

	// Verify the built file exists
	_, err = os.Stat(result[0])
	assert.NoError(t, err)

	// Cleanup
	defer func() { _ = os.Remove(result[0]) }()
}

func TestAutoBuildReferenceFiles_BuildError(t *testing.T) {
	refFile := createTempFileFromTestData(t, "error-missing-rego.yml")

	result, err := AutoBuildReferenceFiles([]string{refFile})
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to build")
}

func TestAutoBuildReferenceFiles_InvalidFile(t *testing.T) {
	result, err := AutoBuildReferenceFiles([]string{"/nonexistent/file.yml"})
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to check file type")
}

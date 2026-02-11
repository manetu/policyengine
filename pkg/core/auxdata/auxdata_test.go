//
//  Copyright © Manetu Inc. All rights reserved.
//

package auxdata

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAuxData_EmptyPath(t *testing.T) {
	result, err := LoadAuxData("")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestLoadAuxData_NonexistentDir(t *testing.T) {
	_, err := LoadAuxData("/nonexistent/path")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read auxdata directory")
}

func TestLoadAuxData_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	result, err := LoadAuxData(dir)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

func TestLoadAuxData_WithFiles(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "region"), []byte("us-east-1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tier"), []byte("premium"), 0644))

	result, err := LoadAuxData(dir)
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "us-east-1", result["region"])
	assert.Equal(t, "premium", result["tier"])
}

func TestLoadAuxData_SkipsHiddenFiles(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "visible"), []byte("data"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".hidden"), []byte("secret"), 0644))

	result, err := LoadAuxData(dir)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "data", result["visible"])
	_, exists := result[".hidden"]
	assert.False(t, exists)
}

func TestLoadAuxData_SkipsSubdirectories(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "key"), []byte("value"), 0644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "subdir"), 0755))

	result, err := LoadAuxData(dir)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "value", result["key"])
}

func TestMergeAuxData_NilAuxData(t *testing.T) {
	input := map[string]interface{}{"key": "value"}
	result := MergeAuxData(input, nil)

	m, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "value", m["key"])
	_, exists := m["auxdata"]
	assert.False(t, exists)
}

func TestMergeAuxData_EmptyAuxData(t *testing.T) {
	input := map[string]interface{}{"key": "value"}
	result := MergeAuxData(input, map[string]interface{}{})

	m, ok := result.(map[string]interface{})
	require.True(t, ok)
	_, exists := m["auxdata"]
	assert.False(t, exists)
}

func TestMergeAuxData_MergesIntoMap(t *testing.T) {
	input := map[string]interface{}{
		"request": "data",
	}
	aux := map[string]interface{}{
		"region": "us-east-1",
		"tier":   "premium",
	}

	result := MergeAuxData(input, aux)

	m, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "data", m["request"])

	auxResult, ok := m["auxdata"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "us-east-1", auxResult["region"])
	assert.Equal(t, "premium", auxResult["tier"])
}

func TestMergeAuxData_NonMapInput(t *testing.T) {
	input := "string-input"
	aux := map[string]interface{}{"key": "value"}

	result := MergeAuxData(input, aux)
	assert.Equal(t, "string-input", result)
}

func TestMergeAuxData_NilInput(t *testing.T) {
	aux := map[string]interface{}{"key": "value"}
	result := MergeAuxData(nil, aux)
	assert.Nil(t, result)
}

//
//  Copyright © Manetu Inc. All rights reserved.
//

package test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	clicommon "github.com/manetu/policyengine/cmd/mpe/common"
	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/model"
	"github.com/manetu/policyengine/pkg/core/opa"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
	"github.com/open-policy-agent/opa/v1/ast"
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
	t.Cleanup(func() { os.Remove(tmpfile.Name()) })

	_, err = tmpfile.Write(content)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	return tmpfile.Name()
}

func executeMapper(rego string, input interface{}, regoVersion ast.RegoVersion) (interface{}, *common.PolicyError) {
	compiler := opa.NewCompiler(opa.WithRegoVersion(regoVersion))

	ast, err := compiler.Compile("test-mapper", opa.Modules{"test.rego": rego})
	if err != nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_UNKNOWN_ERROR, fmt.Sprintf("compilation failed: %s", err))
	}

	m := &model.Mapper{
		Ast: ast,
	}

	return m.Evaluate(context.Background(), input)
}

// TestExecuteMapperRegoWithV0Version tests mapper execution with v0 Rego version via CLI flags
func TestExecuteMapperRegoWithV0Version(t *testing.T) {
	// Load the v0 mapper domain to get the Rego code
	domainFile := createTempFileFromTestData(t, "v0-mapper-domain.yml")

	// Create simple Envoy input
	envoyInput := map[string]interface{}{
		"context": map[string]interface{}{
			"request": map[string]interface{}{
				"http": map[string]interface{}{
					"headers": map[string]interface{}{
						":method": "GET",
						":path":   "/test",
					},
				},
			},
		},
		"operation": "http:method:get",
		"principal": map[string]interface{}{
			"subject": "user123",
			"mroles":  []string{"role1"},
		},
		"resource": map[string]interface{}{
			"id":    "resource:test",
			"group": "group:test",
		},
	}

	// Simple v0 Rego mapper code (from test domain)
	mapperRego := `package mapper
porc = output {
  output := {
    "context": input.context,
    "operation": input.operation,
    "principal": input.principal,
    "resource": input.resource
  }
}`

	// Test with CLI flags: --opa-flags "--v0-compatible"
	regoVersion := clicommon.GetRegoVersionFromOPAFlags(false, "--v0-compatible")
	require.Equal(t, ast.RegoV0, regoVersion, "Should parse --v0-compatible flag to RegoV0")

	// Execute mapper with the version from CLI flags
	porc, err := executeMapper(mapperRego, envoyInput, regoVersion)

	assert.Nil(t, err, "Mapper execution should succeed with RegoV0")
	assert.NotNil(t, porc, "Should have output from mapper")

	// Verify the output is a map with expected fields
	porcMap, ok := porc.(map[string]interface{})
	require.True(t, ok, "Output should be a map")

	assert.Contains(t, porcMap, "context", "Output should contain context")
	assert.Contains(t, porcMap, "operation", "Output should contain operation")
	assert.Contains(t, porcMap, "principal", "Output should contain principal")
	assert.Contains(t, porcMap, "resource", "Output should contain resource")

	// Verify the test domain file was loaded successfully
	require.NotEmpty(t, domainFile, "Domain file should be loaded")
}

// TestExecuteMapperRegoWithoutOPAFlags tests mapper execution with --no-opa-flags
func TestExecuteMapperRegoWithoutOPAFlags(t *testing.T) {
	// Load the v0 mapper domain to get the Rego code
	domainFile := createTempFileFromTestData(t, "v0-mapper-domain.yml")

	// Create simple Envoy input
	envoyInput := map[string]interface{}{
		"context": map[string]interface{}{
			"request": map[string]interface{}{
				"http": map[string]interface{}{
					"headers": map[string]interface{}{
						":method": "GET",
						":path":   "/test",
					},
				},
			},
		},
		"operation": "http:method:get",
		"principal": map[string]interface{}{
			"subject": "user123",
			"mroles":  []string{"role1"},
		},
		"resource": map[string]interface{}{
			"id":    "resource:test",
			"group": "group:test",
		},
	}

	// v0 Rego mapper code (no 'if' keyword)
	mapperRego := `package mapper
porc = output {
  output := {
    "context": input.context,
    "operation": input.operation,
    "principal": input.principal,
    "resource": input.resource
  }
}`

	// Test with CLI flag: --no-opa-flags (disables v0-compatible, uses v1)
	regoVersion := clicommon.GetRegoVersionFromOPAFlags(true, "")
	require.Equal(t, ast.RegoV1, regoVersion, "Should parse --no-opa-flags to RegoV1")

	// Execute mapper with v1 version
	// This should fail because the mapper uses v0 syntax but we're using v1
	porc, err := executeMapper(mapperRego, envoyInput, regoVersion)

	require.NotNil(t, err, "Mapper execution should fail with RegoV1 on v0 syntax")
	assert.Nil(t, porc, "Should have no output on error")
	assert.Contains(t, err.Error(), "rego_parse_error", "Error should mention Rego parse error")
	assert.Contains(t, err.Error(), "if` keyword is required", "Error should mention missing 'if' keyword")

	// Verify the test domain file was loaded successfully
	require.NotEmpty(t, domainFile, "Domain file should be loaded")
}

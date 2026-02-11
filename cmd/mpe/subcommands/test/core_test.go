//
//  Copyright © Manetu Inc. All rights reserved.
//

package test

import (
	"context"
	"encoding/json"
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
	"github.com/urfave/cli/v3"
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

// testDataPath returns the path to test data files in cmd/mpe/test
func testDataPath(filename string) string {
	return filepath.Join("..", "..", "test", filename)
}

// buildTestCommand creates a CLI command structure for testing with the specified action
func buildTestCommand(action cli.ActionFunc) *cli.Command {
	return &cli.Command{
		Name: "mpe",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "trace",
				Value: false,
			},
		},
		Commands: []*cli.Command{
			{
				Name: "test",
				Commands: []*cli.Command{
					{
						Name: "decision",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "input", Aliases: []string{"i"}},
							&cli.StringSliceFlag{Name: "bundle", Aliases: []string{"b"}},
							&cli.StringFlag{Name: "name", Aliases: []string{"n"}},
						},
						Action: action,
					},
					{
						Name: "mapper",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "input", Aliases: []string{"i"}},
							&cli.StringSliceFlag{Name: "bundle", Aliases: []string{"b"}},
							&cli.StringFlag{Name: "name", Aliases: []string{"n"}},
							&cli.StringFlag{Name: "opa-flags"},
							&cli.BoolFlag{Name: "no-opa-flags"},
							&cli.StringFlag{Name: "auxdata"},
						},
						Action: action,
					},
					{
						Name: "envoy",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "input", Aliases: []string{"i"}},
							&cli.StringSliceFlag{Name: "bundle", Aliases: []string{"b"}},
							&cli.StringFlag{Name: "name", Aliases: []string{"n"}},
							&cli.StringFlag{Name: "opa-flags"},
							&cli.BoolFlag{Name: "no-opa-flags"},
							&cli.StringFlag{Name: "auxdata"},
						},
						Action: action,
					},
				},
			},
		},
	}
}

// TestExecuteMapper_WithConsolidatedBundle tests the mapper command with consolidated.yml and envoy.json
func TestExecuteMapper_WithConsolidatedBundle(t *testing.T) {
	bundleFile := testDataPath("consolidated.yml")
	inputFile := testDataPath("envoy.json")

	// Verify test files exist
	require.FileExists(t, bundleFile, "consolidated.yml should exist")
	require.FileExists(t, inputFile, "envoy.json should exist")

	cmd := buildTestCommand(ExecuteMapper)
	args := []string{"mpe", "test", "mapper", "-i", inputFile, "-b", bundleFile}

	err := cmd.Run(context.Background(), args)
	assert.NoError(t, err, "ExecuteMapper should succeed with consolidated bundle and envoy input")
}

// TestExecuteMapper_MissingBundle tests mapper command with missing bundle
func TestExecuteMapper_MissingBundle(t *testing.T) {
	inputFile := testDataPath("envoy.json")

	cmd := buildTestCommand(ExecuteMapper)
	args := []string{"mpe", "test", "mapper", "-i", inputFile}

	err := cmd.Run(context.Background(), args)
	assert.Error(t, err, "ExecuteMapper should fail without bundle")
	assert.Contains(t, err.Error(), "bundle", "Error should mention missing bundle")
}

// TestExecuteDecision_WithConsolidatedBundle tests the decision command with consolidated.yml and example-porc-input.json
func TestExecuteDecision_WithConsolidatedBundle(t *testing.T) {
	bundleFile := testDataPath("consolidated.yml")
	inputFile := testDataPath("example-porc-input.json")

	// Verify test files exist
	require.FileExists(t, bundleFile, "consolidated.yml should exist")
	require.FileExists(t, inputFile, "example-porc-input.json should exist")

	cmd := buildTestCommand(ExecuteDecision)
	args := []string{"mpe", "test", "decision", "-i", inputFile, "-b", bundleFile}

	err := cmd.Run(context.Background(), args)
	assert.NoError(t, err, "ExecuteDecision should succeed with consolidated bundle and PORC input")
}

// TestExecuteDecision_MissingBundle tests decision command with missing bundle
func TestExecuteDecision_MissingBundle(t *testing.T) {
	inputFile := testDataPath("example-porc-input.json")

	cmd := buildTestCommand(ExecuteDecision)
	args := []string{"mpe", "test", "decision", "-i", inputFile}

	err := cmd.Run(context.Background(), args)
	assert.Error(t, err, "ExecuteDecision should fail without bundle")
	assert.Contains(t, err.Error(), "bundle", "Error should mention missing bundle")
}

// TestExecuteDecision_WithScopesInput tests decision command with scopes input
func TestExecuteDecision_WithScopesInput(t *testing.T) {
	bundleFile := testDataPath("consolidated.yml")
	inputFile := testDataPath("example-porc-input-scopes.json")

	// Verify test files exist
	require.FileExists(t, bundleFile, "consolidated.yml should exist")
	require.FileExists(t, inputFile, "example-porc-input-scopes.json should exist")

	cmd := buildTestCommand(ExecuteDecision)
	args := []string{"mpe", "test", "decision", "-i", inputFile, "-b", bundleFile}

	err := cmd.Run(context.Background(), args)
	assert.NoError(t, err, "ExecuteDecision should succeed with PORC input containing scopes")
}

// TestExecuteEnvoy_WithConsolidatedBundle tests the envoy command (full pipeline) with consolidated.yml and envoy.json
func TestExecuteEnvoy_WithConsolidatedBundle(t *testing.T) {
	bundleFile := testDataPath("consolidated.yml")
	inputFile := testDataPath("envoy.json")

	// Verify test files exist
	require.FileExists(t, bundleFile, "consolidated.yml should exist")
	require.FileExists(t, inputFile, "envoy.json should exist")

	cmd := buildTestCommand(ExecuteEnvoy)
	args := []string{"mpe", "test", "envoy", "-i", inputFile, "-b", bundleFile}

	err := cmd.Run(context.Background(), args)
	assert.NoError(t, err, "ExecuteEnvoy should succeed with consolidated bundle and envoy input")
}

// TestExecuteEnvoy_MissingBundle tests envoy command with missing bundle
func TestExecuteEnvoy_MissingBundle(t *testing.T) {
	inputFile := testDataPath("envoy.json")

	cmd := buildTestCommand(ExecuteEnvoy)
	args := []string{"mpe", "test", "envoy", "-i", inputFile}

	err := cmd.Run(context.Background(), args)
	assert.Error(t, err, "ExecuteEnvoy should fail without bundle")
	assert.Contains(t, err.Error(), "bundle", "Error should mention missing bundle")
}

// TestExecuteMapper_InvalidBundle tests mapper command with non-existent bundle file
func TestExecuteMapper_InvalidBundle(t *testing.T) {
	inputFile := testDataPath("envoy.json")
	require.FileExists(t, inputFile, "envoy.json should exist")

	cmd := buildTestCommand(ExecuteMapper)
	args := []string{"mpe", "test", "mapper", "-i", inputFile, "-b", "nonexistent-bundle.yml"}

	err := cmd.Run(context.Background(), args)
	assert.Error(t, err, "ExecuteMapper should fail with non-existent bundle file")
}

// TestExecuteDecision_InvalidBundle tests decision command with non-existent bundle file
func TestExecuteDecision_InvalidBundle(t *testing.T) {
	inputFile := testDataPath("example-porc-input.json")
	require.FileExists(t, inputFile, "example-porc-input.json should exist")

	cmd := buildTestCommand(ExecuteDecision)
	args := []string{"mpe", "test", "decision", "-i", inputFile, "-b", "nonexistent-bundle.yml"}

	err := cmd.Run(context.Background(), args)
	assert.Error(t, err, "ExecuteDecision should fail with non-existent bundle file")
}

// TestExecuteEnvoy_InvalidBundle tests envoy command with non-existent bundle file
func TestExecuteEnvoy_InvalidBundle(t *testing.T) {
	inputFile := testDataPath("envoy.json")
	require.FileExists(t, inputFile, "envoy.json should exist")

	cmd := buildTestCommand(ExecuteEnvoy)
	args := []string{"mpe", "test", "envoy", "-i", inputFile, "-b", "nonexistent-bundle.yml"}

	err := cmd.Run(context.Background(), args)
	assert.Error(t, err, "ExecuteEnvoy should fail with non-existent bundle file")
}

// TestExecuteMapper_WithAuxData tests that auxdata merged into the mapper input
// is accessible to Rego code when computing the PORC. This exercises the full
// CLI pipeline: --auxdata dir -> LoadAuxData -> MergeAuxData -> mapper.Evaluate
// -> input.auxdata.* available in Rego -> PORC output contains auxdata values.
func TestExecuteMapper_WithAuxData(t *testing.T) {
	bundleFile := filepath.Join("test", "auxdata-mapper-domain.yml")
	inputFile := filepath.Join("test", "auxdata-envoy-input.json")

	require.FileExists(t, bundleFile, "auxdata-mapper-domain.yml should exist")
	require.FileExists(t, inputFile, "auxdata-envoy-input.json should exist")

	// Create a temp directory simulating a mounted ConfigMap with auxdata files.
	// Each file name becomes a key and its content becomes the value, just like
	// a Kubernetes ConfigMap volume mount.
	auxDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(auxDir, "region"), []byte("us-east-1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(auxDir, "tier"), []byte("premium"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(auxDir, "environment"), []byte("staging"), 0644))

	// Capture stdout so we can inspect the PORC JSON output
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	cmd := buildTestCommand(ExecuteMapper)
	args := []string{
		"mpe", "test", "mapper",
		"-i", inputFile,
		"-b", bundleFile,
		"--auxdata", auxDir,
	}

	runErr := cmd.Run(context.Background(), args)

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = oldStdout
	captured, readErr := os.ReadFile(r.Name())
	if readErr != nil {
		// os.Pipe files don't have names; read from the reader directly
		buf := make([]byte, 4096)
		n, _ := r.Read(buf)
		captured = buf[:n]
	}
	r.Close()

	require.NoError(t, runErr, "ExecuteMapper should succeed with auxdata")
	require.NotEmpty(t, captured, "Should have PORC JSON output")

	// Parse the PORC JSON output
	var porc map[string]interface{}
	require.NoError(t, json.Unmarshal(captured, &porc), "Output should be valid JSON: %s", string(captured))

	// Pretty-print the full PORC for verbose output
	prettyJSON, _ := json.MarshalIndent(porc, "", "  ")
	t.Logf("Auxdata directory: %s", auxDir)
	t.Logf("Auxdata files: region=us-east-1, tier=premium, environment=staging")
	t.Logf("Bundle: %s", bundleFile)
	t.Logf("Input:  %s", inputFile)
	t.Logf("PORC output:\n%s", string(prettyJSON))

	// Verify auxdata values flowed into the PORC operation field
	t.Logf("Checking operation field contains auxdata region...")
	assert.Equal(t, "svc:http:us-east-1", porc["operation"],
		"operation should contain auxdata region")

	// Verify auxdata values flowed into the PORC resource field
	resource, ok := porc["resource"].(map[string]interface{})
	require.True(t, ok, "resource should be a map")
	t.Logf("Checking resource.id contains auxdata tier...")
	assert.Equal(t, "http://svc/premium", resource["id"],
		"resource id should contain auxdata tier")

	// Verify auxdata values flowed into the PORC context field
	ctx, ok := porc["context"].(map[string]interface{})
	require.True(t, ok, "context should be a map")
	t.Logf("Checking context fields match auxdata values...")
	assert.Equal(t, "us-east-1", ctx["region"],
		"context.region should match auxdata")
	assert.Equal(t, "premium", ctx["tier"],
		"context.tier should match auxdata")
	assert.Equal(t, "staging", ctx["environment"],
		"context.environment should match auxdata")

	t.Logf("All auxdata values verified in PORC output")
}

//
//  Copyright © Manetu Inc. All rights reserved.
//

package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// buildDecisionsTestCommand creates a CLI command structure for testing the decisions command
func buildDecisionsTestCommand(action cli.ActionFunc) *cli.Command {
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
						Name: "decisions",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "input", Aliases: []string{"i"}, Required: true},
							&cli.StringSliceFlag{Name: "bundle", Aliases: []string{"b"}},
							&cli.StringSliceFlag{Name: "test"},
						},
						Action: action,
					},
				},
			},
		},
	}
}

// TestLoadTestSuite tests the YAML parsing of test suites
func TestLoadTestSuite(t *testing.T) {
	// Create a temporary test file
	content := `tests:
  - name: test1
    description: First test
    porc:
      principal:
        sub: user@example.com
      operation: api:test:read
      resource:
        id: mrn:test:1
    result:
      allow: true
  - name: test2
    description: Second test
    porc:
      principal: {}
      operation: api:protected:read
      resource:
        id: mrn:test:2
    result:
      allow: false
`
	tmpfile, err := os.CreateTemp("", "test-suite-*.yaml")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(tmpfile.Name()) })

	_, err = tmpfile.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	// Load the test suite
	suite, err := loadTestSuite(tmpfile.Name())
	require.NoError(t, err)
	require.NotNil(t, suite)

	// Verify parsed content
	assert.Len(t, suite.Tests, 2)

	assert.Equal(t, "test1", suite.Tests[0].Name)
	assert.Equal(t, "First test", suite.Tests[0].Description)
	assert.Equal(t, true, suite.Tests[0].Result.Allow)

	assert.Equal(t, "test2", suite.Tests[1].Name)
	assert.Equal(t, "Second test", suite.Tests[1].Description)
	assert.Equal(t, false, suite.Tests[1].Result.Allow)
}

// TestLoadTestSuite_FileNotFound tests error handling for missing files
func TestLoadTestSuite_FileNotFound(t *testing.T) {
	_, err := loadTestSuite("nonexistent-file.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read test file")
}

// TestLoadTestSuite_InvalidYAML tests error handling for invalid YAML
func TestLoadTestSuite_InvalidYAML(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "invalid-*.yaml")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(tmpfile.Name()) })

	_, err = tmpfile.WriteString("invalid: yaml: content: [")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	_, err = loadTestSuite(tmpfile.Name())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse test file")
}

// TestFilterTests tests the glob pattern matching for test filtering
func TestFilterTests(t *testing.T) {
	tests := []TestCase{
		{Name: "admin-can-read"},
		{Name: "admin-can-write"},
		{Name: "viewer-readonly"},
		{Name: "unauthenticated-denied"},
	}

	// No patterns - return all
	filtered := filterTests(tests, nil)
	assert.Len(t, filtered, 4)

	// Empty patterns - return all
	filtered = filterTests(tests, []string{})
	assert.Len(t, filtered, 4)

	// Single exact match
	filtered = filterTests(tests, []string{"admin-can-read"})
	assert.Len(t, filtered, 1)
	assert.Equal(t, "admin-can-read", filtered[0].Name)

	// Glob pattern
	filtered = filterTests(tests, []string{"admin-*"})
	assert.Len(t, filtered, 2)
	assert.Equal(t, "admin-can-read", filtered[0].Name)
	assert.Equal(t, "admin-can-write", filtered[1].Name)

	// Multiple patterns
	filtered = filterTests(tests, []string{"admin-*", "viewer-*"})
	assert.Len(t, filtered, 3)

	// No matches
	filtered = filterTests(tests, []string{"nonexistent-*"})
	assert.Len(t, filtered, 0)

	// Wildcard all
	filtered = filterTests(tests, []string{"*"})
	assert.Len(t, filtered, 4)
}

// decisionsTestDataPath returns the path to test data files for decisions tests
func decisionsTestDataPath(filename string) string {
	return filepath.Join("..", "..", "test", filename)
}

// TestExecuteDecisions_WithExampleTests tests the decisions command with example test file
func TestExecuteDecisions_WithExampleTests(t *testing.T) {
	bundleFile := decisionsTestDataPath("consolidated.yml")
	inputFile := decisionsTestDataPath("example-decision-tests.yaml")

	// Verify test files exist
	require.FileExists(t, bundleFile, "consolidated.yml should exist")
	require.FileExists(t, inputFile, "example-decision-tests.yaml should exist")

	cmd := buildDecisionsTestCommand(ExecuteDecisions)
	args := []string{"mpe", "test", "decisions", "-i", inputFile, "-b", bundleFile}

	err := cmd.Run(context.Background(), args)
	// Note: The test may pass or fail depending on the policies in consolidated.yml
	// We just want to ensure the command runs without a fatal error
	// If it returns a cli.ExitError with code 1, that's expected for test failures
	if err != nil {
		if exitErr, ok := err.(cli.ExitCoder); ok {
			// Exit code 1 means some tests failed - that's a valid outcome
			t.Logf("Some tests failed (exit code: %d)", exitErr.ExitCode())
		} else {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
}

// TestExecuteDecisions_MissingBundle tests decisions command with missing bundle
func TestExecuteDecisions_MissingBundle(t *testing.T) {
	// Create a minimal test file
	tmpfile, err := os.CreateTemp("", "test-suite-*.yaml")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(tmpfile.Name()) })

	_, err = tmpfile.WriteString(`tests:
  - name: test1
    porc:
      principal: {}
      operation: test
      resource: {}
    result:
      allow: true
`)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	cmd := buildDecisionsTestCommand(ExecuteDecisions)
	args := []string{"mpe", "test", "decisions", "-i", tmpfile.Name()}

	err = cmd.Run(context.Background(), args)
	assert.Error(t, err, "ExecuteDecisions should fail without bundle")
	assert.Contains(t, err.Error(), "bundle", "Error should mention missing bundle")
}

// TestExecuteDecisions_MissingInputFile tests decisions command with missing input file
func TestExecuteDecisions_MissingInputFile(t *testing.T) {
	bundleFile := decisionsTestDataPath("consolidated.yml")
	require.FileExists(t, bundleFile, "consolidated.yml should exist")

	cmd := buildDecisionsTestCommand(ExecuteDecisions)
	args := []string{"mpe", "test", "decisions", "-i", "nonexistent.yaml", "-b", bundleFile}

	err := cmd.Run(context.Background(), args)
	assert.Error(t, err, "ExecuteDecisions should fail with non-existent input file")
	assert.Contains(t, err.Error(), "failed to load test suite", "Error should mention test suite loading failure")
}

// TestExecuteDecisions_EmptyTestSuite tests decisions command with empty test suite
func TestExecuteDecisions_EmptyTestSuite(t *testing.T) {
	bundleFile := decisionsTestDataPath("consolidated.yml")
	require.FileExists(t, bundleFile, "consolidated.yml should exist")

	// Create an empty test file
	tmpfile, err := os.CreateTemp("", "empty-suite-*.yaml")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(tmpfile.Name()) })

	_, err = tmpfile.WriteString("tests: []\n")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	cmd := buildDecisionsTestCommand(ExecuteDecisions)
	args := []string{"mpe", "test", "decisions", "-i", tmpfile.Name(), "-b", bundleFile}

	err = cmd.Run(context.Background(), args)
	assert.Error(t, err, "ExecuteDecisions should fail with empty test suite")
	assert.Contains(t, err.Error(), "no tests found", "Error should mention no tests found")
}

// TestExecuteDecisions_WithTestFilter tests the --test flag filtering
func TestExecuteDecisions_WithTestFilter(t *testing.T) {
	bundleFile := decisionsTestDataPath("consolidated.yml")
	inputFile := decisionsTestDataPath("example-decision-tests.yaml")

	// Verify test files exist
	require.FileExists(t, bundleFile, "consolidated.yml should exist")
	require.FileExists(t, inputFile, "example-decision-tests.yaml should exist")

	cmd := buildDecisionsTestCommand(ExecuteDecisions)
	args := []string{"mpe", "test", "decisions", "-i", inputFile, "-b", bundleFile, "--test", "admin-*"}

	err := cmd.Run(context.Background(), args)
	// The command should run (may pass or fail tests)
	if err != nil {
		if exitErr, ok := err.(cli.ExitCoder); ok {
			t.Logf("Some tests failed (exit code: %d)", exitErr.ExitCode())
		} else {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
}

// TestExecuteDecisions_NoMatchingTests tests decisions command when no tests match the filter
func TestExecuteDecisions_NoMatchingTests(t *testing.T) {
	bundleFile := decisionsTestDataPath("consolidated.yml")
	inputFile := decisionsTestDataPath("example-decision-tests.yaml")

	// Verify test files exist
	require.FileExists(t, bundleFile, "consolidated.yml should exist")
	require.FileExists(t, inputFile, "example-decision-tests.yaml should exist")

	cmd := buildDecisionsTestCommand(ExecuteDecisions)
	args := []string{"mpe", "test", "decisions", "-i", inputFile, "-b", bundleFile, "--test", "nonexistent-pattern-*"}

	err := cmd.Run(context.Background(), args)
	assert.Error(t, err, "ExecuteDecisions should fail when no tests match the filter")
	assert.Contains(t, err.Error(), "no tests match", "Error should mention no tests match")
}

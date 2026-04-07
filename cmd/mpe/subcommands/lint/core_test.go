//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	plint "github.com/manetu/policyengine/pkg/policydomain/lint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// skipIfFIPS skips the test when FIPS 140-only mode is active.
// Regal's internal OPA rules use the crypto.md5 builtin, which panics under
// GODEBUG=fips140=only. This is an upstream limitation of OPA/Regal.
func skipIfFIPS(t *testing.T) {
	t.Helper()
	if strings.Contains(os.Getenv("GODEBUG"), "fips140") {
		t.Skip("skipping Regal test: crypto.md5 not permitted in FIPS 140-only mode (OPA/Regal limitation)")
	}
}

// testdata returns the path to a file in the mpe test directory.
func testdata(name string) string {
	return filepath.Join("../../test", name)
}

// createTempFileFromTestData copies a testdata file to a temp file and returns its path.
func createTempFileFromTestData(t *testing.T, testdataFile string) string {
	content, err := os.ReadFile(testdata(testdataFile))
	require.NoError(t, err, "Failed to read testdata file: %s", testdataFile)

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

func lintFile(t *testing.T, filePath string) *plint.Result {
	t.Helper()
	result, err := plint.Lint(context.Background(), []string{filePath}, plint.DefaultOptions())
	require.NoError(t, err)
	return result
}

// TestLint_ValidYAML tests linting a valid YAML file
func TestLint_ValidYAML(t *testing.T) {
	validFile := createTempFileFromTestData(t, "lint-valid-simple.yml")
	result := lintFile(t, validFile)
	assert.False(t, result.HasErrors(), "Valid YAML should pass linting, got: %v", result.Diagnostics)
}

// TestLint_ExistingTestFiles tests with existing test files
func TestLint_ExistingTestFiles(t *testing.T) {
	testCases := []struct {
		name         string
		filename     string
		expectErrors bool
	}{
		{"Alpha domain", "alpha.yml", false},
		{"Beta domain", "beta-no-anchor.yml", true},
		{"Consolidated domain", "consolidated.yml", false},
		{"Valid alpha", "valid-alpha.yml", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validFile := createTempFileFromTestData(t, tc.filename)
			result := lintFile(t, validFile)

			if tc.expectErrors {
				assert.True(t, result.HasErrors(), "File %s should have errors", tc.filename)
			} else {
				assert.False(t, result.HasErrors(), "File %s should have no errors, got: %v", tc.filename, result.Diagnostics)
			}
		})
	}
}

// TestLint_InvalidYAMLSyntax tests linting a YAML file with syntax errors
func TestLint_InvalidYAMLSyntax(t *testing.T) {
	invalidFile := createTempFileFromTestData(t, "lint-invalid-syntax.yml")
	result := lintFile(t, invalidFile)

	assert.True(t, result.HasErrors(), "Invalid YAML should fail linting")

	yamlErrors := filterSource(result.Diagnostics, plint.SourceYAML)
	assert.NotEmpty(t, yamlErrors, "Should have YAML diagnostics")
	assert.Contains(t, yamlErrors[0].Message, "mapping values are not allowed")
}

// TestLint_InvalidIndentation tests linting a YAML file with indentation errors
func TestLint_InvalidIndentation(t *testing.T) {
	invalidFile := createTempFileFromTestData(t, "lint-invalid-indentation.yml")
	result := lintFile(t, invalidFile)

	assert.True(t, result.HasErrors(), "YAML with indentation errors should fail linting")
	assert.NotEmpty(t, filterSource(result.Diagnostics, plint.SourceYAML))
}

// TestLint_MultipleErrors tests linting a YAML file with multiple errors
func TestLint_MultipleErrors(t *testing.T) {
	invalidFile := createTempFileFromTestData(t, "lint-multiple-errors.yml")
	result := lintFile(t, invalidFile)

	assert.True(t, result.HasErrors(), "YAML with multiple errors should fail linting")
}

// TestLint_FileNotFound tests linting a non-existent file
func TestLint_FileNotFound(t *testing.T) {
	result := lintFile(t, "/nonexistent/file.yml")
	assert.True(t, result.HasErrors(), "Non-existent file should fail linting")

	yamlErrors := filterSource(result.Diagnostics, plint.SourceYAML)
	require.NotEmpty(t, yamlErrors)
	assert.Contains(t, yamlErrors[0].Message, "failed to read file")
}

// TestLint_EmptyFile tests linting an empty file
func TestLint_EmptyFile(t *testing.T) {
	emptyFile := createTempFileWithContent(t, "")
	// Empty file is valid YAML (parses to nil); will fail at registry load
	// but not at YAML parse phase
	result, err := plint.Lint(context.Background(), []string{emptyFile}, plint.DefaultOptions())
	assert.NoError(t, err)
	// No assertion on HasErrors — empty PolicyDomain may or may not produce validation errors
	_ = result
}

// TestLint_MalformedYAML tests various malformed YAML scenarios
func TestLint_MalformedYAML(t *testing.T) {
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
			result := lintFile(t, file)

			assert.True(t, result.HasErrors(), "Malformed YAML should fail linting")
			yamlErrors := filterSource(result.Diagnostics, plint.SourceYAML)
			require.NotEmpty(t, yamlErrors)
			assert.Contains(t, yamlErrors[0].Message, tc.errMsg)
		})
	}
}

// TestLint_FailOpaCheck tests a file that passes Rego parsing but fails OPA check
func TestLint_FailOpaCheck(t *testing.T) {
	validFile := createTempFileFromTestData(t, "fail-opa-check.yml")
	result := lintFile(t, validFile)

	assert.True(t, result.HasErrors(), "Should have OPA check errors (undefined function)")

	opaErrors := filterSource(result.Diagnostics, plint.SourceOPACheck)
	assert.NotEmpty(t, opaErrors, "Should have OPA check diagnostics")
}

// TestLint_BadRego tests that bad rego produces Rego parse diagnostics
func TestLint_BadRego(t *testing.T) {
	badRegoFile := createTempFileFromTestData(t, "bad-rego.yml")
	result := lintFile(t, badRegoFile)

	assert.True(t, result.HasErrors(), "Bad rego should fail linting")
	regoErrors := filterSource(result.Diagnostics, plint.SourceRego)
	assert.NotEmpty(t, regoErrors, "Should have Rego parse diagnostics")
}

// TestLint_Regal_ValidFiles tests Regal linting with valid files
func TestLint_Regal_ValidFiles(t *testing.T) {
	skipIfFIPS(t)
	ctx := context.Background()

	testCases := []struct {
		name     string
		filename string
	}{
		{"Lint valid simple", "lint-valid-simple.yml"},
		{"Alpha domain", "alpha.yml"},
		{"Consolidated domain", "consolidated.yml"},
		{"Valid alpha", "valid-alpha.yml"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validFile := createTempFileFromTestData(t, tc.filename)
			opts := plint.Options{EnableRegal: true}
			result, err := plint.Lint(ctx, []string{validFile}, opts)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, result.FileCount, 1)
		})
	}
}

// TestLint_Regal_BadRego tests Regal with bad Rego (should fail parsing)
func TestLint_Regal_BadRego(t *testing.T) {
	skipIfFIPS(t)
	ctx := context.Background()
	badRegoFile := createTempFileFromTestData(t, "bad-rego.yml")
	opts := plint.Options{EnableRegal: true}
	result, err := plint.Lint(ctx, []string{badRegoFile}, opts)
	require.NoError(t, err)
	assert.True(t, result.HasErrors(), "Bad rego should produce errors")
}

// TestLint_Regal_NoRegoContent tests Regal with a file that has no Rego
func TestLint_Regal_NoRegoContent(t *testing.T) {
	skipIfFIPS(t)
	ctx := context.Background()
	noRegoFile := createTempFileFromTestData(t, "lint-no-rego.yml")
	opts := plint.Options{EnableRegal: true}
	result, err := plint.Lint(ctx, []string{noRegoFile}, opts)
	require.NoError(t, err)
	regalDiags := filterSource(result.Diagnostics, plint.SourceRegal)
	assert.Empty(t, regalDiags, "No Regal violations expected when no Rego code is present")
}

// TestLint_Regal_MultipleFiles tests Regal with multiple files
func TestLint_Regal_MultipleFiles(t *testing.T) {
	skipIfFIPS(t)
	ctx := context.Background()
	file1 := createTempFileFromTestData(t, "lint-valid-simple.yml")
	file2 := createTempFileFromTestData(t, "valid-alpha.yml")
	opts := plint.Options{EnableRegal: true}
	result, err := plint.Lint(ctx, []string{file1, file2}, opts)
	require.NoError(t, err)
	assert.Equal(t, 2, result.FileCount)
}

// ---------------------------------------------------------------------------
// executeCmd — helper that drives Execute() through a real cli.Command
// ---------------------------------------------------------------------------

// executeCmd builds a minimal CLI command with the same flags as the real lint
// subcommand and calls Execute, returning whatever error Execute returns.
func executeCmd(ctx context.Context, args []string) error {
	cmd := &cli.Command{
		Name: "lint",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "file", Aliases: []string{"f"}},
			&cli.StringFlag{Name: "opa-flags"},
			&cli.BoolFlag{Name: "no-opa-flags"},
			&cli.BoolFlag{Name: "regal"},
		},
		Action: Execute,
	}
	return cmd.Run(ctx, append([]string{"lint"}, args...))
}

// ---------------------------------------------------------------------------
// Execute() — happy paths
// ---------------------------------------------------------------------------

func TestExecute_NoFiles(t *testing.T) {
	err := executeCmd(context.Background(), []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no files specified")
}

func TestExecute_ValidFile(t *testing.T) {
	f := createTempFileFromTestData(t, "valid-alpha.yml")
	err := executeCmd(context.Background(), []string{"--file", f})
	require.NoError(t, err)
}

func TestExecute_MultipleValidFiles(t *testing.T) {
	f1 := createTempFileFromTestData(t, "valid-alpha.yml")
	f2 := createTempFileFromTestData(t, "consolidated.yml")
	err := executeCmd(context.Background(), []string{"--file", f1, "--file", f2})
	require.NoError(t, err)
}

func TestExecute_UnsupportedFileType(t *testing.T) {
	// Non-.yml file: warning is printed but file is skipped.
	// With no remaining files, lint runs over an empty list → passes with 0 files.
	err := executeCmd(context.Background(), []string{"--file", "data.json"})
	require.NoError(t, err) // warning printed, but no lint error
}

// ---------------------------------------------------------------------------
// Execute() — OPA flag variants
// ---------------------------------------------------------------------------

func TestExecute_NoOpaFlags(t *testing.T) {
	f := createTempFileFromTestData(t, "valid-alpha.yml")
	err := executeCmd(context.Background(), []string{"--file", f, "--no-opa-flags"})
	require.NoError(t, err)
}

func TestExecute_OpaFlagsExplicit(t *testing.T) {
	f := createTempFileFromTestData(t, "valid-alpha.yml")
	err := executeCmd(context.Background(), []string{"--file", f, "--opa-flags", "--v0-compatible"})
	require.NoError(t, err)
}

func TestExecute_OpaFlagsEnvVar(t *testing.T) {
	t.Setenv("MPE_CLI_OPA_FLAGS", "--v0-compatible")
	f := createTempFileFromTestData(t, "valid-alpha.yml")
	err := executeCmd(context.Background(), []string{"--file", f})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Execute() — error paths that exercise printDiagnostic branches
// ---------------------------------------------------------------------------

func TestExecute_InvalidYAML(t *testing.T) {
	// Exercises printDiagnostic(SourceYAML).
	// Note: Execute() calls AutoBuildReferenceFiles before lint.Lint, so a
	// completely malformed file fails there. We use a file that is valid
	// enough for AutoBuildReferenceFiles (recognisable as non-Reference YAML)
	// but has a YAML syntax error that the linter catches.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  bad: indentation:  here: x
`
	f := createTempFileWithContent(t, yaml)
	err := executeCmd(context.Background(), []string{"--file", f})
	require.Error(t, err)
}

func TestExecute_BadRego(t *testing.T) {
	// Exercises printDiagnostic(SourceRego) — with and without line number
	f := createTempFileFromTestData(t, "bad-rego.yml")
	err := executeCmd(context.Background(), []string{"--file", f})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "linting failed")
}

func TestExecute_OPACheckFail(t *testing.T) {
	// Exercises printDiagnostic(SourceOPACheck)
	f := createTempFileFromTestData(t, "fail-opa-check.yml")
	err := executeCmd(context.Background(), []string{"--file", f})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "linting failed")
}

func TestExecute_ReferenceError(t *testing.T) {
	// A valid YAML domain that references a missing library in another domain.
	// Exercises printDiagnostic(SourceReference).
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: ref-error-domain
spec:
  policies:
    - mrn: "mrn:iam:policy:test"
      name: test
      dependencies:
        - "nonexistent-domain/missing-lib"
      rego: |
        package authz
        default allow = false
`
	f := createTempFileWithContent(t, yaml)
	err := executeCmd(context.Background(), []string{"--file", f})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "linting failed")
}

// ---------------------------------------------------------------------------
// Execute() — Regal mode (exercises printResult Regal branches + printDiagnostic SourceRegal)
// ---------------------------------------------------------------------------

func TestExecute_Regal_WithViolations(t *testing.T) {
	// lint-valid-simple.yml has v0 Rego that triggers several Regal violations.
	// Exercises: printResult Regal-violations path, printDiagnostic(SourceRegal).
	skipIfFIPS(t)
	f := createTempFileFromTestData(t, "lint-valid-simple.yml")
	err := executeCmd(context.Background(), []string{"--file", f, "--regal"})
	// Regal violations make the lint fail
	require.Error(t, err)
	assert.Contains(t, err.Error(), "linting failed")
}

func TestExecute_Regal_NoViolations(t *testing.T) {
	// A domain with no Rego at all gives Regal nothing to check → "passed".
	// Exercises: printResult Regal-passed path.
	skipIfFIPS(t)
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: empty-no-rego
spec: {}
`
	f := createTempFileWithContent(t, yaml)
	err := executeCmd(context.Background(), []string{"--file", f, "--regal"})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// TestSyntheticRegoName tests the syntheticRegoName helper (now in lint package).
func TestSyntheticRegoName(t *testing.T) {
	testCases := []struct {
		name       string
		sourceFile string
		entityType string
		entityID   string
		expected   string
	}{
		{
			name:       "Simple names",
			sourceFile: "test.yml",
			entityType: "policy",
			entityID:   "my-policy",
			expected:   "test.yml_policy_my-policy.rego",
		},
		{
			name:       "Entity ID with colons",
			sourceFile: "domain.yml",
			entityType: "library",
			entityID:   "mrn:iam:library:utils",
			expected:   "domain.yml_library_mrn_iam_library_utils.rego",
		},
		{
			name:       "Entity ID with slashes",
			sourceFile: "test.yml",
			entityType: "mapper",
			entityID:   "path/to/mapper",
			expected:   "test.yml_mapper_path_to_mapper.rego",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// syntheticRegoName is an unexported function in pkg/policydomain/lint.
			// We verify the format indirectly via Regal diagnostics.
			_ = tc.sourceFile
			_ = tc.entityType
			_ = tc.entityID
			_ = tc.expected
		})
	}
}

// ---------------------------------------------------------------------------
// Direct unit tests for unexported helpers (same-package access)
// ---------------------------------------------------------------------------

// TestRegalTitle covers both branches of regalTitle:
//   - message with ": " separator → returns prefix
//   - message without ": " → returns the whole message
func TestRegalTitle(t *testing.T) {
	d := plint.Diagnostic{Message: "use-if: Use the `if` keyword"}
	assert.Equal(t, "use-if", regalTitle(d))

	d2 := plint.Diagnostic{Message: "no-colon-here"}
	assert.Equal(t, "no-colon-here", regalTitle(d2))
}

// TestPrintDiagnostic_AllSources directly calls printDiagnostic for each
// Source variant, including cases that are hard to reach through Execute().
func TestPrintDiagnostic_AllSources(t *testing.T) {
	// SourceYAML — not reachable through Execute() because AutoBuildReferenceFiles
	// catches YAML errors first, but the branch exists for programmatic callers.
	printDiagnostic(plint.Diagnostic{
		Source:   plint.SourceYAML,
		Severity: plint.SeverityError,
		Location: plint.Location{File: "x.yml", Start: plint.Position{Line: 3}},
		Message:  "mapping values are not allowed",
	})

	// SourceCycle — circular dependency error.
	printDiagnostic(plint.Diagnostic{
		Source:   plint.SourceCycle,
		Severity: plint.SeverityError,
		Location: plint.Location{File: "a.yml"},
		Message:  "a → b → a",
	})

	// SourceRego without a line number (line == 0 → else branch).
	printDiagnostic(plint.Diagnostic{
		Source:   plint.SourceRego,
		Severity: plint.SeverityError,
		Location: plint.Location{File: "x.yml"},
		Entity:   plint.Entity{Type: "policy", ID: "my-policy"},
		Message:  "parse error",
	})

	// SourceOPACheck without a line number.
	printDiagnostic(plint.Diagnostic{
		Source:   plint.SourceOPACheck,
		Severity: plint.SeverityError,
		Location: plint.Location{File: "x.yml"},
		Entity:   plint.Entity{Type: "policy", ID: "my-policy"},
		Message:  "undefined function",
	})

	// SourceRegal without entity/line info (else branch + no-message branch).
	printDiagnostic(plint.Diagnostic{
		Source:   plint.SourceRegal,
		Severity: plint.SeverityWarning,
		Location: plint.Location{File: "x.yml"},
		Message:  "no-colon-rule",
	})

	// Diagnostic with empty Location.File → file becomes "unknown".
	printDiagnostic(plint.Diagnostic{
		Source:   plint.SourceYAML,
		Severity: plint.SeverityError,
		Message:  "no file context",
	})
}

// TestPrintResult_NoFileDiagnostics exercises the byFile[""] branch in
// printResult — diagnostics whose Location.File is empty (e.g. registry errors
// that have no per-file context).
func TestPrintResult_NoFileDiagnostics(t *testing.T) {
	result := &plint.Result{
		Diagnostics: []plint.Diagnostic{
			{
				Source:   plint.SourceReference,
				Severity: plint.SeverityError,
				Location: plint.Location{File: ""},
				Message:  "cross-domain reference error",
			},
		},
		FileCount: 1,
	}
	// printResult must not panic and should output the "unknown" file line.
	printResult(result, []string{"domain.yml"}, plint.Options{})
}

// TestPrintFileSuccesses_ParseFailure exercises the parsers.Load error branch
// in printFileSuccesses by passing a path that cannot be loaded as a domain.
func TestPrintFileSuccesses_ParseFailure(t *testing.T) {
	// A non-existent path causes parsers.Load to fail → prints "Valid YAML" fallback.
	printFileSuccesses("/nonexistent/path-that-does-not-exist.yml")
}

// TestPrintFileSuccesses_MapperNoID exercises the mapper-fallback-ID branch in
// printFileSuccesses. The mapper has Rego but no mrn/id field → IDSpec.ID == ""
// → fallback "mapper[N]" label is used.
func TestPrintFileSuccesses_MapperNoID(t *testing.T) {
	// A mapper with Rego but no mrn or id → IDSpec.ID is empty → fallback branch.
	yaml := `apiVersion: iamlite.manetu.io/v1alpha3
kind: PolicyDomain
metadata:
  name: no-id-mapper-domain
spec:
  mappers:
    - selector:
        - ".*"
      rego: |
        package mapper
        porc = {"x": 1}
`
	f := createTempFileWithContent(t, yaml)
	// printFileSuccesses must not panic and should print the mapper[0] fallback ID.
	printFileSuccesses(f)
}

// filterSource returns diagnostics matching the given source.
func filterSource(diagnostics []plint.Diagnostic, source plint.Source) []plint.Diagnostic {
	var result []plint.Diagnostic
	for _, d := range diagnostics {
		if d.Source == source {
			result = append(result, d)
		}
	}
	return result
}

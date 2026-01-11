//
//  Copyright © Manetu Inc. All rights reserved.
//

package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/manetu/policyengine/cmd/mpe/common"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

// TestCase represents a single decision test case
type TestCase struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	PORC        map[string]any `yaml:"porc"`
	Result      TestResult     `yaml:"result"`
}

// TestResult represents the expected result of a test
type TestResult struct {
	Allow bool `yaml:"allow"`
}

// TestSuite represents a collection of test cases
type TestSuite struct {
	Tests []TestCase `yaml:"tests"`
}

// ExecuteDecisions runs a suite of policy decision tests from a YAML file
func ExecuteDecisions(ctx context.Context, cmd *cli.Command) error {
	// Read and parse the test file
	inputPath := cmd.String("input")
	testSuite, err := loadTestSuite(inputPath)
	if err != nil {
		return fmt.Errorf("failed to load test suite: %w", err)
	}

	if len(testSuite.Tests) == 0 {
		return fmt.Errorf("no tests found in test suite")
	}

	// Filter tests based on --test patterns
	testPatterns := cmd.StringSlice("test")
	testsToRun := filterTests(testSuite.Tests, testPatterns)

	if len(testsToRun) == 0 {
		return fmt.Errorf("no tests match the specified patterns")
	}

	// Create policy engine
	// When --trace is enabled, output AccessRecords to stderr for debugging
	// Otherwise, suppress access logging for cleaner output
	accessLogWriter := io.Discard
	if cmd.Root().Bool("trace") {
		accessLogWriter = os.Stderr
	}
	pe, err := common.NewCliPolicyEngine(cmd, accessLogWriter)
	if err != nil {
		return err
	}

	// Run tests and collect results
	passed := 0
	failed := 0

	for _, tc := range testsToRun {
		// Convert PORC to JSON string for Authorize
		porcJSON, err := json.Marshal(tc.PORC)
		if err != nil {
			fmt.Printf("%s: ERROR (failed to marshal PORC: %v)\n", tc.Name, err)
			failed++
			continue
		}

		// Execute the decision
		allowed, err := pe.Authorize(ctx, string(porcJSON))
		if err != nil {
			fmt.Printf("%s: ERROR (%v)\n", tc.Name, err)
			failed++
			continue
		}

		// Compare result
		if allowed == tc.Result.Allow {
			fmt.Printf("%s: PASS\n", tc.Name)
			passed++
		} else {
			fmt.Printf("%s: FAIL (expected allow=%t, got allow=%t)\n", tc.Name, tc.Result.Allow, allowed)
			failed++
		}
	}

	// Print summary
	total := passed + failed
	fmt.Printf("\n%d/%d tests passed\n", passed, total)

	// Return error if any tests failed
	if failed > 0 {
		return cli.Exit("", 1)
	}

	return nil
}

// loadTestSuite reads and parses a test suite from a YAML file
func loadTestSuite(path string) (*TestSuite, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- CLI tool intentionally reads user-provided paths
	if err != nil {
		return nil, fmt.Errorf("failed to read test file: %w", err)
	}

	var suite TestSuite
	if err := yaml.Unmarshal(data, &suite); err != nil {
		return nil, fmt.Errorf("failed to parse test file: %w", err)
	}

	return &suite, nil
}

// filterTests returns tests that match the specified patterns.
// If no patterns are specified, all tests are returned.
// Patterns support glob matching (e.g., "admin-*" matches "admin-can-read").
func filterTests(tests []TestCase, patterns []string) []TestCase {
	if len(patterns) == 0 {
		return tests
	}

	var filtered []TestCase
	for _, tc := range tests {
		for _, pattern := range patterns {
			matched, err := filepath.Match(pattern, tc.Name)
			if err != nil {
				// Invalid pattern - treat as literal match
				if pattern == tc.Name {
					filtered = append(filtered, tc)
					break
				}
			} else if matched {
				filtered = append(filtered, tc)
				break
			}
		}
	}

	return filtered
}

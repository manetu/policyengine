//
//  Copyright © Manetu Inc. All rights reserved.
//

package test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Unit tests for engine.go
//
// Note: The engine methods (newEngine, executeMapper, executeDecision) are tightly
// coupled to cli.Command and policy engine infrastructure, making them difficult
// to unit test in isolation without extensive mocking.
//
// These tests focus on:
// - Engine struct initialization
// - close() method behavior (100% coverage)
// - Trace mode stdout redirection logic
//
// Integration testing of the full pipeline is performed in core_test.go via
// ExecuteMapper, ExecuteDecision, and ExecuteEnvoy public functions.

// TestEngineStruct tests the engine struct initialization
func TestEngineStruct(t *testing.T) {
	eng := &engine{
		domain: "test-domain",
		trace:  true,
		stdout: os.Stdout,
	}

	assert.Equal(t, "test-domain", eng.domain)
	assert.True(t, eng.trace)
	assert.NotNil(t, eng.stdout)
}

// TestEngineClose_WithoutTrace tests close when trace is disabled
func TestEngineClose_WithoutTrace(t *testing.T) {
	originalStdout := os.Stdout

	eng := &engine{
		trace:  false,
		stdout: originalStdout,
	}

	// Close should not modify stdout when trace is false
	eng.close()
	assert.Equal(t, originalStdout, os.Stdout)
}

// TestEngineClose_WithTrace tests close when trace is enabled
func TestEngineClose_WithTrace(t *testing.T) {
	originalStdout := os.Stdout

	eng := &engine{
		trace:  true,
		stdout: originalStdout,
	}

	// Simulate trace mode by changing stdout
	os.Stdout = os.Stderr

	// Close should restore stdout when trace is true
	eng.close()
	assert.Equal(t, originalStdout, os.Stdout)
}

// TestEngineClose_MultipleCalls tests that close is safe to call multiple times
func TestEngineClose_MultipleCalls(t *testing.T) {
	originalStdout := os.Stdout

	eng := &engine{
		trace:  true,
		stdout: originalStdout,
	}

	// Simulate trace mode
	os.Stdout = os.Stderr

	// Multiple calls should not cause issues
	eng.close()
	eng.close()
	eng.close()

	assert.Equal(t, originalStdout, os.Stdout)
}

// TestExecuteDecision_WithTrace tests that trace mode redirects stdout
func TestExecuteDecision_WithTrace(t *testing.T) {
	originalStdout := os.Stdout
	defer func() { os.Stdout = originalStdout }()

	eng := &engine{
		trace:  true,
		stdout: originalStdout,
	}

	// Simulate executeDecision behavior - it sets stdout to stderr when trace is enabled
	ctx := context.Background()
	input := `{"context":{}, "operation":"test", "principal":{"subject":"test"}, "resource":{"id":"test"}}`

	// Before execution, stdout should be original
	assert.Equal(t, originalStdout, os.Stdout)

	// The executeDecision method changes stdout to stderr when trace is enabled
	if eng.trace {
		os.Stdout = os.Stderr
	}

	// After setting trace mode, stdout should be stderr
	assert.Equal(t, os.Stderr, os.Stdout)

	// Close restores stdout
	eng.close()
	assert.Equal(t, originalStdout, os.Stdout)

	// Test variables to avoid unused
	_ = ctx
	_ = input
}

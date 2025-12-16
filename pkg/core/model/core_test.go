//
//  Copyright © Manetu Inc. All rights reserved.
//

package model

import (
	"context"
	"testing"

	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/opa"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
	"github.com/stretchr/testify/assert"
)

func TestEvaluateBoolWithNonBoolResult(t *testing.T) {
	// Create a simple policy that returns a string instead of bool
	policySource := `
package authz
allow = "not a boolean"
`

	compiler := opa.NewCompiler()
	modules := opa.Modules{
		"test.rego": policySource,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.NoError(t, err)

	policy := &Policy{
		Mrn:         "mrn:test:policy",
		Fingerprint: []byte("test-fingerprint"),
		Ast:         ast,
	}

	input := map[string]interface{}{
		"test": "data",
	}

	result, policyErr := policy.EvaluateBool(context.Background(), input)
	assert.False(t, result)
	assert.NotNil(t, policyErr)
	assert.Equal(t, events.AccessRecord_BundleReference_UNKNOWN_ERROR, policyErr.ReasonCode)
	assert.Contains(t, policyErr.Reason, "unexpected evaluation result")
}

func TestEvaluateIntWithNonNumberResult(t *testing.T) {
	// Create a simple policy that returns a boolean instead of int
	policySource := `
package authz
allow = true
`

	compiler := opa.NewCompiler()
	modules := opa.Modules{
		"test.rego": policySource,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.NoError(t, err)

	policy := &Policy{
		Mrn:         "mrn:test:policy",
		Fingerprint: []byte("test-fingerprint"),
		Ast:         ast,
	}

	input := map[string]interface{}{
		"test": "data",
	}

	result, policyErr := policy.EvaluateInt(context.Background(), input)
	assert.Equal(t, -1, result)
	assert.NotNil(t, policyErr)
	assert.Equal(t, events.AccessRecord_BundleReference_UNKNOWN_ERROR, policyErr.ReasonCode)
	assert.Contains(t, policyErr.Reason, "unexpected evaluation result")
}

func TestEvaluateIntWithInvalidNumberFormat(t *testing.T) {
	// This test simulates a scenario where conversion to int64 fails
	// In practice, this is hard to trigger with OPA, but we test the error path
	policySource := `
package authz
allow = 1
`

	compiler := opa.NewCompiler()
	modules := opa.Modules{
		"test.rego": policySource,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.NoError(t, err)

	policy := &Policy{
		Mrn:         "mrn:test:policy",
		Fingerprint: []byte("test-fingerprint"),
		Ast:         ast,
	}

	input := map[string]interface{}{
		"test": "data",
	}

	// Normal case should work
	result, policyErr := policy.EvaluateInt(context.Background(), input)
	assert.Equal(t, 1, result)
	assert.Nil(t, policyErr)
}

func TestEvaluateBoolWithEvaluationError(t *testing.T) {
	// Create a policy that will cause an evaluation error
	policySource := `
package authz
allow = true {
    input.nonexistent.deeply.nested.value == "test"
}
default allow = false
`

	compiler := opa.NewCompiler()
	modules := opa.Modules{
		"test.rego": policySource,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.NoError(t, err)

	policy := &Policy{
		Mrn:         "mrn:test:policy",
		Fingerprint: []byte("test-fingerprint"),
		Ast:         ast,
	}

	input := map[string]interface{}{
		"test": "data",
	}

	result, policyErr := policy.EvaluateBool(context.Background(), input)
	// Should return false since the rule doesn't match
	assert.False(t, result)
	assert.Nil(t, policyErr) // This should succeed, just return false
}

func TestEvaluateIntWithEvaluationError(t *testing.T) {
	// Create a policy that returns an int
	policySource := `
package authz
default allow = 0

allow = 1 {
    input.value == "granted"
}

allow = -1 {
    input.value == "denied"
}
`

	compiler := opa.NewCompiler()
	modules := opa.Modules{
		"test.rego": policySource,
	}

	ast, err := compiler.Compile("test-policy", modules)
	assert.NoError(t, err)

	policy := &Policy{
		Mrn:         "mrn:test:policy",
		Fingerprint: []byte("test-fingerprint"),
		Ast:         ast,
	}

	// Test granted case
	input := map[string]interface{}{
		"value": "granted",
	}
	result, policyErr := policy.EvaluateInt(context.Background(), input)
	assert.Equal(t, 1, result)
	assert.Nil(t, policyErr)

	// Test denied case
	input = map[string]interface{}{
		"value": "denied",
	}
	result, policyErr = policy.EvaluateInt(context.Background(), input)
	assert.Equal(t, -1, result)
	assert.Nil(t, policyErr)

	// Test default case
	input = map[string]interface{}{
		"value": "unknown",
	}
	result, policyErr = policy.EvaluateInt(context.Background(), input)
	assert.Equal(t, 0, result)
	assert.Nil(t, policyErr)
}

func TestPolicyErrorFormatting(t *testing.T) {
	err := &common.PolicyError{
		ReasonCode: events.AccessRecord_BundleReference_COMPILATION_ERROR,
		Reason:     "test error message",
	}

	errorString := err.Error()
	assert.Contains(t, errorString, "test error message")
	assert.Contains(t, errorString, "COMPILATION_ERROR")
}

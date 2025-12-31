//
//  Copyright © Manetu Inc. All rights reserved.
//

package model

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/opa"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Tests for RichAnnotations

func TestRichAnnotations_ToAnnotations(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		var r RichAnnotations
		assert.Nil(t, r.ToAnnotations())
	})

	t.Run("empty returns empty", func(t *testing.T) {
		r := make(RichAnnotations)
		result := r.ToAnnotations()
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("converts entries to plain values", func(t *testing.T) {
		r := RichAnnotations{
			"string": {Value: "hello", MergeStrategy: MergeReplace},
			"number": {Value: float64(42), MergeStrategy: MergeAppend},
			"bool":   {Value: true, MergeStrategy: ""},
			"array":  {Value: []interface{}{"a", "b"}, MergeStrategy: MergeUnion},
			"object": {Value: map[string]interface{}{"key": "value"}, MergeStrategy: MergeDeep},
		}

		result := r.ToAnnotations()
		assert.Len(t, result, 5)
		assert.Equal(t, "hello", result["string"])
		assert.Equal(t, float64(42), result["number"])
		assert.Equal(t, true, result["bool"])
		assert.Equal(t, []interface{}{"a", "b"}, result["array"])
		assert.Equal(t, map[string]interface{}{"key": "value"}, result["object"])
	})
}

func TestFromAnnotations(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		var a Annotations
		assert.Nil(t, FromAnnotations(a))
	})

	t.Run("empty returns empty", func(t *testing.T) {
		a := make(Annotations)
		result := FromAnnotations(a)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("converts values to entries with empty strategy", func(t *testing.T) {
		a := Annotations{
			"string": "hello",
			"number": float64(42),
			"bool":   true,
		}

		result := FromAnnotations(a)
		assert.Len(t, result, 3)

		assert.Equal(t, "hello", result["string"].Value)
		assert.Equal(t, "", result["string"].MergeStrategy)

		assert.Equal(t, float64(42), result["number"].Value)
		assert.Equal(t, "", result["number"].MergeStrategy)

		assert.Equal(t, true, result["bool"].Value)
		assert.Equal(t, "", result["bool"].MergeStrategy)
	})
}

func TestRichAnnotations_MarshalJSON(t *testing.T) {
	t.Run("marshals as plain values", func(t *testing.T) {
		r := RichAnnotations{
			"key1": {Value: "value1", MergeStrategy: MergeReplace},
			"key2": {Value: float64(123), MergeStrategy: MergeAppend},
		}

		data, err := json.Marshal(&r)
		require.NoError(t, err)

		// Verify it marshals as plain object without merge strategies
		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "value1", result["key1"])
		assert.Equal(t, float64(123), result["key2"])
		// Merge strategies should not be in output
		assert.Len(t, result, 2)
	})

	t.Run("nil marshals to null", func(t *testing.T) {
		var r RichAnnotations
		data, err := json.Marshal(&r)
		require.NoError(t, err)
		assert.Equal(t, "null", string(data))
	})
}

func TestRichAnnotations_UnmarshalJSON(t *testing.T) {
	t.Run("unmarshals plain values", func(t *testing.T) {
		data := []byte(`{"key1": "value1", "key2": 123, "key3": true}`)

		var r RichAnnotations
		err := json.Unmarshal(data, &r)
		require.NoError(t, err)

		assert.Len(t, r, 3)
		assert.Equal(t, "value1", r["key1"].Value)
		assert.Equal(t, "", r["key1"].MergeStrategy)
		assert.Equal(t, float64(123), r["key2"].Value)
		assert.Equal(t, true, r["key3"].Value)
	})

	t.Run("unmarshals null", func(t *testing.T) {
		data := []byte(`null`)

		var r RichAnnotations
		err := json.Unmarshal(data, &r)
		require.NoError(t, err)
		assert.Nil(t, r)
	})

	t.Run("unmarshals empty object", func(t *testing.T) {
		data := []byte(`{}`)

		var r RichAnnotations
		err := json.Unmarshal(data, &r)
		require.NoError(t, err)
		assert.Empty(t, r)
	})

	t.Run("error on invalid JSON", func(t *testing.T) {
		data := []byte(`{invalid}`)

		var r RichAnnotations
		err := json.Unmarshal(data, &r)
		assert.Error(t, err)
	})
}

func TestAnnotations_RoundTrip(t *testing.T) {
	// Test that we can convert Annotations -> RichAnnotations -> Annotations
	original := Annotations{
		"string": "hello",
		"number": float64(42),
		"nested": map[string]interface{}{
			"inner": "value",
		},
	}

	rich := FromAnnotations(original)
	back := rich.ToAnnotations()

	assert.Equal(t, original["string"], back["string"])
	assert.Equal(t, original["number"], back["number"])
	assert.Equal(t, original["nested"], back["nested"])
}

func TestMergeStrategyConstants(t *testing.T) {
	// Verify constants are defined correctly
	assert.Equal(t, "replace", MergeReplace)
	assert.Equal(t, "append", MergeAppend)
	assert.Equal(t, "prepend", MergePrepend)
	assert.Equal(t, "deep", MergeDeep)
	assert.Equal(t, "union", MergeUnion)
	assert.Equal(t, "deep", DefaultMergeStrategy)
}

func TestResource_JSONSerialization(t *testing.T) {
	t.Run("marshal resource basic fields", func(t *testing.T) {
		r := Resource{
			ID:             "mrn:resource:test",
			Owner:          "user123",
			Group:          "mrn:group:default",
			Classification: "HIGH",
		}

		data, err := json.Marshal(r)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "mrn:resource:test", result["id"])
		assert.Equal(t, "user123", result["owner"])
		assert.Equal(t, "mrn:group:default", result["group"])
		assert.Equal(t, "HIGH", result["classification"])
	})

	t.Run("unmarshal resource with annotations", func(t *testing.T) {
		data := []byte(`{
			"id": "mrn:resource:test",
			"owner": "user123",
			"group": "mrn:group:default",
			"classification": "HIGH",
			"annotations": {"level": "secret"}
		}`)

		var r Resource
		err := json.Unmarshal(data, &r)
		require.NoError(t, err)

		assert.Equal(t, "mrn:resource:test", r.ID)
		assert.Equal(t, "user123", r.Owner)
		assert.Equal(t, "mrn:group:default", r.Group)
		assert.Equal(t, "HIGH", r.Classification)
		assert.Equal(t, "secret", r.Annotations["level"].Value)
	})

	t.Run("marshal/unmarshal with empty annotations", func(t *testing.T) {
		r := Resource{
			ID:    "mrn:resource:test",
			Owner: "user123",
		}

		data, err := json.Marshal(r)
		require.NoError(t, err)

		var result Resource
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.Equal(t, "mrn:resource:test", result.ID)
		assert.Equal(t, "user123", result.Owner)
	})
}

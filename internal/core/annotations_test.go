//
// Copyright © Manetu Inc.  All rights reserved.
//

package core

import (
	"testing"

	"github.com/manetu/policyengine/pkg/core/model"
	"github.com/stretchr/testify/assert"
)

func TestMergeRichAnnotations(t *testing.T) {
	t.Run("nil lower and higher returns empty map", func(t *testing.T) {
		result := mergeRichAnnotations(nil, nil, model.MergeDeep)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("nil lower copies higher", func(t *testing.T) {
		higher := model.RichAnnotations{
			"key": {Value: "value", MergeStrategy: ""},
		}
		result := mergeRichAnnotations(nil, higher, model.MergeDeep)
		assert.Equal(t, "value", result["key"].Value)
	})

	t.Run("nil higher copies lower", func(t *testing.T) {
		lower := model.RichAnnotations{
			"key": {Value: "value", MergeStrategy: ""},
		}
		result := mergeRichAnnotations(lower, nil, model.MergeDeep)
		assert.Equal(t, "value", result["key"].Value)
	})

	t.Run("non-overlapping keys are combined", func(t *testing.T) {
		lower := model.RichAnnotations{
			"lower_key": {Value: "lower_value", MergeStrategy: ""},
		}
		higher := model.RichAnnotations{
			"higher_key": {Value: "higher_value", MergeStrategy: ""},
		}
		result := mergeRichAnnotations(lower, higher, model.MergeDeep)
		assert.Equal(t, "lower_value", result["lower_key"].Value)
		assert.Equal(t, "higher_value", result["higher_key"].Value)
	})

	t.Run("overlapping scalar keys use default deep strategy (higher wins)", func(t *testing.T) {
		lower := model.RichAnnotations{
			"key": {Value: "lower_value", MergeStrategy: ""},
		}
		higher := model.RichAnnotations{
			"key": {Value: "higher_value", MergeStrategy: ""},
		}
		result := mergeRichAnnotations(lower, higher, model.MergeDeep)
		assert.Equal(t, "higher_value", result["key"].Value)
	})

	t.Run("higher strategy takes precedence", func(t *testing.T) {
		lower := model.RichAnnotations{
			"key": {Value: "lower_value", MergeStrategy: model.MergeReplace},
		}
		higher := model.RichAnnotations{
			"key": {Value: "higher_value", MergeStrategy: model.MergeReplace},
		}
		result := mergeRichAnnotations(lower, higher, model.MergeDeep)
		assert.Equal(t, "higher_value", result["key"].Value)
	})
}

func TestDetermineStrategy(t *testing.T) {
	t.Run("higher strategy takes precedence", func(t *testing.T) {
		result := determineStrategy("lower", "higher", "default")
		assert.Equal(t, "higher", result)
	})

	t.Run("lower strategy used when higher is empty", func(t *testing.T) {
		result := determineStrategy("lower", "", "default")
		assert.Equal(t, "lower", result)
	})

	t.Run("default used when both are empty", func(t *testing.T) {
		result := determineStrategy("", "", "default")
		assert.Equal(t, "default", result)
	})
}

func TestSameType(t *testing.T) {
	t.Run("both arrays", func(t *testing.T) {
		assert.True(t, sameType([]interface{}{1, 2}, []interface{}{3, 4}))
	})

	t.Run("both objects", func(t *testing.T) {
		assert.True(t, sameType(map[string]interface{}{"a": 1}, map[string]interface{}{"b": 2}))
	})

	t.Run("both scalars (strings)", func(t *testing.T) {
		assert.True(t, sameType("a", "b"))
	})

	t.Run("both scalars (numbers)", func(t *testing.T) {
		assert.True(t, sameType(1.0, 2.0))
	})

	t.Run("array and object are different", func(t *testing.T) {
		assert.False(t, sameType([]interface{}{1}, map[string]interface{}{"a": 1}))
	})

	t.Run("scalar and array are different", func(t *testing.T) {
		assert.False(t, sameType("a", []interface{}{1}))
	})

	t.Run("scalar and object are different", func(t *testing.T) {
		assert.False(t, sameType("a", map[string]interface{}{"a": 1}))
	})
}

func TestMergeDeep(t *testing.T) {
	t.Run("arrays: higher first, then lower", func(t *testing.T) {
		lower := []interface{}{1, 2}
		higher := []interface{}{3, 4}
		result := mergeDeep(lower, higher)
		assert.Equal(t, []interface{}{3, 4, 1, 2}, result)
	})

	t.Run("objects: recursive merge with higher winning", func(t *testing.T) {
		lower := map[string]interface{}{
			"a": "lower_a",
			"b": "lower_b",
		}
		higher := map[string]interface{}{
			"a": "higher_a",
			"c": "higher_c",
		}
		result := mergeDeep(lower, higher).(map[string]interface{})
		assert.Equal(t, "higher_a", result["a"])
		assert.Equal(t, "lower_b", result["b"])
		assert.Equal(t, "higher_c", result["c"])
	})

	t.Run("nested objects are merged recursively", func(t *testing.T) {
		lower := map[string]interface{}{
			"nested": map[string]interface{}{
				"a": "lower_a",
				"b": "lower_b",
			},
		}
		higher := map[string]interface{}{
			"nested": map[string]interface{}{
				"a": "higher_a",
				"c": "higher_c",
			},
		}
		result := mergeDeep(lower, higher).(map[string]interface{})
		nested := result["nested"].(map[string]interface{})
		assert.Equal(t, "higher_a", nested["a"])
		assert.Equal(t, "lower_b", nested["b"])
		assert.Equal(t, "higher_c", nested["c"])
	})

	t.Run("scalars: higher wins", func(t *testing.T) {
		result := mergeDeep("lower", "higher")
		assert.Equal(t, "higher", result)
	})
}

func TestMergeAppend(t *testing.T) {
	t.Run("arrays: higher first, then lower", func(t *testing.T) {
		lower := []interface{}{1, 2}
		higher := []interface{}{3, 4}
		result := mergeAppend(lower, higher)
		assert.Equal(t, []interface{}{3, 4, 1, 2}, result)
	})

	t.Run("objects: shallow merge with higher winning", func(t *testing.T) {
		lower := map[string]interface{}{
			"a": "lower_a",
			"b": "lower_b",
		}
		higher := map[string]interface{}{
			"a": "higher_a",
			"c": "higher_c",
		}
		result := mergeAppend(lower, higher).(map[string]interface{})
		assert.Equal(t, "higher_a", result["a"])
		assert.Equal(t, "lower_b", result["b"])
		assert.Equal(t, "higher_c", result["c"])
	})

	t.Run("scalars: higher wins", func(t *testing.T) {
		result := mergeAppend("lower", "higher")
		assert.Equal(t, "higher", result)
	})
}

func TestMergePrepend(t *testing.T) {
	t.Run("arrays: lower first, then higher", func(t *testing.T) {
		lower := []interface{}{1, 2}
		higher := []interface{}{3, 4}
		result := mergePrepend(lower, higher)
		assert.Equal(t, []interface{}{1, 2, 3, 4}, result)
	})

	t.Run("objects: shallow merge with lower winning", func(t *testing.T) {
		lower := map[string]interface{}{
			"a": "lower_a",
			"b": "lower_b",
		}
		higher := map[string]interface{}{
			"a": "higher_a",
			"c": "higher_c",
		}
		result := mergePrepend(lower, higher).(map[string]interface{})
		assert.Equal(t, "lower_a", result["a"]) // lower wins
		assert.Equal(t, "lower_b", result["b"])
		assert.Equal(t, "higher_c", result["c"])
	})

	t.Run("scalars: lower wins", func(t *testing.T) {
		result := mergePrepend("lower", "higher")
		assert.Equal(t, "lower", result)
	})
}

func TestMergeUnion(t *testing.T) {
	t.Run("arrays: deduplicates with higher priority", func(t *testing.T) {
		lower := []interface{}{"a", "b", "c"}
		higher := []interface{}{"b", "c", "d"}
		result := mergeUnion(lower, higher).([]interface{})
		// Higher elements first, then unique lower elements
		assert.Equal(t, 4, len(result))
		assert.Contains(t, result, "a")
		assert.Contains(t, result, "b")
		assert.Contains(t, result, "c")
		assert.Contains(t, result, "d")
	})

	t.Run("arrays with numbers", func(t *testing.T) {
		lower := []interface{}{1.0, 2.0, 3.0}
		higher := []interface{}{2.0, 3.0, 4.0}
		result := mergeUnion(lower, higher).([]interface{})
		assert.Equal(t, 4, len(result))
	})

	t.Run("objects: deep merge (same as deep)", func(t *testing.T) {
		lower := map[string]interface{}{
			"a": "lower_a",
			"b": "lower_b",
		}
		higher := map[string]interface{}{
			"a": "higher_a",
			"c": "higher_c",
		}
		result := mergeUnion(lower, higher).(map[string]interface{})
		assert.Equal(t, "higher_a", result["a"])
		assert.Equal(t, "lower_b", result["b"])
		assert.Equal(t, "higher_c", result["c"])
	})

	t.Run("scalars: higher wins", func(t *testing.T) {
		result := mergeUnion("lower", "higher")
		assert.Equal(t, "higher", result)
	})
}

func TestMergeValuesTypeMismatch(t *testing.T) {
	t.Run("type mismatch: higher always wins", func(t *testing.T) {
		// Array vs scalar
		result := mergeValues([]interface{}{1, 2}, "higher", model.MergeDeep)
		assert.Equal(t, "higher", result)

		// Object vs array
		result = mergeValues(map[string]interface{}{"a": 1}, []interface{}{1}, model.MergeDeep)
		assert.Equal(t, []interface{}{1}, result)

		// Scalar vs object
		result = mergeValues("lower", map[string]interface{}{"a": 1}, model.MergeDeep)
		assert.Equal(t, map[string]interface{}{"a": 1}, result)
	})
}

func TestMergeReplace(t *testing.T) {
	t.Run("replace strategy returns higher only", func(t *testing.T) {
		lower := []interface{}{1, 2}
		higher := []interface{}{3, 4}
		result := mergeValues(lower, higher, model.MergeReplace)
		assert.Equal(t, []interface{}{3, 4}, result)
	})
}

func TestToComparableKey(t *testing.T) {
	t.Run("strings are prefixed with s:", func(t *testing.T) {
		assert.Equal(t, "s:hello", toComparableKey("hello"))
	})

	t.Run("numbers are prefixed with n:", func(t *testing.T) {
		assert.Equal(t, "n:42", toComparableKey(42.0))
	})

	t.Run("booleans are prefixed with b:", func(t *testing.T) {
		assert.Equal(t, "b:true", toComparableKey(true))
		assert.Equal(t, "b:false", toComparableKey(false))
	})

	t.Run("nil returns null", func(t *testing.T) {
		assert.Equal(t, "null", toComparableKey(nil))
	})

	t.Run("complex values are JSON serialized", func(t *testing.T) {
		result := toComparableKey(map[string]interface{}{"a": 1})
		assert.Contains(t, result, "j:")
	})
}

func TestMergeRichAnnotationsWithStrategies(t *testing.T) {
	t.Run("replace strategy in higher overrides deep merge", func(t *testing.T) {
		lower := model.RichAnnotations{
			"tags": {Value: []interface{}{"a", "b"}, MergeStrategy: ""},
		}
		higher := model.RichAnnotations{
			"tags": {Value: []interface{}{"c", "d"}, MergeStrategy: model.MergeReplace},
		}
		result := mergeRichAnnotations(lower, higher, model.MergeDeep)
		assert.Equal(t, []interface{}{"c", "d"}, result["tags"].Value)
	})

	t.Run("append strategy in lower is used when higher has no strategy", func(t *testing.T) {
		lower := model.RichAnnotations{
			"tags": {Value: []interface{}{"a", "b"}, MergeStrategy: model.MergeAppend},
		}
		higher := model.RichAnnotations{
			"tags": {Value: []interface{}{"c", "d"}, MergeStrategy: ""},
		}
		result := mergeRichAnnotations(lower, higher, model.MergeDeep)
		// With append: higher first, then lower
		assert.Equal(t, []interface{}{"c", "d", "a", "b"}, result["tags"].Value)
	})

	t.Run("prepend strategy puts lower elements first", func(t *testing.T) {
		lower := model.RichAnnotations{
			"tags": {Value: []interface{}{"a", "b"}, MergeStrategy: ""},
		}
		higher := model.RichAnnotations{
			"tags": {Value: []interface{}{"c", "d"}, MergeStrategy: model.MergePrepend},
		}
		result := mergeRichAnnotations(lower, higher, model.MergeDeep)
		// With prepend: lower first, then higher
		assert.Equal(t, []interface{}{"a", "b", "c", "d"}, result["tags"].Value)
	})

	t.Run("union strategy deduplicates", func(t *testing.T) {
		lower := model.RichAnnotations{
			"tags": {Value: []interface{}{"a", "b", "c"}, MergeStrategy: ""},
		}
		higher := model.RichAnnotations{
			"tags": {Value: []interface{}{"b", "c", "d"}, MergeStrategy: model.MergeUnion},
		}
		result := mergeRichAnnotations(lower, higher, model.MergeDeep)
		// Union should deduplicate
		tags := result["tags"].Value.([]interface{})
		assert.Equal(t, 4, len(tags))
	})
}

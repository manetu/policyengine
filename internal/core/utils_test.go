//
//  Copyright © Manetu Inc. All rights reserved.
//

package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected []string
	}{
		{
			name:     "nil input returns empty slice",
			input:    nil,
			expected: []string{},
		},
		{
			name:     "[]any with strings extracts correctly",
			input:    []any{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "[]any with mixed types skips non-strings",
			input:    []any{"a", 123, "b", true, "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "[]any empty returns empty slice",
			input:    []any{},
			expected: []string{},
		},
		{
			name:     "[]string returns as-is",
			input:    []string{"x", "y", "z"},
			expected: []string{"x", "y", "z"},
		},
		{
			name:     "[]string empty returns empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "unsupported type (int) returns empty slice",
			input:    42,
			expected: []string{},
		},
		{
			name:     "unsupported type (string) returns empty slice",
			input:    "not a slice",
			expected: []string{},
		},
		{
			name:     "unsupported type (map) returns empty slice",
			input:    map[string]string{"key": "value"},
			expected: []string{},
		},
		{
			name:     "[]any with only non-strings returns empty slice",
			input:    []any{1, 2, 3},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toStringSlice(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

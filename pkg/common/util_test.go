//
//  Copyright © Manetu Inc. All rights reserved.
//

package common

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrettyPrint(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		contains string
	}{
		{
			name:     "simple map",
			input:    map[string]interface{}{"key": "value", "number": 42},
			contains: `"key": "value"`,
		},
		{
			name:     "nested structure",
			input:    map[string]interface{}{"outer": map[string]interface{}{"inner": "data"}},
			contains: `"inner": "data"`,
		},
		{
			name:     "array",
			input:    []string{"item1", "item2", "item3"},
			contains: "item1",
		},
		{
			name:     "nil input",
			input:    nil,
			contains: "null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			PrettyPrint(tt.input)

			_ = w.Close()
			os.Stdout = oldStdout

			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			output := buf.String()

			assert.Contains(t, output, tt.contains)
		})
	}
}

func TestPrettyPrintWithUnmarshalableData(t *testing.T) {
	// Channels cannot be marshaled to JSON
	input := map[string]interface{}{
		"channel": make(chan int),
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	PrettyPrint(input)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Should print error when marshaling fails
	assert.Contains(t, output, "json: unsupported type")
}

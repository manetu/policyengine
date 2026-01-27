//
//  Copyright © Manetu Inc. All rights reserved.
//

package accesslog

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestIoWriterFactory(t *testing.T) {
	log := NewStdoutFactory()
	assert.NotNil(t, log)
	assert.IsType(t, &IoWriterFactory{}, log)
}

func TestIoWriterAccessLog(t *testing.T) {
	buf := &bytes.Buffer{}
	log := newStream(buf, AccessLogOptions{})
	assert.NotNil(t, log)
	assert.IsType(t, &IoWriterStream{}, log)
}

func TestStdoutAccessLog_Send(t *testing.T) {
	tests := []struct {
		name    string
		record  *events.AccessRecord
		wantErr bool
	}{
		{
			name: "valid access record",
			record: &events.AccessRecord{
				Principal: &events.AccessRecord_Principal{
					Subject: "user123",
				},
				Operation: "read",
				Resource:  "resource456",
			},
			wantErr: false,
		},
		{
			name:    "empty access record",
			record:  &events.AccessRecord{},
			wantErr: false,
		},
		{
			name: "access record with multiple fields",
			record: &events.AccessRecord{
				Principal: &events.AccessRecord_Principal{
					Subject: "admin",
					Realm:   "test-realm",
				},
				Operation: "write",
				Resource:  "database",
				Decision:  events.AccessRecord_GRANT,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			log := newStream(buf, AccessLogOptions{})

			err := log.Send(tt.record)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify the output is valid JSON
				var decoded events.AccessRecord
				err = protojson.Unmarshal(buf.Bytes(), &decoded)
				require.NoError(t, err)

				// Verify fields match
				assert.Equal(t, tt.record.Operation, decoded.Operation)
				assert.Equal(t, tt.record.Resource, decoded.Resource)
				assert.Equal(t, tt.record.Decision, decoded.Decision)
			}
		})
	}
}

func TestStdoutAccessLog_Send_JSONMarshaling(t *testing.T) {
	buf := &bytes.Buffer{}
	log := newStream(buf, AccessLogOptions{})

	record := &events.AccessRecord{
		Principal: &events.AccessRecord_Principal{
			Subject: "test-subject",
		},
		Operation: "test-operation",
		Resource:  "test-resource",
		Decision:  events.AccessRecord_GRANT,
	}

	err := log.Send(record)
	require.NoError(t, err)

	// Verify output contains expected JSON
	output := buf.String()
	assert.Contains(t, output, `"subject":"test-subject"`)
	assert.Contains(t, output, `"operation":"test-operation"`)
	assert.Contains(t, output, `"resource":"test-resource"`)
	assert.Contains(t, output, `"decision":"GRANT"`)
	assert.Contains(t, output, "\n") // Verify newline is added
}

func TestStdoutAccessLog_Close(t *testing.T) {
	buf := &bytes.Buffer{}
	log := newStream(buf, AccessLogOptions{})

	// Close should not panic and should be a no-op
	assert.NotPanics(t, func() {
		log.Close()
	})

	// Verify we can still write after Close (since it's a no-op)
	record := &events.AccessRecord{
		Principal: &events.AccessRecord_Principal{Subject: "test"},
	}
	err := log.Send(record)
	assert.NoError(t, err)
}

func TestStdoutAccessLog_MultipleWrites(t *testing.T) {
	buf := &bytes.Buffer{}
	log := newStream(buf, AccessLogOptions{})

	records := []*events.AccessRecord{
		{
			Principal: &events.AccessRecord_Principal{Subject: "user1"},
			Operation: "read",
			Resource:  "file1",
		},
		{
			Principal: &events.AccessRecord_Principal{Subject: "user2"},
			Operation: "write",
			Resource:  "file2",
		},
		{
			Principal: &events.AccessRecord_Principal{Subject: "user3"},
			Operation: "delete",
			Resource:  "file3",
		},
	}

	for _, record := range records {
		err := log.Send(record)
		require.NoError(t, err)
	}

	// Verify all records were written
	output := buf.String()
	assert.Contains(t, output, "user1")
	assert.Contains(t, output, "user2")
	assert.Contains(t, output, "user3")

	// Verify we have 3 lines
	lines := bytes.Count(buf.Bytes(), []byte("\n"))
	assert.Equal(t, 3, lines)
}

// Tests for NullFactory and NullStream

func TestNullFactory(t *testing.T) {
	factory := NewNullFactory()
	assert.NotNil(t, factory)
	assert.IsType(t, &NullFactory{}, factory)
}

func TestNullFactory_NewStream(t *testing.T) {
	factory := NewNullFactory()
	stream, err := factory.NewStream()

	require.NoError(t, err)
	assert.NotNil(t, stream)
	assert.IsType(t, &NullStream{}, stream)
}

func TestNullStream_Send(t *testing.T) {
	factory := NewNullFactory()
	stream, _ := factory.NewStream()

	record := &events.AccessRecord{
		Principal: &events.AccessRecord_Principal{Subject: "test-user"},
		Operation: "read",
		Resource:  "test-resource",
		Decision:  events.AccessRecord_GRANT,
	}

	err := stream.Send(record)
	assert.NoError(t, err)
}

func TestNullStream_Send_MultipleTimes(t *testing.T) {
	factory := NewNullFactory()
	stream, _ := factory.NewStream()

	for i := 0; i < 100; i++ {
		record := &events.AccessRecord{
			Principal: &events.AccessRecord_Principal{Subject: "user"},
			Operation: "read",
			Resource:  "resource",
		}
		err := stream.Send(record)
		assert.NoError(t, err)
	}
}

func TestNullStream_Close(t *testing.T) {
	factory := NewNullFactory()
	stream, _ := factory.NewStream()

	// Close should not panic
	assert.NotPanics(t, func() {
		stream.Close()
	})

	// Should be able to call Close multiple times without issue
	stream.Close()
	stream.Close()
}

func TestNullStream_Send_NilRecord(t *testing.T) {
	factory := NewNullFactory()
	stream, _ := factory.NewStream()

	// Should handle nil record gracefully
	err := stream.Send(nil)
	assert.NoError(t, err)
}

// Tests for IoWriterFactory.NewStream

func TestIoWriterFactory_NewStream(t *testing.T) {
	buf := &bytes.Buffer{}
	factory := NewIoWriterFactory(buf)

	stream, err := factory.NewStream()
	require.NoError(t, err)
	assert.NotNil(t, stream)
	assert.IsType(t, &IoWriterStream{}, stream)
}

func TestNewIoWriterFactory(t *testing.T) {
	buf := &bytes.Buffer{}
	factory := NewIoWriterFactory(buf)

	assert.NotNil(t, factory)
	assert.IsType(t, &IoWriterFactory{}, factory)
}

func TestIoWriterStream_ViaFactory(t *testing.T) {
	buf := &bytes.Buffer{}
	factory := NewIoWriterFactory(buf)

	stream, err := factory.NewStream()
	require.NoError(t, err)

	record := &events.AccessRecord{
		Principal: &events.AccessRecord_Principal{Subject: "test-user"},
		Operation: "write",
		Resource:  "test-resource",
		Decision:  events.AccessRecord_DENY,
	}

	err = stream.Send(record)
	require.NoError(t, err)

	// Verify output
	output := buf.String()
	assert.Contains(t, output, "test-user")
	assert.Contains(t, output, "write")
	assert.Contains(t, output, "test-resource")
	assert.Contains(t, output, "DENY")
}

// Tests for PORC field expansion

func TestIoWriterStream_PorcExpansion(t *testing.T) {
	buf := &bytes.Buffer{}
	log := newStream(buf, AccessLogOptions{})

	// Create a record with a JSON-encoded porc string
	porcJSON := `{"principal":{"subject":"alice"},"operation":"read","resource":"doc1"}`
	record := &events.AccessRecord{
		Principal: &events.AccessRecord_Principal{Subject: "alice"},
		Operation: "read",
		Resource:  "doc1",
		Decision:  events.AccessRecord_GRANT,
		Porc:      porcJSON,
	}

	err := log.Send(record)
	require.NoError(t, err)

	output := buf.String()

	// Parse the output JSON to verify porc is expanded
	var data map[string]interface{}
	err = json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	// Verify porc is now an object, not a string
	porc, ok := data["porc"].(map[string]interface{})
	require.True(t, ok, "porc should be an object, got %T", data["porc"])

	// Verify the porc contents
	principal, ok := porc["principal"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "alice", principal["subject"])
	assert.Equal(t, "read", porc["operation"])
	assert.Equal(t, "doc1", porc["resource"])
}

func TestIoWriterStream_PorcExpansion_InvalidJSON(t *testing.T) {
	buf := &bytes.Buffer{}
	log := newStream(buf, AccessLogOptions{})

	// Create a record with an invalid JSON string in porc
	record := &events.AccessRecord{
		Principal: &events.AccessRecord_Principal{Subject: "alice"},
		Operation: "read",
		Resource:  "doc1",
		Decision:  events.AccessRecord_GRANT,
		Porc:      "not-valid-json",
	}

	err := log.Send(record)
	require.NoError(t, err)

	output := buf.String()

	// Parse the output JSON
	var data map[string]interface{}
	err = json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	// Verify porc remains as a string since it couldn't be parsed
	porc, ok := data["porc"].(string)
	require.True(t, ok, "porc should remain a string when JSON is invalid, got %T", data["porc"])
	assert.Equal(t, "not-valid-json", porc)
}

func TestIoWriterStream_PorcExpansion_EmptyPorc(t *testing.T) {
	buf := &bytes.Buffer{}
	log := newStream(buf, AccessLogOptions{})

	// Create a record without porc field
	record := &events.AccessRecord{
		Principal: &events.AccessRecord_Principal{Subject: "alice"},
		Operation: "read",
		Resource:  "doc1",
		Decision:  events.AccessRecord_GRANT,
	}

	err := log.Send(record)
	require.NoError(t, err)

	output := buf.String()

	// Parse the output JSON
	var data map[string]interface{}
	err = json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	// Verify porc is not present (empty string is omitted)
	_, exists := data["porc"]
	assert.False(t, exists, "empty porc should be omitted")
}

// Tests for PrettyPrint option

func TestIoWriterStream_PrettyPrint(t *testing.T) {
	buf := &bytes.Buffer{}
	log := newStream(buf, AccessLogOptions{PrettyPrint: true})

	record := &events.AccessRecord{
		Principal: &events.AccessRecord_Principal{Subject: "alice"},
		Operation: "read",
		Resource:  "doc1",
		Decision:  events.AccessRecord_GRANT,
	}

	err := log.Send(record)
	require.NoError(t, err)

	output := buf.String()

	// Verify output contains indentation (newlines and spaces)
	assert.True(t, strings.Contains(output, "\n  "), "pretty print should contain indented newlines")

	// Verify it's still valid JSON
	var data map[string]interface{}
	err = json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	// Verify fields
	assert.Equal(t, "read", data["operation"])
	assert.Equal(t, "doc1", data["resource"])
}

func TestIoWriterStream_CompactOutput(t *testing.T) {
	buf := &bytes.Buffer{}
	log := newStream(buf, AccessLogOptions{PrettyPrint: false})

	record := &events.AccessRecord{
		Principal: &events.AccessRecord_Principal{Subject: "alice"},
		Operation: "read",
		Resource:  "doc1",
		Decision:  events.AccessRecord_GRANT,
	}

	err := log.Send(record)
	require.NoError(t, err)

	output := buf.String()

	// Trim trailing newline for line counting
	trimmed := strings.TrimSuffix(output, "\n")

	// Verify output is single line (no newlines in the JSON itself)
	assert.False(t, strings.Contains(trimmed, "\n"), "compact output should be single line")

	// Verify it's still valid JSON
	var data map[string]interface{}
	err = json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)
}

func TestIoWriterStream_PrettyPrintWithPorc(t *testing.T) {
	buf := &bytes.Buffer{}
	log := newStream(buf, AccessLogOptions{PrettyPrint: true})

	porcJSON := `{"principal":{"subject":"alice"},"operation":"read","resource":"doc1"}`
	record := &events.AccessRecord{
		Principal: &events.AccessRecord_Principal{Subject: "alice"},
		Operation: "read",
		Resource:  "doc1",
		Decision:  events.AccessRecord_GRANT,
		Porc:      porcJSON,
	}

	err := log.Send(record)
	require.NoError(t, err)

	output := buf.String()

	// Verify output is pretty printed
	assert.True(t, strings.Contains(output, "\n  "), "pretty print should contain indented newlines")

	// Parse and verify porc is expanded
	var data map[string]interface{}
	err = json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	porc, ok := data["porc"].(map[string]interface{})
	require.True(t, ok, "porc should be an expanded object")
	assert.Equal(t, "read", porc["operation"])
}

func TestNewIoWriterFactoryWithOptions(t *testing.T) {
	buf := &bytes.Buffer{}
	opts := AccessLogOptions{PrettyPrint: true}
	factory := NewIoWriterFactoryWithOptions(buf, opts)

	assert.NotNil(t, factory)
	assert.IsType(t, &IoWriterFactory{}, factory)

	// Verify options are passed through
	ioFactory := factory.(*IoWriterFactory)
	assert.True(t, ioFactory.options.PrettyPrint)
}

func TestNewIoWriterFactoryWithOptions_StreamInheritsOptions(t *testing.T) {
	buf := &bytes.Buffer{}
	opts := AccessLogOptions{PrettyPrint: true}
	factory := NewIoWriterFactoryWithOptions(buf, opts)

	stream, err := factory.NewStream()
	require.NoError(t, err)

	// Send a record and verify it's pretty printed
	record := &events.AccessRecord{
		Principal: &events.AccessRecord_Principal{Subject: "test"},
		Operation: "read",
		Resource:  "resource",
	}

	err = stream.Send(record)
	require.NoError(t, err)

	output := buf.String()
	assert.True(t, strings.Contains(output, "\n  "), "stream should inherit pretty print option")
}

//
//  Copyright © Manetu Inc. All rights reserved.
//

package accesslog

import (
	"bytes"
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
	log := newStream(buf)
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
			log := newStream(buf)

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
	log := newStream(buf)

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
	log := newStream(buf)

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
	log := newStream(buf)

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

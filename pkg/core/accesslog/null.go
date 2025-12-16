package accesslog

import (
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

// NullFactory is a factory for NullStream.
type NullFactory struct {
}

// NullStream implements the Stream interface but drops all writes to the floor.  It is useful to downstream implementations
// when they want to support disabling access logging as a configuration option, such as for testing.
type NullStream struct {
}

// NewNullFactory creates a new NullStream that writes to the specified writer.
func NewNullFactory() Factory {
	return &NullFactory{}
}

// NewStream creates a new NullStream to satisfy the Factory interface.
func (f *NullFactory) NewStream() (Stream, error) {
	return &NullStream{}, nil
}

// Send drops the access record on the floor
func (s *NullStream) Send(record *events.AccessRecord) error {
	return nil
}

// Close is a no-op for NullStream
func (s *NullStream) Close() {}

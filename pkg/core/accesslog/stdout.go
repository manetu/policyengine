package accesslog

import (
	"fmt"
	"io"
	"os"

	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// IoWriterFactory is a factory for IoWriterStream.
type IoWriterFactory struct {
	writer io.Writer
}

// IoWriterStream implements the Stream interface by writing access records to stdout.
type IoWriterStream struct {
	writer io.Writer
	codec  protojson.MarshalOptions
}

// NewStdoutFactory creates a new IoWriterStream that writes to os.Stdout.
func NewStdoutFactory() Factory {
	return NewIoWriterFactory(os.Stdout)
}

// NewIoWriterFactory creates a new IoWriterStream that writes to the specified writer.
func NewIoWriterFactory(w io.Writer) Factory {
	return &IoWriterFactory{
		writer: w,
	}
}

// NewStream creates a new IoWriterStream to satisfy the Factory interface.
func (f *IoWriterFactory) NewStream() (Stream, error) {
	return newStream(f.writer), nil
}

func newStream(w io.Writer) Stream {
	return &IoWriterStream{
		writer: w,
		codec: protojson.MarshalOptions{
			Multiline: false,
		},
	}
}

// Send marshals the access record to JSON and writes it to the configured writer.
func (s *IoWriterStream) Send(record *events.AccessRecord) error {
	_, _ = fmt.Fprintln(s.writer, s.codec.Format(record))
	return nil
}

// Close is a no-op for IoWriterStream as stdout doesn't need to be closed.
func (s *IoWriterStream) Close() {}

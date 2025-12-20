//
//  Copyright © Manetu Inc. All rights reserved.
//

package accesslog

import (
	"fmt"
	"io"
	"os"

	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// IoWriterFactory creates [Stream] instances that write to an [io.Writer].
//
// Use [NewStdoutFactory] to create a factory for stdout, or [NewIoWriterFactory]
// for a custom writer.
type IoWriterFactory struct {
	writer io.Writer
}

// IoWriterStream writes access records as JSON to an [io.Writer].
//
// Each record is written as a single line of JSON followed by a newline.
// This format is suitable for log aggregation systems and command-line tools.
//
// IoWriterStream is safe for concurrent use; writes are atomic at the line level.
type IoWriterStream struct {
	writer io.Writer
	codec  protojson.MarshalOptions
}

// NewStdoutFactory creates a [Factory] that writes access records to stdout.
//
// This is the default factory used by the policy engine if no access log
// is explicitly configured. It's suitable for development and debugging,
// or for production environments where stdout is captured by a log aggregator.
//
// Example:
//
//	pe, _ := core.NewPolicyEngine(
//	    options.WithAccessLog(accesslog.NewStdoutFactory()),
//	)
func NewStdoutFactory() Factory {
	return NewIoWriterFactory(os.Stdout)
}

// NewIoWriterFactory creates a [Factory] that writes access records to the
// specified [io.Writer].
//
// This is useful for writing to files, buffers, or other destinations:
//
//	file, _ := os.Create("access.log")
//	factory := accesslog.NewIoWriterFactory(file)
//	pe, _ := core.NewPolicyEngine(options.WithAccessLog(factory))
func NewIoWriterFactory(w io.Writer) Factory {
	return &IoWriterFactory{
		writer: w,
	}
}

// NewStream creates a new [IoWriterStream] that writes to the configured writer.
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
//
// The record is written as a single line of compact JSON followed by a newline.
// Write errors are silently ignored as stdout writes rarely fail, and the
// policy engine should not fail authorization decisions due to logging issues.
func (s *IoWriterStream) Send(record *events.AccessRecord) error {
	_, _ = fmt.Fprintln(s.writer, s.codec.Format(record))
	return nil
}

// Close is a no-op for IoWriterStream.
//
// The underlying writer is not closed by this method; the caller is responsible
// for closing the writer if needed (except for stdout, which should not be closed).
func (s *IoWriterStream) Close() {}

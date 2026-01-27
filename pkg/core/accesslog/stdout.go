//
//  Copyright © Manetu Inc. All rights reserved.
//

package accesslog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// AccessLogOptions configures the behavior of access log output.
type AccessLogOptions struct {
	// PrettyPrint enables indented multi-line JSON output.
	// When false (default), output is compact single-line JSON.
	PrettyPrint bool
}

// IoWriterFactory creates [Stream] instances that write to an [io.Writer].
//
// Use [NewStdoutFactory] to create a factory for stdout, or [NewIoWriterFactory]
// for a custom writer.
type IoWriterFactory struct {
	writer  io.Writer
	options AccessLogOptions
}

// IoWriterStream writes access records as JSON to an [io.Writer].
//
// Each record is written as a single line of JSON followed by a newline.
// This format is suitable for log aggregation systems and command-line tools.
//
// IoWriterStream is safe for concurrent use; writes are atomic at the line level.
type IoWriterStream struct {
	writer  io.Writer
	codec   protojson.MarshalOptions
	options AccessLogOptions
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
	return NewIoWriterFactoryWithOptions(w, AccessLogOptions{})
}

// NewIoWriterFactoryWithOptions creates a [Factory] that writes access records to the
// specified [io.Writer] with the given options.
//
// Use this when you need to customize output formatting:
//
//	factory := accesslog.NewIoWriterFactoryWithOptions(os.Stdout, accesslog.AccessLogOptions{
//	    PrettyPrint: true,
//	})
//	pe, _ := core.NewPolicyEngine(options.WithAccessLog(factory))
func NewIoWriterFactoryWithOptions(w io.Writer, opts AccessLogOptions) Factory {
	return &IoWriterFactory{
		writer:  w,
		options: opts,
	}
}

// NewStream creates a new [IoWriterStream] that writes to the configured writer.
func (f *IoWriterFactory) NewStream() (Stream, error) {
	return newStream(f.writer, f.options), nil
}

func newStream(w io.Writer, opts AccessLogOptions) Stream {
	return &IoWriterStream{
		writer: w,
		codec: protojson.MarshalOptions{
			Multiline: false,
		},
		options: opts,
	}
}

// Send marshals the access record to JSON and writes it to the configured writer.
//
// The record is written as JSON followed by a newline. The porc field, if present,
// is decoded from its JSON string representation into a proper JSON object for
// improved readability. Output format is controlled by AccessLogOptions:
// - PrettyPrint=false (default): compact single-line JSON
// - PrettyPrint=true: indented multi-line JSON
//
// Write errors are silently ignored as stdout writes rarely fail, and the
// policy engine should not fail authorization decisions due to logging issues.
func (s *IoWriterStream) Send(record *events.AccessRecord) error {
	// Marshal protobuf to JSON bytes
	jsonBytes, err := s.codec.Marshal(record)
	if err != nil {
		return err
	}

	// Unmarshal to generic map so we can manipulate the porc field
	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		// Fall back to original output if we can't parse
		_, _ = fmt.Fprintln(s.writer, string(jsonBytes))
		return nil
	}

	// Expand porc field from JSON string to object if present
	if porcStr, ok := data["porc"].(string); ok {
		var porcData interface{}
		if err := json.Unmarshal([]byte(porcStr), &porcData); err == nil {
			data["porc"] = porcData
		}
	}

	// Re-encode with appropriate formatting
	var output []byte
	if s.options.PrettyPrint {
		output, err = json.MarshalIndent(data, "", "  ")
	} else {
		output, err = json.Marshal(data)
	}
	if err != nil {
		// Fall back to original output if re-encoding fails
		_, _ = fmt.Fprintln(s.writer, string(jsonBytes))
		return nil
	}

	_, _ = fmt.Fprintln(s.writer, string(output))
	return nil
}

// Close is a no-op for IoWriterStream.
//
// The underlying writer is not closed by this method; the caller is responsible
// for closing the writer if needed (except for stdout, which should not be closed).
func (s *IoWriterStream) Close() {}

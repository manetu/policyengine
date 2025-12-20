//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package accesslog provides interfaces and implementations for audit logging
// of authorization decisions.
//
// Access logs record every authorization decision made by the policy engine,
// creating an audit trail for compliance, debugging, and security monitoring.
// Each record includes the PORC input, the decision outcome, timing information,
// and details about which policies were evaluated.
//
// # Built-in Implementations
//
// The package provides several stream implementations:
//   - [NewStdoutFactory]: Writes JSON records to stdout (default for development)
//   - [NewIoWriterFactory]: Writes JSON records to any io.Writer
//   - [NewNullFactory]: Discards all records (useful for testing or benchmarks)
//
// # Custom Implementations
//
// To implement a custom access log (e.g., for Kafka, database, or cloud logging):
//
//  1. Implement the [Factory] interface to create stream instances
//  2. Implement the [Stream] interface to handle record delivery
//  3. Use [options.WithAccessLog] when creating the policy engine
//
// Example:
//
//	type KafkaFactory struct { brokers []string }
//
//	func (f *KafkaFactory) NewStream() (accesslog.Stream, error) {
//	    producer, err := kafka.NewProducer(f.brokers)
//	    if err != nil {
//	        return nil, err
//	    }
//	    return &KafkaStream{producer: producer}, nil
//	}
//
// # Record Format
//
// Access records are Protocol Buffer messages defined in the events package.
// See [events.AccessRecord] for the complete record structure.
package accesslog

import (
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

// Factory creates access log [Stream] instances.
//
// The factory pattern enables deferred initialization of streaming resources.
// Early initialization (setting Viper defaults, validating configuration) should
// happen during factory construction. Late initialization (opening connections,
// allocating buffers) should happen in [NewStream].
//
// The policy engine framework guarantees that configuration is fully loaded
// before [NewStream] is called.
type Factory interface {
	// NewStream creates a new access log stream.
	//
	// The returned stream should be ready to receive records via [Stream.Send].
	// Returns an error if the stream cannot be initialized (e.g., connection failure).
	NewStream() (Stream, error)
}

// Stream is the interface for sending access records to an audit destination.
//
// Implementations must be safe for concurrent use by multiple goroutines.
// The policy engine may call [Send] from multiple goroutines simultaneously.
//
// Implementations should handle backpressure appropriately. If the destination
// cannot accept records fast enough, implementations may buffer, drop, or block
// depending on their requirements.
type Stream interface {
	// Send delivers an access record to the audit destination.
	//
	// Send should not modify the record. The caller retains ownership of the
	// record and may reuse it after Send returns.
	//
	// Returns an error if the record cannot be delivered. The policy engine
	// logs send errors but does not retry; implementations should handle
	// retries internally if needed.
	Send(record *events.AccessRecord) error

	// Close releases any resources held by the stream.
	//
	// Close should flush any buffered records before returning. After Close
	// is called, the stream should not be used again.
	Close()
}

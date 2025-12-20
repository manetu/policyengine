//
//  Copyright © Manetu Inc. All rights reserved.
//

package accesslog

import (
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

// NullFactory creates [NullStream] instances that discard all records.
type NullFactory struct {
}

// NullStream is an access log stream that discards all records.
//
// NullStream is useful for:
//   - Testing: When you don't need access log output in tests
//   - Benchmarking: To measure authorization performance without I/O overhead
//   - Conditional logging: When you want to disable logging based on configuration
//
// Example:
//
//	pe, _ := core.NewPolicyEngine(
//	    options.WithAccessLog(accesslog.NewNullFactory()),
//	)
type NullStream struct {
}

// NewNullFactory creates a [Factory] that produces streams discarding all records.
//
// Use this when you want to completely disable access logging:
//
//	factory := accesslog.NewNullFactory()
//	pe, _ := core.NewPolicyEngine(options.WithAccessLog(factory))
func NewNullFactory() Factory {
	return &NullFactory{}
}

// NewStream creates a new [NullStream].
func (f *NullFactory) NewStream() (Stream, error) {
	return &NullStream{}, nil
}

// Send discards the access record without taking any action.
//
// This method always returns nil.
func (s *NullStream) Send(record *events.AccessRecord) error {
	return nil
}

// Close is a no-op for NullStream as there are no resources to release.
func (s *NullStream) Close() {}

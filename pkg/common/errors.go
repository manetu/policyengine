//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package common provides shared types and utilities used across the
// policy engine packages.
//
// # Error Handling
//
// The [PolicyError] type provides structured error information for
// authorization failures, including reason codes suitable for access
// log records.
package common

import (
	"fmt"

	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

// PolicyError represents an error encountered during policy evaluation.
//
// PolicyError provides structured error information that can be included
// in access log records for audit purposes. It includes both a machine-readable
// reason code and a human-readable message.
//
// PolicyError is returned by backend methods and policy evaluation functions
// instead of the standard error interface to ensure audit trail completeness.
type PolicyError struct {
	// ReasonCode is the machine-readable error classification for access logs.
	ReasonCode events.AccessRecord_BundleReference_ReasonCode
	// Reason is a human-readable description of the error.
	Reason string
}

// Error implements the error interface, returning a formatted string
// containing both the reason message and the reason code.
func (e *PolicyError) Error() string {
	return fmt.Sprintf("%s(code-%s)", e.Reason, e.ReasonCode)
}

// NewError creates a new [PolicyError] with the specified reason code and message.
//
// Common reason codes include:
//   - NOTFOUND_ERROR: Entity not found in backend
//   - EVALUATION_ERROR: Policy evaluation failed
//   - COMPILATION_ERROR: Policy compilation failed
//   - UNKNOWN_ERROR: Unexpected error condition
func NewError(code events.AccessRecord_BundleReference_ReasonCode, msg string) *PolicyError {
	return &PolicyError{ReasonCode: code, Reason: msg}
}

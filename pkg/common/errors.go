//
//  Copyright © Manetu Inc. All rights reserved.
//

package common

import (
	"fmt"

	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

// PolicyError encountered while processing Authorization and propagated in the accesslog event
type PolicyError struct {
	ReasonCode events.AccessRecord_BundleReference_ReasonCode
	Reason     string
}

// Error returns a string representation of the PolicyError.
func (e *PolicyError) Error() string {
	return fmt.Sprintf("%s(code-%s)", e.Reason, e.ReasonCode)
}

// NewError creates a new PolicyError with the specified reason code and message.
func NewError(code events.AccessRecord_BundleReference_ReasonCode, msg string) *PolicyError {
	return &PolicyError{ReasonCode: code, Reason: msg}
}

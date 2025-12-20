//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package types defines the core data types used for policy engine authorization
// requests, particularly the PORC (Principal, Operation, Resource, Context) structure.
//
// PORC is the standard input format for authorization decisions. It encapsulates:
//   - Principal: The identity making the request (user, service, etc.)
//   - Operation: The action being performed (read, write, delete, etc.)
//   - Resource: The target of the operation (document, record, etc.)
//   - Context: Additional contextual information (time, location, etc.)
//
// # Usage
//
// The [AnyPORC] type provides flexibility in how PORC data is provided:
//
//	// As a JSON string (convenient for HTTP handlers)
//	porc := `{"principal": {...}, "operation": {...}, "resource": {...}, "context": {}}`
//
//	// As a pre-parsed map (efficient for programmatic use)
//	porc := map[string]interface{}{
//	    "principal": map[string]interface{}{"roles": []string{"admin"}},
//	    "operation": map[string]interface{}{"id": "mrn:example:operation:read"},
//	    "resource":  map[string]interface{}{"id": "mrn:example:resource:doc/1"},
//	    "context":   map[string]interface{}{},
//	}
package types

import (
	"encoding/json"
	"errors"
)

// AnyPORC is a flexible type that accepts PORC data in multiple formats.
//
// AnyPORC allows authorization requests to be submitted as either:
//   - A JSON string containing the PORC structure (convenient for HTTP handlers)
//   - A map[string]interface{} with pre-parsed PORC data (efficient for programmatic use)
//
// This flexibility allows callers to choose between convenience (JSON strings)
// and efficiency (pre-parsed maps) based on their use case. When a JSON string
// is provided, it will be parsed once by [UnmarshalPORC]. When a map is provided,
// it passes through without additional parsing overhead.
type AnyPORC interface{}

// PORC represents the structured input for authorization decisions.
//
// PORC is an acronym for Principal, Operation, Resource, Context - the four
// components that define an authorization request:
//
//   - principal: Identity information including roles, groups, scopes, and clearance
//   - operation: The action being performed (e.g., "api:documents:read")
//   - resource: The target of the operation, either as an MRN string or descriptor
//   - context: Additional contextual data for policy evaluation
//
// Example PORC structure:
//
//	{
//	    "principal": {
//	        "sub": "alice@example.com",
//	        "mroles": ["mrn:iam:role:editor"],
//	        "mgroups": ["mrn:iam:group:engineering"],
//	        "scopes": ["mrn:iam:scope:full-access"],
//	        "mclearance": "HIGH",
//	        "mannotations": {"department": "engineering"}
//	    },
//	    "operation": "api:documents:update",
//	    "resource": {
//	        "id": "mrn:app:document:12345",
//	        "owner": "alice@example.com",
//	        "group": "mrn:iam:resource-group:docs",
//	        "classification": "MODERATE"
//	    },
//	    "context": {
//	        "timestamp": "2024-01-15T10:30:00Z",
//	        "source_ip": "10.0.1.50"
//	    }
//	}
//
// See the PORC documentation for complete field descriptions.
type PORC map[string]interface{}

// UnmarshalPORC converts an [AnyPORC] value into a [PORC] map.
//
// This function handles the type flexibility of AnyPORC:
//   - If input is a JSON string, it is parsed into a PORC map
//   - If input is already a map[string]interface{}, it is returned as-is
//   - Any other type returns an error
//
// This function is called automatically by [core.PolicyEngine.Authorize] and
// typically does not need to be called directly.
//
// Returns an error if the input is a malformed JSON string or an unsupported type.
func UnmarshalPORC(input AnyPORC) (PORC, error) {

	switch input := input.(type) {
	case string:
		porc := make(PORC)
		// Now unmarshal into the map.
		err := json.Unmarshal([]byte(input), &porc)
		if err != nil {
			return nil, err
		}

		return porc, nil
	case map[string]interface{}:
		return input, nil
	default:
		return nil, errors.New("invalid type")
	}
}

//
//  Copyright © Manetu Inc. All rights reserved.
//
// Package model defines the core data structures shared between the policy engine core and backends

package model

import (
	"github.com/manetu/policyengine/pkg/core/opa"
)

// Annotations is a map structure for storing key-value pairs of annotations, where keys are strings and values based on JSON types
type Annotations map[string]interface{}

// Policy represents a compiled REGO policy and its metadata such as MRN and fingerprint
type Policy struct {
	Mrn         string
	Fingerprint []byte
	Ast         *opa.Ast
}

// PolicyReference represents any object that references a policy, such as Roles, Scopes, Operations, and ResourceGroups
type PolicyReference struct {
	Mrn         string
	Policy      *Policy
	Annotations Annotations
}

// Group represents a collection of roles and associated metadata such as MRN and annotations.
type Group struct {
	Mrn         string
	Roles       []string
	Annotations Annotations
}

// Resource represents any noun that an operation may be applied to.  We supply JSON mappings to support use within PORC encoding/decoding
type Resource struct {
	ID             string      `json:"id,omitempty"`          // Resource MRN
	Owner          string      `json:"owner,omitempty"`       // Identity/group MRN
	Group          string      `json:"group,omitempty"`       // ResourceGroup MRN
	Annotations    Annotations `json:"annotations,omitempty"` // A map of json-based annotations
	Classification string      `json:"classification,omitempty"`
}

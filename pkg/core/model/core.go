//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package model defines the core data structures for policy evaluation.
//
// This package contains the runtime data types used by the policy engine
// and backend implementations. These types represent compiled policies,
// roles, groups, resources, and other policy domain entities at runtime.
//
// # Key Types
//
// Policy evaluation types:
//   - [Policy]: A compiled Rego policy with its AST and metadata
//   - [PolicyReference]: A reference to a policy with annotations (used by roles, scopes, etc.)
//   - [Mapper]: A compiled principal mapper for transforming identity claims
//
// Domain entity types:
//   - [Group]: A collection of roles for batch permission assignment
//   - [Resource]: A target of operations with ownership and classification
//   - [Annotations]: Key-value metadata attached to policy entities
//
// # Relationship to policydomain Package
//
// The [policydomain] package contains the intermediate model parsed from YAML
// configuration files. This package (model) contains the runtime representation
// after policies have been compiled and are ready for evaluation.
package model

import (
	"encoding/json"

	"github.com/manetu/policyengine/pkg/core/opa"
)

// Annotations is a key-value map for storing metadata on policy entities.
//
// Annotations provide a flexible way to attach custom metadata to resources
// and principals. Values can be any JSON-compatible type (strings, numbers,
// booleans, arrays, or nested objects).
//
// Annotations are available during policy evaluation via the PORC input:
//   - Principal annotations: input.principal.mannotations
//   - Resource annotations: input.resource.annotations
//
// Example usage in a policy:
//
//	allow {
//	    input.resource.annotations.department == input.principal.mannotations.department
//	}
type Annotations map[string]interface{}

// MergeStrategy strategy constants for annotation merging
const (
	MergeReplace = "replace" // Higher priority value completely replaces lower
	MergeAppend  = "append"  // Arrays: [higher..., lower...], Objects: shallow merge (higher wins)
	MergePrepend = "prepend" // Arrays: [lower..., higher...], Objects: shallow merge (lower wins)
	MergeDeep    = "deep"    // Arrays: [higher..., lower...], Objects: recursive deep merge
	MergeUnion   = "union"   // Arrays: deduplicated set, Objects: same as deep

	// DefaultMergeStrategy is used when no strategy is specified
	DefaultMergeStrategy = MergeDeep
)

// AnnotationEntry holds a parsed annotation value with its merge strategy.
//
// AnnotationEntry is used during the annotation merging process to track
// both the value and how it should be merged with values from other sources
// in the inheritance hierarchy.
type AnnotationEntry struct {
	// Value is the parsed JSON value of the annotation
	Value interface{}
	// MergeStrategy is the strategy for merging: "replace", "append", "prepend", "deep", "union"
	MergeStrategy string
}

// RichAnnotations is a map of annotation entries with merge strategies.
//
// RichAnnotations is used internally during annotation resolution to track
// merge strategies. After merging is complete, the result is converted to
// plain Annotations for use in policy evaluation.
type RichAnnotations map[string]AnnotationEntry

// ToAnnotations converts RichAnnotations to plain Annotations by extracting just the values.
func (r RichAnnotations) ToAnnotations() Annotations {
	if r == nil {
		return nil
	}
	result := make(Annotations, len(r))
	for k, entry := range r {
		result[k] = entry.Value
	}
	return result
}

// FromAnnotations converts plain Annotations to RichAnnotations with default (empty) merge strategies.
// This is useful when receiving resources from PORC input where annotations are already plain values.
func FromAnnotations(a Annotations) RichAnnotations {
	if a == nil {
		return nil
	}
	result := make(RichAnnotations, len(a))
	for k, v := range a {
		result[k] = AnnotationEntry{Value: v}
	}
	return result
}

// MarshalJSON serializes RichAnnotations as a plain map of values (without merge strategies).
// This ensures OPA receives annotations in the expected format.
func (r *RichAnnotations) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.ToAnnotations())
}

// UnmarshalJSON deserializes a plain map of values into RichAnnotations.
// MergeStrategy strategies default to empty (which means use default).
func (r *RichAnnotations) UnmarshalJSON(data []byte) error {
	var plain Annotations
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	if plain == nil {
		*r = nil
		return nil
	}
	result := make(RichAnnotations, len(plain))
	for k, v := range plain {
		result[k] = AnnotationEntry{Value: v}
	}
	*r = result
	return nil
}

// Policy represents a compiled Rego policy ready for evaluation.
//
// Policy contains the compiled AST (Abstract Syntax Tree) of a Rego policy
// along with identifying metadata. The AST is used by the policy engine to
// evaluate authorization decisions.
//
// Fields:
//   - Mrn: The Manetu Resource Name uniquely identifying this policy
//   - Fingerprint: A SHA-256 hash of the policy content for cache invalidation
//   - Ast: The compiled OPA AST for policy evaluation
type Policy struct {
	Mrn         string
	Fingerprint []byte
	Ast         *opa.Ast
}

// PolicyReference represents a policy binding with annotations.
//
// PolicyReference is used by roles, scopes, operations, and resource groups
// to associate a compiled policy with the entity. It provides:
//   - The entity's MRN for identification
//   - A reference to the compiled policy for evaluation
//   - Annotations providing metadata for policy decisions with merge strategies
//
// During authorization, the policy engine retrieves PolicyReferences to
// access both the policy to evaluate and any annotations that should be
// made available to the policy as input.
type PolicyReference struct {
	Mrn         string
	Policy      *Policy
	Annotations RichAnnotations
}

// Group represents a named collection of roles for batch permission assignment.
//
// Groups allow administrators to manage permissions at a higher level of
// abstraction. Instead of assigning individual roles to users, users can
// be assigned to groups, inheriting all roles in the group.
//
// Fields:
//   - Mrn: The Manetu Resource Name uniquely identifying this group
//   - Roles: MRNs of all roles included in this group
//   - Annotations: Metadata available during policy evaluation with merge strategies
type Group struct {
	Mrn         string
	Roles       []string
	Annotations RichAnnotations
}

// Resource represents a target of operations in authorization decisions.
//
// Resources are the "R" in PORC - the objects that operations act upon.
// Examples include documents, database records, API endpoints, or any
// other entity that requires access control.
//
// Fields:
//   - ID: The Manetu Resource Name identifying this specific resource
//   - Owner: Subject identifier of the identity that owns this resource
//   - Group: MRN of the resource group this resource belongs to
//   - Annotations: Custom metadata for policy decisions (with merge strategies)
//   - Classification: Security level (e.g., "LOW", "MODERATE", "HIGH", "MAXIMUM")
//
// The JSON tags support PORC encoding/decoding when resources are passed
// through authorization requests. RichAnnotations marshal to plain values
// for OPA compatibility while preserving merge strategies internally.
type Resource struct {
	ID             string          `json:"id,omitempty"`
	Owner          string          `json:"owner,omitempty"`
	Group          string          `json:"group,omitempty"`
	Annotations    RichAnnotations `json:"annotations,omitempty"`
	Classification string          `json:"classification,omitempty"`
}

// Mapper transforms non-PORC inputs into PORC expressions.
//
// Mappers are Rego policies used for integrations where the enforcement
// point cannot construct PORC expressions directly (e.g., Envoy ext_authz).
// The mapper receives the raw input and produces a complete PORC expression.
//
// A mapper Rego policy uses package mapper and defines a porc rule:
//
//	package mapper
//
//	porc := {
//	    "principal": {
//	        "sub": input.request.headers.authorization,
//	        "mroles": ["mrn:iam:role:user"]
//	    },
//	    "operation": sprintf("%s:http:%s", [service, method]),
//	    "resource": sprintf("mrn:http:%s%s", [service, path]),
//	    "context": input
//	}
//
// Most integrations should construct PORC directly in application code
// rather than using mappers. See the Integration documentation.
//
// Fields:
//   - Domain: The policy domain this mapper belongs to
//   - Ast: The compiled Rego AST for executing the transformation
type Mapper struct {
	Domain string
	Ast    *opa.Ast
}

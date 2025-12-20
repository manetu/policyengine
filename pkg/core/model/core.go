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
//   - Annotations providing metadata for policy decisions
//
// During authorization, the policy engine retrieves PolicyReferences to
// access both the policy to evaluate and any annotations that should be
// made available to the policy as input.
type PolicyReference struct {
	Mrn         string
	Policy      *Policy
	Annotations Annotations
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
//   - Annotations: Metadata available during policy evaluation
type Group struct {
	Mrn         string
	Roles       []string
	Annotations Annotations
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
//   - Annotations: Custom metadata for policy decisions
//   - Classification: Security level (e.g., "LOW", "MODERATE", "HIGH", "MAXIMUM")
//
// The JSON tags support PORC encoding/decoding when resources are passed
// through authorization requests.
type Resource struct {
	ID             string      `json:"id,omitempty"`
	Owner          string      `json:"owner,omitempty"`
	Group          string      `json:"group,omitempty"`
	Annotations    Annotations `json:"annotations,omitempty"`
	Classification string      `json:"classification,omitempty"`
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

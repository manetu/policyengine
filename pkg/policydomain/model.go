//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package policydomain provides types for representing parsed policy domain
// configurations.
//
// Policy domains are defined in YAML files and loaded via the [registry]
// package. This package contains the intermediate model types used after
// parsing but before compilation into the runtime [model] types.
//
// # Key Types
//
//   - [IntermediateModel]: Complete policy domain with all components
//   - [Policy]: A policy definition with Rego source code
//   - [PolicyReference]: Reference from roles/scopes/resource-groups to policies
//   - [Mapper]: Principal mapper for transforming external identity claims
//
// # Usage
//
// Policy domains are typically loaded via the [registry.NewRegistry] function,
// which parses YAML files and returns validated [IntermediateModel] instances.
//
// See the PolicyDomain concepts documentation for the YAML schema.
package policydomain

import (
	"regexp"

	"github.com/manetu/policyengine/pkg/core/opa"
)

// IDSpec contains the MRN identifier and content fingerprint for a policy entity.
type IDSpec struct {
	// ID is the Manetu Resource Name (MRN) identifying this entity.
	ID string
	// Fingerprint is a SHA-256 hash of the entity's content for cache invalidation.
	Fingerprint []byte
}

// Annotation holds an annotation's value and optional merge strategy.
type Annotation struct {
	// Value is the annotation value. For v1alpha3/v1alpha4 this is a JSON-encoded string.
	// For v1beta1 this is the native decoded value (interface{}).
	Value interface{}
	// MergeStrategy is the merge strategy: "replace", "append", "prepend", "deep", "union".
	// Empty string defaults to "deep".
	MergeStrategy string
}

// AnnotationDefaults contains default settings for annotation merging.
type AnnotationDefaults struct {
	// MergeStrategy is the default merge strategy for annotations.
	MergeStrategy string
}

// Policy represents a Rego policy definition parsed from YAML.
//
// The Ast field is nil after parsing and populated by
// [registry.Registry.CompileAllPolicies] after validation.
type Policy struct {
	IDSpec       IDSpec
	Dependencies []string // MRNs of policy libraries this policy depends on
	Rego         string   // Rego source code
	Ast          *opa.Ast // Compiled AST (populated after compilation)
}

// PolicyReference connects roles, scopes, or resource groups to their policies.
type PolicyReference struct {
	IDSpec      IDSpec
	Policy      string                // MRN of the referenced policy
	Default     bool                  // True if this is a default resource group
	Annotations map[string]Annotation // Metadata available during policy evaluation
}

// Group represents a named collection of roles.
type Group struct {
	IDSpec      IDSpec
	Roles       []string              // MRNs of roles in this group
	Annotations map[string]Annotation // Metadata available during policy evaluation
}

// Operation routes authorization requests to policies based on operation MRN patterns.
type Operation struct {
	IDSpec    IDSpec
	Selectors []*regexp.Regexp // Patterns matching operation MRNs
	Policy    string           // MRN of the policy to evaluate
}

// Mapper transforms external identity claims into PORC principal data.
//
// The Ast field is nil after parsing and populated by
// [registry.Registry.CompileAllPolicies] after validation.
type Mapper struct {
	IDSpec    IDSpec
	Selectors []*regexp.Regexp // Patterns matching operation MRNs
	Rego      string           // Rego source code for the mapper
	Ast       *opa.Ast         // Compiled AST (populated after compilation)
}

// Resource matches resource MRNs to resource groups for policy evaluation.
type Resource struct {
	IDSpec      IDSpec
	Selectors   []*regexp.Regexp      // Patterns matching resource MRNs
	Group       string                // MRN of the resource group
	Annotations map[string]Annotation // Metadata available during policy evaluation
}

// IntermediateModel is the complete representation of a parsed policy domain.
//
// IntermediateModel is created by parsing YAML policy domain files and
// validated by the [registry] package. After validation, policies and
// mappers are compiled to populate the Ast fields.
type IntermediateModel struct {
	Name               string                     // Policy domain name
	AnnotationDefaults AnnotationDefaults         // Default annotation merge settings
	PolicyLibraries    map[string]Policy          // Reusable Rego libraries
	Policies           map[string]Policy          // Authorization policies
	Roles              map[string]PolicyReference // Role-to-policy bindings
	Groups             map[string]Group           // Named role collections
	ResourceGroups     map[string]PolicyReference // Resource-to-policy bindings
	Scopes             map[string]PolicyReference // Scope-to-policy bindings
	Operations         []Operation                // Operation routing rules
	Mappers            []Mapper                   // Principal mappers
	Resources          []Resource                 // Resource matching rules
}

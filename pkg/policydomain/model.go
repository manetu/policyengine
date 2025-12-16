//
//  Copyright © Manetu Inc. All rights reserved.
//

package policydomain

import (
	"regexp"

	"github.com/manetu/policyengine/pkg/core/opa"
)

// IDSpec represents an identifier specification with an ID and optional fingerprint
type IDSpec struct {
	ID          string
	Fingerprint []byte
}

// Policy represents a policy with its ID, dependencies, and Rego code.
// The Ast field is populated by CompileAllPolicies after registry validation.
type Policy struct {
	IDSpec       IDSpec
	Dependencies []string
	Rego         string
	Ast          *opa.Ast
}

// PolicyReference represents a reference to a policy with annotations
type PolicyReference struct {
	IDSpec      IDSpec
	Policy      string
	Default     bool
	Annotations map[string]string
}

// Group represents a group with roles and annotations
type Group struct {
	IDSpec      IDSpec
	Roles       []string
	Annotations map[string]string
}

// Operation represents an operation with selectors and a policy reference
type Operation struct {
	IDSpec    IDSpec
	Selectors []*regexp.Regexp
	Policy    string
}

// Mapper represents a mapper with selectors and Rego code.
// The Ast field is populated by CompileAllPolicies after registry validation.
type Mapper struct {
	IDSpec    IDSpec
	Selectors []*regexp.Regexp
	Rego      string
	Ast       *opa.Ast
}

// Resource represents a resource with selectors and a resource group reference
type Resource struct {
	IDSpec      IDSpec
	Selectors   []*regexp.Regexp
	Group       string
	Annotations map[string]string
}

// IntermediateModel represents a complete policy domain model.
type IntermediateModel struct {
	Name            string
	PolicyLibraries map[string]Policy
	Policies        map[string]Policy
	Roles           map[string]PolicyReference
	Groups          map[string]Group
	ResourceGroups  map[string]PolicyReference
	Scopes          map[string]PolicyReference
	Operations      []Operation
	Mappers         []Mapper
	Resources       []Resource
}

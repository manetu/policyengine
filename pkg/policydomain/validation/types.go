//
//  Copyright © Manetu Inc. All rights reserved.
//

package validation

import "regexp"

// DomainMap provides access to policy domain models by name
type DomainMap interface {
	GetDomain(name string) (DomainModel, bool)
	GetAllDomains() map[string]DomainModel
}

// DomainModel interface represents a policy domain
type DomainModel interface {
	GetName() string
	GetPolicies() map[string]PolicyEntity
	GetPolicyLibraries() map[string]PolicyEntity
	GetRoles() map[string]ReferenceEntity
	GetGroups() map[string]GroupEntity
	GetResourceGroups() map[string]ReferenceEntity
	GetScopes() map[string]ReferenceEntity
	GetOperations() []OperationEntity
	GetMappers() []MapperEntity
}

// RegoEntity interface for any entity that contains Rego code
// This allows the validator to work with any domain model without importing domain types
type RegoEntity interface {
	GetRego() string
}

// PolicyEntity interface for policies and policy libraries (have dependencies and rego)
type PolicyEntity interface {
	RegoEntity
	GetDependencies() []string
}

// ReferenceEntity interface for entities that reference policies
type ReferenceEntity interface {
	GetPolicy() string
}

// GroupEntity interface for groups that reference roles
type GroupEntity interface {
	GetRoles() []string
}

// OperationEntity interface for operations
type OperationEntity interface {
	GetSelectors() []*regexp.Regexp
	GetPolicy() string
}

// MapperEntity interface for mappers that have Rego and an ID
type MapperEntity interface {
	RegoEntity
	GetID() string
}

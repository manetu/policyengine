//
//  Copyright © Manetu Inc. All rights reserved.
//

package registry

import (
	"regexp"

	"github.com/manetu/policyengine/pkg/policydomain"
	"github.com/manetu/policyengine/pkg/policydomain/validation"
)

// DomainMapAdapter adapts the existing DomainMap to the validation.DomainMap interface
type DomainMapAdapter struct {
	domains DomainMap // existing DomainMap type from registry
}

// NewDomainMapAdapter creates a new adapter for the domain map
func NewDomainMapAdapter(domains DomainMap) *DomainMapAdapter {
	return &DomainMapAdapter{
		domains: domains,
	}
}

// GetDomain implements validation.DomainMap interface
func (dma *DomainMapAdapter) GetDomain(name string) (validation.DomainModel, bool) {
	model, exists := dma.domains[name]
	if !exists {
		return nil, false
	}
	return &DomainModelAdapter{model}, true
}

// GetAllDomains implements validation.DomainMap interface
func (dma *DomainMapAdapter) GetAllDomains() map[string]validation.DomainModel {
	result := make(map[string]validation.DomainModel)
	for name, model := range dma.domains {
		result[name] = &DomainModelAdapter{model}
	}
	return result
}

// PolicyAdapter adapts policydomain.Policy to validation.PolicyEntity interface
type PolicyAdapter struct {
	*policydomain.Policy
}

// GetRego implements validation.RegoEntity interface
func (pa *PolicyAdapter) GetRego() string {
	return pa.Rego
}

// GetDependencies implements validation.PolicyEntity interface
func (pa *PolicyAdapter) GetDependencies() []string {
	return pa.Dependencies
}

// ReferenceAdapter adapts policy reference strings to validation.ReferenceEntity interface
type ReferenceAdapter struct {
	policy string
}

// GetPolicy implements validation.ReferenceEntity interface
func (ra *ReferenceAdapter) GetPolicy() string {
	return ra.policy
}

// GroupAdapter adapts role slices to validation.GroupEntity interface
type GroupAdapter struct {
	roles []string
}

// GetRoles implements validation.GroupEntity interface
func (ga *GroupAdapter) GetRoles() []string {
	return ga.roles
}

// OperationAdapter adapts policydomain.Operation to validation.OperationEntity interface
type OperationAdapter struct {
	*policydomain.Operation
}

// GetSelectors implements validation.OperationEntity interface
func (oa *OperationAdapter) GetSelectors() []*regexp.Regexp {
	return oa.Selectors
}

// GetPolicy implements validation.OperationEntity interface
func (oa *OperationAdapter) GetPolicy() string {
	return oa.Policy
}

// MapperAdapter adapts policydomain.Mapper to validation.MapperEntity interface
type MapperAdapter struct {
	*policydomain.Mapper
}

// GetRego implements validation.RegoEntity interface
func (ma *MapperAdapter) GetRego() string {
	return ma.Rego
}

// GetID implements validation.MapperEntity interface
func (ma *MapperAdapter) GetID() string {
	return ma.IDSpec.ID
}

// DomainModelAdapter adapts policydomain.IntermediateModel to validation.DomainModel interface
type DomainModelAdapter struct {
	*policydomain.IntermediateModel
}

// GetName implements validation.DomainModel interface
func (dma *DomainModelAdapter) GetName() string {
	return dma.Name
}

// GetPolicies implements validation.DomainModel interface
func (dma *DomainModelAdapter) GetPolicies() map[string]validation.PolicyEntity {
	result := make(map[string]validation.PolicyEntity)
	for id, policy := range dma.Policies {
		result[id] = &PolicyAdapter{&policy}
	}
	return result
}

// GetPolicyLibraries implements validation.DomainModel interface
func (dma *DomainModelAdapter) GetPolicyLibraries() map[string]validation.PolicyEntity {
	result := make(map[string]validation.PolicyEntity)
	for id, library := range dma.PolicyLibraries {
		result[id] = &PolicyAdapter{&library}
	}
	return result
}

// GetRoles implements validation.DomainModel interface
func (dma *DomainModelAdapter) GetRoles() map[string]validation.ReferenceEntity {
	result := make(map[string]validation.ReferenceEntity)
	for id, role := range dma.Roles {
		result[id] = &ReferenceAdapter{role.Policy}
	}
	return result
}

// GetGroups implements validation.DomainModel interface
func (dma *DomainModelAdapter) GetGroups() map[string]validation.GroupEntity {
	result := make(map[string]validation.GroupEntity)
	for id, group := range dma.Groups {
		result[id] = &GroupAdapter{group.Roles}
	}
	return result
}

// GetResourceGroups implements validation.DomainModel interface
func (dma *DomainModelAdapter) GetResourceGroups() map[string]validation.ReferenceEntity {
	result := make(map[string]validation.ReferenceEntity)
	for id, rg := range dma.ResourceGroups {
		result[id] = &ReferenceAdapter{rg.Policy}
	}
	return result
}

// GetScopes implements validation.DomainModel interface
func (dma *DomainModelAdapter) GetScopes() map[string]validation.ReferenceEntity {
	result := make(map[string]validation.ReferenceEntity)
	for id, scope := range dma.Scopes {
		result[id] = &ReferenceAdapter{scope.Policy}
	}
	return result
}

// GetOperations implements validation.DomainModel interface
func (dma *DomainModelAdapter) GetOperations() []validation.OperationEntity {
	result := make([]validation.OperationEntity, len(dma.Operations))
	for i, operation := range dma.Operations {
		result[i] = &OperationAdapter{&operation}
	}
	return result
}

// GetMappers implements validation.DomainModel interface
func (dma *DomainModelAdapter) GetMappers() []validation.MapperEntity {
	result := make([]validation.MapperEntity, len(dma.Mappers))
	for i, mapper := range dma.Mappers {
		result[i] = &MapperAdapter{&mapper}
	}
	return result
}

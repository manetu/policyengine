//
//  Copyright © Manetu Inc. All rights reserved.
//

package validation

import (
	"fmt"
	"strings"
)

// libraryNode represents a library in the dependency graph
type libraryNode struct {
	domain string
	id     string
}

// DomainValidator handles all validation logic for policy domains
type DomainValidator struct {
	resolver      *ReferenceResolver
	domains       DomainMap
	regoValidator *RegoValidator
}

// NewDomainValidator creates a new domain validator
func NewDomainValidator(resolver *ReferenceResolver, domains DomainMap) *DomainValidator {
	return &DomainValidator{
		resolver:      resolver,
		domains:       domains,
		regoValidator: NewRegoValidator(),
	}
}

// ValidateAll performs complete validation of all domains, accumulating all errors
func (v *DomainValidator) ValidateAll() error {
	errors := NewValidationErrors()

	// Validate references across all domains
	v.validateAllReferences(errors)

	// Validate library cycles
	v.validateAllLibraryCycles(errors)

	// Validate rego compilation
	v.validateAllRegoCompilation(errors)

	if errors.HasErrors() {
		return errors
	}

	return nil
}

// ValidateWithSummary validates and returns a detailed summary of any errors
func (v *DomainValidator) ValidateWithSummary() (bool, string) {
	err := v.ValidateAll()
	if err == nil {
		return true, "All validations passed successfully"
	}

	if validationErrors, ok := err.(*Errors); ok {
		return false, validationErrors.Summary()
	}

	// Fallback for non-ValidationErrors
	return false, fmt.Sprintf("Validation failed: %v", err)
}

// GetAllValidationErrors returns all validation errors without stopping on first error
func (v *DomainValidator) GetAllValidationErrors() []*Error {
	err := v.ValidateAll()
	if err == nil {
		return nil
	}

	if validationErrors, ok := err.(*Errors); ok {
		return validationErrors.Errors
	}

	// Fallback for non-ValidationErrors
	return []*Error{
		{
			Type:    "unknown",
			Message: err.Error(),
		},
	}
}

// ValidateDomain validates a specific domain, accumulating errors
func (v *DomainValidator) ValidateDomain(domainName string) error {
	domainModel, exists := v.domains.GetDomain(domainName)
	if !exists {
		return fmt.Errorf("domain '%s' not found", domainName)
	}

	errors := NewValidationErrors()
	v.validateDomainReferences(domainName, domainModel, errors)

	// Also validate rego compilation for this specific domain
	v.regoValidator.ValidateDomainRego(domainName, domainModel, errors)

	if errors.HasErrors() {
		return errors
	}

	return nil
}

// validateAllReferences validates all cross-domain references, accumulating errors
func (v *DomainValidator) validateAllReferences(errors *Errors) {
	allDomains := v.domains.GetAllDomains()
	for domainName, model := range allDomains {
		v.validateDomainReferences(domainName, model, errors)
	}
}

// validateAllLibraryCycles detects circular dependencies, accumulating errors
func (v *DomainValidator) validateAllLibraryCycles(errors *Errors) {
	if err := v.detectLibraryCycles(); err != nil {
		errors.AddCycleError(err.Error())
	}
}

// validateAllRegoCompilation validates rego compilation
func (v *DomainValidator) validateAllRegoCompilation(errors *Errors) {
	allDomains := v.domains.GetAllDomains()
	for domainName, model := range allDomains {
		v.regoValidator.ValidateDomainRego(domainName, model, errors)
	}
}

// validateDomainReferences validates all references within a single domain, accumulating errors
func (v *DomainValidator) validateDomainReferences(domainName string, model DomainModel, errors *Errors) {
	// Validate each entity type, accumulating errors instead of stopping on first failure
	v.validatePolicyLibraries(domainName, model, errors)
	v.validatePolicies(domainName, model, errors)
	v.validateRoles(domainName, model, errors)
	v.validateGroups(domainName, model, errors)
	v.validateResourceGroups(domainName, model, errors)
	v.validateScopes(domainName, model, errors)
	v.validateOperations(domainName, model, errors)
}

// validatePolicyLibraries validates all policy library dependencies
func (v *DomainValidator) validatePolicyLibraries(domainName string, model DomainModel, errors *Errors) {
	libraries := model.GetPolicyLibraries()
	for libID, library := range libraries {
		for _, dep := range library.GetDependencies() {
			if err := v.resolver.ValidateReference(dep, domainName, "library"); err != nil {
				errors.AddReferenceError(domainName, "library", libID, "dependencies", err.Error())
			}
		}
	}
}

// validatePolicies validates all policy dependencies
func (v *DomainValidator) validatePolicies(domainName string, model DomainModel, errors *Errors) {
	policies := model.GetPolicies()
	for policyID, policy := range policies {
		for _, dep := range policy.GetDependencies() {
			if err := v.resolver.ValidateReference(dep, domainName, "library"); err != nil {
				errors.AddReferenceError(domainName, "policy", policyID, "dependencies", err.Error())
			}
		}
	}
}

// validateRoles validates all role policy references
func (v *DomainValidator) validateRoles(domainName string, model DomainModel, errors *Errors) {
	roles := model.GetRoles()
	for roleID, role := range roles {
		if err := v.resolver.ValidateReference(role.GetPolicy(), domainName, "policy"); err != nil {
			errors.AddReferenceError(domainName, "role", roleID, "policy", err.Error())
		}
	}
}

// validateGroups validates all group role references
func (v *DomainValidator) validateGroups(domainName string, model DomainModel, errors *Errors) {
	groups := model.GetGroups()
	for groupID, group := range groups {
		for i, roleRef := range group.GetRoles() {
			if err := v.resolver.ValidateReference(roleRef, domainName, "role"); err != nil {
				errors.AddReferenceError(domainName, "group", groupID, fmt.Sprintf("roles[%d]", i), err.Error())
			}
		}
	}
}

// validateResourceGroups validates all resource group policy references
func (v *DomainValidator) validateResourceGroups(domainName string, model DomainModel, errors *Errors) {
	resourceGroups := model.GetResourceGroups()
	for rgID, rg := range resourceGroups {
		if err := v.resolver.ValidateReference(rg.GetPolicy(), domainName, "policy"); err != nil {
			errors.AddReferenceError(domainName, "resource-group", rgID, "policy", err.Error())
		}
	}
}

// validateScopes validates all scope policy references
func (v *DomainValidator) validateScopes(domainName string, model DomainModel, errors *Errors) {
	scopes := model.GetScopes()
	for scopeID, scope := range scopes {
		if err := v.resolver.ValidateReference(scope.GetPolicy(), domainName, "policy"); err != nil {
			errors.AddReferenceError(domainName, "scope", scopeID, "policy", err.Error())
		}
	}
}

// validateOperations validates all operation policy references
func (v *DomainValidator) validateOperations(domainName string, model DomainModel, errors *Errors) {
	operations := model.GetOperations()
	for i, operation := range operations {
		if err := v.resolver.ValidateReference(operation.GetPolicy(), domainName, "policy"); err != nil {
			errors.AddReferenceError(domainName, "operation", fmt.Sprintf("operation[%d]", i), "policy", err.Error())
		}
	}
}

// detectLibraryCycles performs DFS-based cycle detection across all domains
func (v *DomainValidator) detectLibraryCycles() error {
	qname := func(d, id string) string {
		return fmt.Sprintf("%s/%s", d, id)
	}

	state := make(map[string]int)

	// DFS function for cycle detection
	var dfs func(cur libraryNode, stack []string) error
	dfs = func(cur libraryNode, stack []string) error {
		key := qname(cur.domain, cur.id)

		if state[key] == 1 {
			// Cycle detected - build error message
			return v.buildCycleError(key, stack)
		}
		if state[key] == 2 {
			return nil // Already processed
		}

		// Mark as visiting and add to stack
		state[key] = 1
		stack = append(stack, key)

		// Get library and validate dependencies
		library, err := v.getLibrary(cur.domain, cur.id)
		if err != nil {
			return err
		}

		// Check each dependency
		for _, dep := range library.GetDependencies() {
			depNode, err := v.resolveDependencyNode(dep, cur.domain)
			if err != nil {
				return err
			}

			if err := dfs(depNode, stack); err != nil {
				return err
			}
		}

		// Mark as done
		state[key] = 2
		return nil
	}

	// Check all libraries in all domains
	allDomains := v.domains.GetAllDomains()
	for domainName, domainModel := range allDomains {
		libraries := domainModel.GetPolicyLibraries()
		for libID := range libraries {
			if err := dfs(libraryNode{domain: domainName, id: libID}, []string{}); err != nil {
				return err
			}
		}
	}

	return nil
}

// buildCycleError creates a detailed error message for circular dependencies
func (v *DomainValidator) buildCycleError(key string, stack []string) error {
	// Find where the cycle starts
	start := 0
	for i, k := range stack {
		if k == key {
			start = i
			break
		}
	}

	cycle := append(stack[start:], key)
	return fmt.Errorf("circular dependency detected: %s", strings.Join(cycle, " → "))
}

// getLibrary safely retrieves a library from a domain
func (v *DomainValidator) getLibrary(domainName, libID string) (PolicyEntity, error) {
	domainModel, ok := v.domains.GetDomain(domainName)
	if !ok {
		return nil, fmt.Errorf("domain '%s' not found", domainName)
	}

	libraries := domainModel.GetPolicyLibraries()
	library, ok := libraries[libID]
	if !ok {
		return nil, fmt.Errorf("library '%s' not found in domain '%s'", libID, domainName)
	}

	return library, nil
}

// resolveDependencyNode resolves a dependency string to a libraryNode
func (v *DomainValidator) resolveDependencyNode(dependency, sourceDomain string) (libraryNode, error) {
	targetDomain, depID, err := v.resolver.ParseReference(dependency, sourceDomain)
	if err != nil {
		return libraryNode{}, err
	}

	// Validate that the target exists
	if err := v.validateDependencyExists(targetDomain, depID); err != nil {
		return libraryNode{}, err
	}

	return libraryNode{domain: targetDomain, id: depID}, nil
}

// validateDependencyExists checks if a dependency target exists
func (v *DomainValidator) validateDependencyExists(targetDomain, depID string) error {
	targetModel, exists := v.domains.GetDomain(targetDomain)
	if !exists {
		return fmt.Errorf("domain '%s' not found", targetDomain)
	}

	libraries := targetModel.GetPolicyLibraries()
	if _, exists := libraries[depID]; !exists {
		return fmt.Errorf("library '%s' not found in domain '%s'", depID, targetDomain)
	}

	return nil
}

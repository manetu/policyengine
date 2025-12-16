//
//  Copyright © Manetu Inc. All rights reserved.
//

package validation

import (
	"fmt"
	"strings"
)

// ReferenceResolver handles all reference parsing and resolution logic
type ReferenceResolver struct {
	domains DomainMap
}

// NewReferenceResolver creates a new reference resolver with the given domains
func NewReferenceResolver(domains DomainMap) *ReferenceResolver {
	return &ReferenceResolver{
		domains: domains,
	}
}

// ParseReference parses a reference string into target domain and object ID
// Handles both qualified (domain/objectID) and unqualified (objectID) references
func (r *ReferenceResolver) ParseReference(reference, sourceDomain string) (targetDomain, objectID string, err error) {
	if reference == "" {
		return "", "", fmt.Errorf("empty reference")
	}

	if strings.Contains(reference, "/") {
		// Qualified reference: "domain/objectID"
		parts := strings.SplitN(reference, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", fmt.Errorf("invalid qualified reference format '%s', expected 'domain/id'", reference)
		}
		return parts[0], parts[1], nil
	}

	// Unqualified reference: use source domain
	return sourceDomain, reference, nil
}

// QualifyReference converts a reference to its fully qualified form
func (r *ReferenceResolver) QualifyReference(reference, sourceDomain string) string {
	if strings.Contains(reference, "/") {
		return reference // Already qualified
	}
	return fmt.Sprintf("%s/%s", sourceDomain, reference)
}

// ValidateReference checks if a reference exists and is of the expected type
func (r *ReferenceResolver) ValidateReference(reference, sourceDomain, expectedType string) error {
	if reference == "" {
		return nil
	}

	targetDomain, objectID, err := r.ParseReference(reference, sourceDomain)
	if err != nil {
		return err
	}

	// Check if target domain exists
	targetModel, exists := r.domains.GetDomain(targetDomain)
	if !exists {
		return fmt.Errorf("domain '%s' contains undefined references to domain '%s'", sourceDomain, targetDomain)
	}

	// Check if referenced object exists and is of the correct type
	if !r.objectExistsInDomain(objectID, expectedType, targetModel) {
		return fmt.Errorf("%s reference '%s' not found in domain '%s'", expectedType, objectID, targetDomain)
	}

	return nil
}

// ResolveReference parses and validates a reference, returning the target domain and model
func (r *ReferenceResolver) ResolveReference(reference, sourceDomain, expectedType string) (targetDomain string, targetModel DomainModel, objectID string, err error) {
	targetDomain, objectID, err = r.ParseReference(reference, sourceDomain)
	if err != nil {
		return "", nil, "", err
	}

	targetModel, exists := r.domains.GetDomain(targetDomain)
	if !exists {
		return "", nil, "", fmt.Errorf("domain '%s' not found", targetDomain)
	}

	if !r.objectExistsInDomain(objectID, expectedType, targetModel) {
		return "", nil, "", fmt.Errorf("%s reference '%s' not found in domain '%s'", expectedType, objectID, targetDomain)
	}

	return targetDomain, targetModel, objectID, nil
}

// objectExistsInDomain checks if an object ID exists in a domain and is of the specified type
func (r *ReferenceResolver) objectExistsInDomain(objectID, objectType string, model DomainModel) bool {
	switch objectType {
	case "policy":
		policies := model.GetPolicies()
		_, exists := policies[objectID]
		return exists
	case "library":
		libraries := model.GetPolicyLibraries()
		_, exists := libraries[objectID]
		return exists
	case "role":
		roles := model.GetRoles()
		_, exists := roles[objectID]
		return exists
	case "group":
		groups := model.GetGroups()
		_, exists := groups[objectID]
		return exists
	case "resource-group":
		resourceGroups := model.GetResourceGroups()
		_, exists := resourceGroups[objectID]
		return exists
	case "scope":
		scopes := model.GetScopes()
		_, exists := scopes[objectID]
		return exists
	case "operation":
		return r.matchesAnyOperation(objectID, model)
	default:
		return false
	}
}

// FindObjectAcrossDomains searches for an object across all domains
func (r *ReferenceResolver) FindObjectAcrossDomains(objectID, objectType string) (string, DomainModel, error) {
	var foundDomains []string
	allDomains := r.domains.GetAllDomains()

	for domainName, domainModel := range allDomains {
		if r.objectExistsInDomain(objectID, objectType, domainModel) {
			foundDomains = append(foundDomains, domainName)
		}
	}

	if len(foundDomains) == 0 {
		return "", nil, fmt.Errorf("%s '%s' not found in any domain", objectType, objectID)
	}

	if len(foundDomains) > 1 {
		return "", nil, fmt.Errorf("ambiguous %s '%s' found in multiple domains: %v", objectType, objectID, foundDomains)
	}

	foundDomain := foundDomains[0]
	domainModel, _ := r.domains.GetDomain(foundDomain)
	return foundDomain, domainModel, nil
}

// matchesAnyOperation checks if objectID matches any operation selector in the domain
func (r *ReferenceResolver) matchesAnyOperation(objectID string, model DomainModel) bool {
	operations := model.GetOperations()
	for _, operation := range operations {
		selectors := operation.GetSelectors()
		for _, selector := range selectors {
			if selector.Match([]byte(objectID)) {
				return true
			}
		}
	}
	return false
}

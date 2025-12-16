//
//  Copyright © Manetu Inc. All rights reserved.
//

package validation

// ValidatorInterface defines the main validation contract
type ValidatorInterface interface {
	// ValidateAll performs complete validation of all domains
	ValidateAll() error

	// ValidateDomain validates a specific domain
	ValidateDomain(domainName string) error

	// ValidateWithSummary validates and returns a summary
	ValidateWithSummary() (bool, string)

	// GetAllValidationErrors returns all validation errors
	GetAllValidationErrors() []*Error
}

// BundleValidator provides high-level validation for policy bundles
type BundleValidator struct {
	validator *DomainValidator
}

// NewBundleValidator creates a validator for policy domains
func NewBundleValidator(domains DomainMap) *BundleValidator {
	resolver := NewReferenceResolver(domains)
	validator := NewDomainValidator(resolver, domains)

	return &BundleValidator{
		validator: validator,
	}
}

// ValidateAll validates all domains in the bundle
func (bv *BundleValidator) ValidateAll() error {
	return bv.validator.ValidateAll()
}

// ValidateDomain validates a specific domain
func (bv *BundleValidator) ValidateDomain(domainName string) error {
	return bv.validator.ValidateDomain(domainName)
}

// ValidateWithSummary validates and returns a summary
func (bv *BundleValidator) ValidateWithSummary() (bool, string) {
	return bv.validator.ValidateWithSummary()
}

// GetAllValidationErrors returns all validation errors
func (bv *BundleValidator) GetAllValidationErrors() []*Error {
	return bv.validator.GetAllValidationErrors()
}

// ValidateDependencies resolves and validates dependencies for a domain model
func (bv *BundleValidator) ValidateDependencies(model DomainModel, dependencies []string) ([]string, error) {
	resolver := NewReferenceResolver(bv.validator.domains)
	depResolver := NewDependencyResolver(resolver)
	return depResolver.ResolveDependencies(model, dependencies)
}

// ValidateRegoCode validates individual Rego code snippets
func ValidateRegoCode(regoCode, entityType, entityID string) error {
	validator := NewRegoValidator()
	return validator.ValidateRegoCode(regoCode, entityType, entityID)
}

// ParseReference parses a reference string into domain and object ID components
func ParseReference(reference, sourceDomain string, domains DomainMap) (targetDomain, objectID string, err error) {
	resolver := NewReferenceResolver(domains)
	return resolver.ParseReference(reference, sourceDomain)
}

// ValidateReference validates that a reference exists in the domain collection
func ValidateReference(reference, sourceDomain, expectedType string, domains DomainMap) error {
	resolver := NewReferenceResolver(domains)
	return resolver.ValidateReference(reference, sourceDomain, expectedType)
}

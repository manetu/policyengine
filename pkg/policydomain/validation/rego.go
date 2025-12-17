//
//  Copyright © Manetu Inc. All rights reserved.
//

package validation

import (
	"fmt"
	"strings"

	//lint:ignore SA1019 deprecated OPA v0.x package kept for compatibility
	"github.com/open-policy-agent/opa/ast" //nolint:staticcheck
)

// RegoValidator handles validation of Rego code compilation
type RegoValidator struct{}

// NewRegoValidator creates a new Rego validator
func NewRegoValidator() *RegoValidator {
	return &RegoValidator{}
}

// ValidateRegoCode validates that Rego code compiles successfully
func (rv *RegoValidator) ValidateRegoCode(regoCode, entityType, entityID string) error {
	if strings.TrimSpace(regoCode) == "" {
		return nil
	}

	// Parse the Rego code into an AST to check for syntax errors
	_, err := ast.ParseModule(fmt.Sprintf("%s:%s", entityType, entityID), regoCode)
	if err != nil {
		return rv.formatRegoError(err, entityType, entityID)
	}

	return nil
}

// formatRegoError formats Rego compilation errors
func (rv *RegoValidator) formatRegoError(err error, entityType, entityID string) error {
	errorMsg := err.Error()

	cleanedMsg := rv.cleanupRegoErrorMessage(errorMsg)

	return fmt.Errorf("rego compilation failed in %s '%s': %s", entityType, entityID, cleanedMsg)
}

// cleanupRegoErrorMessage makes OPA error messages more readable
func (rv *RegoValidator) cleanupRegoErrorMessage(errorMsg string) string {
	cleaned := errorMsg

	replacements := map[string]string{
		"rego_parse_error: ":   "",
		"rego_compile_error: ": "",
		"rego_type_error: ":    "",
	}

	for old, new := range replacements {
		cleaned = strings.ReplaceAll(cleaned, old, new)
	}

	return cleaned
}

// ValidateDomainRego validates all Rego code in a domain
func (rv *RegoValidator) ValidateDomainRego(domainName string, model DomainModel, errors *Errors) {
	// Validate policy library Rego
	libraries := model.GetPolicyLibraries()
	for libID, library := range libraries {
		if err := rv.ValidateRegoCode(library.GetRego(), "library", libID); err != nil {
			errors.Add(&Error{
				Domain:   domainName,
				Type:     "rego",
				Entity:   "library",
				EntityID: libID,
				Field:    "rego",
				Message:  err.Error(),
			})
		}
	}

	// Validate policy Rego
	policies := model.GetPolicies()
	for policyID, policy := range policies {
		if err := rv.ValidateRegoCode(policy.GetRego(), "policy", policyID); err != nil {
			errors.Add(&Error{
				Domain:   domainName,
				Type:     "rego",
				Entity:   "policy",
				EntityID: policyID,
				Field:    "rego",
				Message:  err.Error(),
			})
		}
	}

	// Validate mapper Rego
	mappers := model.GetMappers()
	for i, mapper := range mappers {
		mapperID := mapper.GetID()
		if mapperID == "" {
			mapperID = fmt.Sprintf("mapper[%d]", i) // Fallback if no ID
		}
		if err := rv.ValidateRegoCode(mapper.GetRego(), "mapper", mapperID); err != nil {
			errors.Add(&Error{
				Domain:   domainName,
				Type:     "rego",
				Entity:   "mapper",
				EntityID: mapperID,
				Field:    "rego",
				Message:  err.Error(),
			})
		}
	}
}

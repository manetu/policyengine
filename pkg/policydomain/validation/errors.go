//
//  Copyright © Manetu Inc. All rights reserved.
//

package validation

import (
	"fmt"
	"strings"
)

// Error represents a single validation error with context
type Error struct {
	Domain   string
	Type     string
	Entity   string
	EntityID string
	Field    string
	Message  string
	Cause    error
}

// Error implements the error interface
func (ve *Error) Error() string {
	parts := []string{}

	if ve.Domain != "" {
		parts = append(parts, fmt.Sprintf("domain '%s'", ve.Domain))
	}

	if ve.Entity != "" && ve.EntityID != "" {
		parts = append(parts, fmt.Sprintf("%s '%s'", ve.Entity, ve.EntityID))
	}

	if ve.Field != "" {
		parts = append(parts, fmt.Sprintf("field '%s'", ve.Field))
	}

	context := ""
	if len(parts) > 0 {
		context = "in " + strings.Join(parts, " ") + ": "
	}

	return context + ve.Message
}

// Errors represents a collection of validation errors
type Errors struct {
	Errors []*Error
}

// NewValidationErrors creates a new validation errors collection
func NewValidationErrors() *Errors {
	return &Errors{
		Errors: make([]*Error, 0),
	}
}

// Add adds a validation error to the collection
func (ve *Errors) Add(err *Error) {
	ve.Errors = append(ve.Errors, err)
}

// AddError adds a validation error with all fields
func (ve *Errors) AddError(errorType, domain, entityType, entityID, field, message string) {
	ve.Add(&Error{
		Type:     errorType,
		Domain:   domain,
		Entity:   entityType,
		EntityID: entityID,
		Field:    field,
		Message:  message,
	})
}

// AddReferenceError adds a reference validation error
func (ve *Errors) AddReferenceError(domain, entityType, entityID, field, message string) {
	ve.AddError("reference", domain, entityType, entityID, field, message)
}

// AddCycleError adds a cycle detection error
func (ve *Errors) AddCycleError(message string) {
	ve.AddError("cycle", "", "", "", "", message)
}

// AddRegoError adds a rego compilation error
func (ve *Errors) AddRegoError(domain, entityType, entityID, message string) {
	ve.AddError("rego", domain, entityType, entityID, "rego", message)
}

// HasErrors returns true if there are any validation errors
func (ve *Errors) HasErrors() bool {
	return len(ve.Errors) > 0
}

// Count returns the number of validation errors
func (ve *Errors) Count() int {
	return len(ve.Errors)
}

// Error implements the error interface for the collection
func (ve *Errors) Error() string {
	if len(ve.Errors) == 0 {
		return "no validation errors"
	}

	if len(ve.Errors) == 1 {
		return ve.Errors[0].Error()
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("validation failed with %d errors:\n", len(ve.Errors)))

	for i, err := range ve.Errors {
		// Include type information in the error output
		typeInfo := ""
		if err.Type != "" {
			typeInfo = fmt.Sprintf("[%s] ", err.Type)
		}
		sb.WriteString(fmt.Sprintf("  %d. %s%s\n", i+1, typeInfo, err.Error()))
	}

	return sb.String()
}

// ErrorsByDomain groups errors by domain
func (ve *Errors) ErrorsByDomain() map[string][]*Error {
	byDomain := make(map[string][]*Error)

	for _, err := range ve.Errors {
		domain := err.Domain
		if domain == "" {
			domain = "unknown"
		}
		byDomain[domain] = append(byDomain[domain], err)
	}

	return byDomain
}

// ErrorsByType groups errors by validation type
func (ve *Errors) ErrorsByType() map[string][]*Error {
	byType := make(map[string][]*Error)

	for _, err := range ve.Errors {
		errType := err.Type
		if errType == "" {
			errType = "unknown"
		}
		byType[errType] = append(byType[errType], err)
	}

	return byType
}

// Summary provides a concise summary of validation errors
func (ve *Errors) Summary() string {
	if len(ve.Errors) == 0 {
		return "No validation errors"
	}

	byDomain := ve.ErrorsByDomain()
	byType := ve.ErrorsByType()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Validation Summary: %d errors found\n", len(ve.Errors)))

	sb.WriteString("\nBy Domain:\n")
	for domain, errors := range byDomain {
		sb.WriteString(fmt.Sprintf("  %s: %d errors\n", domain, len(errors)))
	}

	sb.WriteString("\nBy Type:\n")
	for errType, errors := range byType {
		sb.WriteString(fmt.Sprintf("  %s: %d errors\n", errType, len(errors)))
	}

	return sb.String()
}

// First returns the first error
func (ve *Errors) First() error {
	if len(ve.Errors) == 0 {
		return nil
	}
	return ve.Errors[0]
}

// ToSlice returns the errors as a slice of regular errors
func (ve *Errors) ToSlice() []error {
	errors := make([]error, len(ve.Errors))
	for i, err := range ve.Errors {
		errors[i] = err
	}
	return errors
}

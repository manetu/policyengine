//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"github.com/manetu/policyengine/pkg/policydomain/validation"
)

// convertValidationErrors converts validation.Error slice (reference/cycle errors)
// to Diagnostics. File path is looked up via domainFileMap.
// Line/column are not available for these error types (zero = unknown).
func convertValidationErrors(errs []*validation.Error, domainFileMap map[string]string) []Diagnostic {
	if len(errs) == 0 {
		return nil
	}

	diagnostics := make([]Diagnostic, 0, len(errs))
	for _, e := range errs {
		d := Diagnostic{
			Severity: SeverityError,
			Entity: Entity{
				Domain: e.Domain,
				Type:   e.Entity,
				ID:     e.EntityID,
				Field:  e.Field,
			},
			Message: e.Message,
		}

		switch e.Type {
		case "reference":
			d.Source = SourceReference
		case "cycle":
			d.Source = SourceCycle
		case "rego":
			// Rego parse errors from the validation layer lack line info;
			// richer diagnostics come from lintRegoAST in Phase 3.
			d.Source = SourceRego
		default:
			d.Source = SourceReference
		}

		if file := domainFileMap[e.Domain]; file != "" {
			d.Location.File = file
		}

		diagnostics = append(diagnostics, d)
	}

	return diagnostics
}

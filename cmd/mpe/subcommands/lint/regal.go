//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/regal/pkg/linter"
	"github.com/open-policy-agent/regal/pkg/report"
	"github.com/open-policy-agent/regal/pkg/rules"

	"github.com/manetu/policyengine/pkg/policydomain/parsers"
)

// performRegalLinting runs Regal lint on all embedded Rego code extracted from the given files.
// It uses the Regal Go library directly instead of shelling out to the regal CLI.
// Returns the number of violations found.
func performRegalLinting(ctx context.Context, files []string) int {
	// fileToEntityMap maps synthetic filenames to "sourceFile:entityType:entityID"
	fileToEntityMap := make(map[string]string)
	// regoFiles maps synthetic filenames to their Rego content
	regoFiles := make(map[string]string)

	for _, file := range files {
		domain, err := parsers.Load(file)
		if err != nil {
			continue
		}

		for libID, library := range domain.PolicyLibraries {
			if strings.TrimSpace(library.Rego) != "" {
				syntheticName := syntheticFileName(file, "library", libID)
				regoFiles[syntheticName] = library.Rego
				fileToEntityMap[syntheticName] = fmt.Sprintf("%s:library:%s", file, libID)
			}
		}

		for policyID, policy := range domain.Policies {
			if strings.TrimSpace(policy.Rego) != "" {
				syntheticName := syntheticFileName(file, "policy", policyID)
				regoFiles[syntheticName] = policy.Rego
				fileToEntityMap[syntheticName] = fmt.Sprintf("%s:policy:%s", file, policyID)
			}
		}

		for i, mapper := range domain.Mappers {
			if strings.TrimSpace(mapper.Rego) != "" {
				mapperID := mapper.IDSpec.ID
				if mapperID == "" {
					mapperID = fmt.Sprintf("mapper[%d]", i)
				}
				syntheticName := syntheticFileName(file, "mapper", mapperID)
				regoFiles[syntheticName] = mapper.Rego
				fileToEntityMap[syntheticName] = fmt.Sprintf("%s:mapper:%s", file, mapperID)
			}
		}
	}

	if len(regoFiles) == 0 {
		fmt.Println("No Rego code found to lint with Regal")
		return 0
	}

	return runRegalLint(ctx, regoFiles, fileToEntityMap)
}

// syntheticFileName creates a consistent synthetic filename for a Rego entity.
func syntheticFileName(sourceFile, entityType, entityID string) string {
	safeID := strings.ReplaceAll(entityID, ":", "_")
	safeID = strings.ReplaceAll(safeID, "/", "_")
	return fmt.Sprintf("%s_%s_%s.rego", sourceFile, entityType, safeID)
}

// runRegalLint uses the Regal Go library to lint the provided Rego files.
func runRegalLint(ctx context.Context, regoFiles map[string]string, fileToEntityMap map[string]string) int {
	input, err := rules.InputFromMap(regoFiles, nil)
	if err != nil {
		fmt.Printf("✗ Failed to parse Rego for Regal linting: %v\n", err)
		return 1
	}

	regalLinter := linter.NewLinter().WithInputModules(&input)

	regalReport, err := regalLinter.Lint(ctx)
	if err != nil {
		fmt.Printf("✗ Regal linting failed: %v\n", err)
		return 1
	}

	if len(regalReport.Violations) == 0 {
		return 0
	}

	for _, violation := range regalReport.Violations {
		entityInfo := fileToEntityMap[violation.Location.File]
		printRegalViolation(violation, entityInfo)
	}

	return len(regalReport.Violations)
}

// printRegalViolation formats and prints a single Regal violation.
func printRegalViolation(violation report.Violation, entityInfo string) {
	if entityInfo != "" {
		parts := strings.SplitN(entityInfo, ":", 3)
		if len(parts) == 3 {
			file, entityType, entityID := parts[0], parts[1], parts[2]
			fmt.Printf("✗ %s (Regal: %s in %s '%s' at line %d)\n", file, violation.Title, entityType, entityID, violation.Location.Row)
		} else {
			fmt.Printf("✗ Regal: %s at %s:%d:%d\n", violation.Title, violation.Location.File, violation.Location.Row, violation.Location.Column)
		}
	} else {
		fmt.Printf("✗ Regal: %s at %s:%d:%d\n", violation.Title, violation.Location.File, violation.Location.Row, violation.Location.Column)
	}

	fmt.Printf("  Category: %s | Level: %s\n", violation.Category, violation.Level)
	if violation.Description != "" {
		fmt.Printf("  Description: %s\n", violation.Description)
	}
	fmt.Println()
}

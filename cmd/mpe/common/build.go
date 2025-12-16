//
//  Copyright © Manetu Inc. All rights reserved.
//

package common

import (
	"fmt"
	"os"

	"github.com/manetu/policyengine/cmd/mpe/subcommands/build"
)

// AutoBuildReferenceFiles automatically detects and builds PolicyDomainReference files,
// returning a list of built output files and pass-through files.
func AutoBuildReferenceFiles(inputFiles []string) ([]string, error) {
	if len(inputFiles) == 0 {
		return inputFiles, nil
	}

	var referencesToBuild []string
	var passThrough []string
	var outputFiles []string

	// Categorize files
	for _, file := range inputFiles {
		isRef, err := build.IsPolicyDomainReference(file)
		if err != nil {
			return nil, fmt.Errorf("failed to check file type for '%s': %w", file, err)
		}

		if isRef {
			referencesToBuild = append(referencesToBuild, file)
		} else {
			passThrough = append(passThrough, file)
		}
	}

	// If there are reference files to build, show message and build them
	if len(referencesToBuild) > 0 {
		fmt.Fprintln(os.Stderr, "Detected PolicyDomainReference files, building...")

		for _, file := range referencesToBuild {
			result := build.File(file, "")
			if !result.Success {
				return nil, fmt.Errorf("failed to build '%s': %w", file, result.Error)
			}
			fmt.Fprintf(os.Stderr, "✓ %s → %s\n", result.InputFile, result.OutputFile)
			outputFiles = append(outputFiles, result.OutputFile)
		}

		fmt.Fprintln(os.Stderr)
	}

	// Combine built files and pass-through files
	finalFiles := append(outputFiles, passThrough...)

	return finalFiles, nil
}

//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/manetu/policyengine/cmd/mpe/common"
	"github.com/manetu/policyengine/pkg/policydomain/lint"
	"github.com/manetu/policyengine/pkg/policydomain/parsers"
	"github.com/urfave/cli/v3"
)

// Execute runs the lint command with the provided context and CLI command.
func Execute(ctx context.Context, cmd *cli.Command) error {
	files := cmd.StringSlice("file")
	if len(files) == 0 {
		return fmt.Errorf("no files specified, use --file/-f to specify YAML files to lint")
	}

	// Filter to supported file types up-front
	var yamlFiles []string
	for _, file := range files {
		ext := strings.ToLower(filepath.Ext(file))
		if ext != ".yml" && ext != ".yaml" {
			fmt.Printf("⚠ %s: Unsupported file type (only .yml, .yaml supported)\n\n", file)
			continue
		}
		yamlFiles = append(yamlFiles, file)
	}

	// Auto-build any PolicyDomainReference files
	processedFiles, err := common.AutoBuildReferenceFiles(yamlFiles)
	if err != nil {
		return err
	}

	// Determine OPA flags
	noOpaFlags := cmd.Bool("no-opa-flags")
	opaFlags := cmd.String("opa-flags")
	if noOpaFlags {
		opaFlags = ""
	} else if opaFlags == "" {
		opaFlags = os.Getenv("MPE_CLI_OPA_FLAGS")
		if opaFlags == "" {
			opaFlags = "--v0-compatible"
		}
	}

	opts := lint.Options{
		OPAFlags:    opaFlags,
		DisableOPA:  noOpaFlags,
		EnableRegal: cmd.Bool("regal"),
	}

	if opts.EnableRegal {
		fmt.Println("Running Regal linting...")
		fmt.Println()
	} else {
		fmt.Println("Linting YAML files...")
		fmt.Println()
	}

	result, err := lint.Lint(ctx, processedFiles, opts)
	if err != nil {
		return err
	}

	printResult(result, processedFiles, opts)

	if result.HasErrors() {
		return fmt.Errorf("linting failed: %d error(s)", result.ErrorCount())
	}

	fmt.Printf("All checks passed: %d file(s) validated successfully\n", len(processedFiles))
	return nil
}

// printResult formats and prints the lint result for terminal display.
// Reproduces the output format of the previous mpe lint implementation.
func printResult(result *lint.Result, files []string, opts lint.Options) {
	byFile := result.ByFile()

	// Print diagnostics grouped by file, preserving original file order
	printedFiles := make(map[string]bool)
	for _, file := range files {
		diags := byFile[file]
		for _, d := range diags {
			printDiagnostic(d)
		}
		if len(diags) > 0 {
			printedFiles[file] = true
		}
	}

	// Print any diagnostics without a mapped file
	for _, d := range byFile[""] {
		printDiagnostic(d)
	}

	fmt.Println("---")

	if opts.EnableRegal {
		violations := countSource(result.Diagnostics, lint.SourceRegal)
		if violations > 0 {
			fmt.Printf("Regal linting completed: %d violation(s)\n", violations)
			return
		}
		fmt.Printf("Regal linting passed: %d file(s) validated successfully\n", len(files))
		return
	}

	// Standard mode: show per-entity success for files with no errors
	for _, file := range files {
		if !printedFiles[file] {
			printFileSuccesses(file)
		}
	}
}

// printDiagnostic formats a single diagnostic for terminal output.
func printDiagnostic(d lint.Diagnostic) {
	file := d.Location.File
	if file == "" {
		file = "unknown"
	}

	switch d.Source {
	case lint.SourceYAML:
		fmt.Printf("✗ %s (YAML)\n", file)
		fmt.Printf("  Error: %s\n", d.Message)
		fmt.Println()

	case lint.SourceReference:
		fmt.Printf("✗ %s (%s)\n", file, d.Message)
		fmt.Println()

	case lint.SourceCycle:
		fmt.Printf("✗ %s (cycle: %s)\n", file, d.Message)
		fmt.Println()

	case lint.SourceRego:
		if d.Location.Start.Line > 0 {
			fmt.Printf("✗ %s (Rego in %s '%s' at line %d)\n", file, d.Entity.Type, d.Entity.ID, d.Location.Start.Line)
		} else {
			fmt.Printf("✗ %s (Rego in %s '%s')\n", file, d.Entity.Type, d.Entity.ID)
		}
		fmt.Printf("  Error: %s\n", d.Message)
		fmt.Println()

	case lint.SourceOPACheck:
		if d.Location.Start.Line > 0 {
			fmt.Printf("✗ %s (Rego in %s '%s' at line %d)\n", file, d.Entity.Type, d.Entity.ID, d.Location.Start.Line)
		} else {
			fmt.Printf("✗ %s (Rego in %s '%s')\n", file, d.Entity.Type, d.Entity.ID)
		}
		fmt.Printf("  OPA Check Error: %s\n", d.Message)
		fmt.Println()

	case lint.SourceRegal:
		if d.Location.Start.Line > 0 {
			fmt.Printf("✗ %s (Regal: %s in %s '%s' at line %d)\n",
				file, regalTitle(d), d.Entity.Type, d.Entity.ID, d.Location.Start.Line)
		} else {
			fmt.Printf("✗ %s (Regal: %s)\n", file, regalTitle(d))
		}
		if d.Category != "" {
			level := d.Severity.String()
			fmt.Printf("  Category: %s | Level: %s\n", d.Category, level)
		}
		if d.Message != "" {
			fmt.Printf("  Description: %s\n", d.Message)
		}
		fmt.Println()
	}
}

// regalTitle extracts just the rule title from a Regal diagnostic message
// (Message may be "title: description").
func regalTitle(d lint.Diagnostic) string {
	if idx := strings.Index(d.Message, ": "); idx >= 0 {
		return d.Message[:idx]
	}
	return d.Message
}

// printFileSuccesses prints ✓ lines for each Rego entity in a file that had no errors.
func printFileSuccesses(file string) {
	from, err := parsers.Load(file)
	if err != nil {
		fmt.Printf("✓ %s: Valid YAML\n", file)
		return
	}
	for libID, library := range from.PolicyLibraries {
		if strings.TrimSpace(library.Rego) != "" {
			fmt.Printf("✓ %s: Valid Rego in library '%s'\n", file, libID)
		}
	}
	for policyID, policy := range from.Policies {
		if strings.TrimSpace(policy.Rego) != "" {
			fmt.Printf("✓ %s: Valid Rego in policy '%s'\n", file, policyID)
		}
	}
	for i, mapper := range from.Mappers {
		if strings.TrimSpace(mapper.Rego) != "" {
			mapperID := mapper.IDSpec.ID
			if mapperID == "" {
				mapperID = fmt.Sprintf("mapper[%d]", i)
			}
			fmt.Printf("✓ %s: Valid Rego in mapper '%s'\n", file, mapperID)
		}
	}
}

// countSource counts diagnostics from a specific source.
func countSource(diagnostics []lint.Diagnostic, source lint.Source) int {
	n := 0
	for _, d := range diagnostics {
		if d.Source == source {
			n++
		}
	}
	return n
}

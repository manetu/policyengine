//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/manetu/policyengine/cmd/mpe/common"
	"github.com/manetu/policyengine/pkg/policydomain"
	"github.com/manetu/policyengine/pkg/policydomain/parsers"
	"github.com/manetu/policyengine/pkg/policydomain/registry"
	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

// Result represents the outcome of a lint operation on a file.
type Result struct {
	File    string
	Valid   bool
	Error   error
	Message string
	Type    string // "yaml" or "rego"
}

// RegoResult represents the outcome of a Rego lint operation.
type RegoResult struct {
	File     string // the file path
	Source   string // "policy", "library", "mapper", or "file"
	ID       string // entity ID or filename
	Valid    bool
	Error    error
	Message  string
	RegoCode string // the actual rego code that was linted
}

// Execute runs the lint command with the provided context and CLI command.
func Execute(ctx context.Context, cmd *cli.Command) error {
	files := cmd.StringSlice("file")
	if len(files) == 0 {
		return fmt.Errorf("no files specified, use --file/-f to specify YAML files to lint")
	}

	// Auto-build any PolicyDomainReference files
	processedFiles, err := common.AutoBuildReferenceFiles(files)
	if err != nil {
		return err
	}
	files = processedFiles

	// Get OPA flags from command line, environment variable, or use default
	noOpaFlags := cmd.Bool("no-opa-flags")
	opaFlags := cmd.String("opa-flags")

	if noOpaFlags {
		// Explicitly disable all OPA flags
		opaFlags = ""
	} else if opaFlags == "" {
		// Check environment variable
		opaFlags = os.Getenv("MPE_CLI_OPA_FLAGS")
		if opaFlags == "" {
			// Use default
			opaFlags = "--v0-compatible"
		}
	}

	fmt.Println("Linting YAML files...")
	fmt.Println()

	hasYamlErrors := 0
	for _, file := range files {
		ext := strings.ToLower(filepath.Ext(file))
		if ext != ".yml" && ext != ".yaml" {
			fmt.Printf("⚠ %s: Unsupported file type (only .yml, .yaml supported)\n\n", file)
			continue
		}

		yamlResult := lintFile(file)
		if !yamlResult.Valid {
			hasYamlErrors++
			fmt.Printf("✗ %s (YAML)\n", file)
			if yamlResult.Error != nil {
				fmt.Printf("  Error: %s\n", formatYAMLError(yamlResult.Error))
			} else {
				fmt.Printf("  Error: %s\n", yamlResult.Message)
			}
			fmt.Println()
		} else {
			fmt.Printf("✓ %s: Valid YAML\n", file)
		}
	}

	if hasYamlErrors > 0 {
		fmt.Println("---")
		fmt.Printf("Linting completed: %d file(s) with YAML errors\n", hasYamlErrors)
		return fmt.Errorf("linting failed: %d file(s) with YAML errors", hasYamlErrors)
	}

	regoErrors := lintRegoUsingExistingValidation(files, opaFlags)

	fmt.Println("---")
	if regoErrors > 0 {
		fmt.Printf("Linting completed: %d file(s) with errors\n", regoErrors)
		return fmt.Errorf("linting failed: %d file(s) with errors", regoErrors)
	}

	fmt.Printf("All checks passed: %d file(s) validated successfully\n", len(files))
	return nil
}

func lintRegoUsingExistingValidation(files []string, opaFlags string) int {
	registry, err := registry.NewRegistry(files)
	if err != nil {
		// Backend creation failed - this means validation failed
		fmt.Printf("✗ Bundle validation failed: %s\n", err.Error())
		return 1
	}

	validationErrors := registry.GetAllValidationErrors()

	domainToFileMap := make(map[string]string)
	for _, file := range files {
		if domain, err := parsers.Load(file); err == nil {
			domainToFileMap[domain.Name] = file
		}
	}

	// Track errors
	errorCount := 0

	// Process validation errors
	for _, validationError := range validationErrors {
		file := domainToFileMap[validationError.Domain]
		if file == "" {
			file = "unknown"
		}

		switch validationError.Type {
		case "rego":
			// Rego compilation error
			fmt.Printf("✗ %s (Rego in %s '%s')\n", file, validationError.Entity, validationError.EntityID)
			fmt.Printf("  Error: %s\n", validationError.Message)
			fmt.Println()
			errorCount++
		case "reference":
			// Cross-domain reference error - this affects the whole bundle
			fmt.Printf("✗ %s (%s)\n", file, validationError.Message)
			fmt.Println()
			errorCount++
		}
	}

	if errorCount == 0 {
		opaErrors := performOpaCheckLinting(files, opaFlags)
		errorCount += opaErrors

		if opaErrors == 0 {
			for _, file := range files {
				if domain, err := parsers.Load(file); err == nil {
					// Show success for libraries
					for libID, library := range domain.PolicyLibraries {
						if strings.TrimSpace(library.Rego) != "" {
							fmt.Printf("✓ %s: Valid Rego in library '%s'\n", file, libID)
						}
					}
					// Show success for policies
					for policyID, policy := range domain.Policies {
						if strings.TrimSpace(policy.Rego) != "" {
							fmt.Printf("✓ %s: Valid Rego in policy '%s'\n", file, policyID)
						}
					}
					// Show success for mappers
					for i, mapper := range domain.Mappers {
						if strings.TrimSpace(mapper.Rego) != "" {
							mapperID := mapper.IDSpec.ID
							if mapperID == "" {
								mapperID = fmt.Sprintf("mapper[%d]", i)
							}
							fmt.Printf("✓ %s: Valid Rego in mapper '%s'\n", file, mapperID)
						}
					}
				}
			}
		}
	}

	return errorCount
}

func lintFile(filepath string) Result {
	result := Result{
		File:  filepath,
		Valid: true,
		Type:  "yaml",
	}

	// Read file
	content, err := os.ReadFile(filepath) // #nosec G304 -- CLI tool intentionally reads user-provided paths
	if err != nil {
		result.Valid = false
		result.Message = fmt.Sprintf("Failed to read file: %v", err)
		return result
	}

	// Try to parse the YAML
	var data interface{}
	err = yaml.Unmarshal(content, &data)
	if err != nil {
		result.Valid = false
		result.Error = err
		return result
	}

	return result
}

func performOpaCheckLinting(files []string, opaFlags string) int {

	tmpDir, err := os.MkdirTemp("", "rego-lint-*")
	if err != nil {
		fmt.Printf("✗ Failed to create temporary directory for opa check: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	reg, err := registry.NewRegistry(files)
	if err != nil {
		fmt.Printf("✗ Failed to create registry for opa check: %v\n", err)
		return 1
	}

	errorCount := 0

	errorCount += lintAllLibraries(files, tmpDir, reg, opaFlags)

	errorCount += lintPoliciesWithDependencies(files, tmpDir, reg, opaFlags)

	errorCount += lintMappersWithDependencies(files, tmpDir, reg, opaFlags)

	return errorCount
}

func lintAllLibraries(files []string, tmpDir string, reg *registry.Registry, opaFlags string) int {
	var libraryFiles []string
	fileToEntityMap := make(map[string]string)

	// Collect all libraries from all domains
	for _, file := range files {
		domain, err := parsers.Load(file)
		if err != nil {
			continue
		}

		for libID, library := range domain.PolicyLibraries {
			if strings.TrimSpace(library.Rego) != "" {
				tempFile := writeRegoToTempFile(tmpDir, file, "library", libID, library.Rego)
				if tempFile != "" {
					libraryFiles = append(libraryFiles, tempFile)
					fileToEntityMap[filepath.Base(tempFile)] = fmt.Sprintf("%s:library:%s", file, libID)
				}
			}
		}
	}

	if len(libraryFiles) == 0 {
		return 0
	}

	// Run opa check on all libraries together
	return runOpaCheckOnFiles(libraryFiles, fileToEntityMap, tmpDir, opaFlags)
}

func lintPoliciesWithDependencies(files []string, tmpDir string, reg *registry.Registry, opaFlags string) int {
	errorCount := 0

	for _, file := range files {
		domain, err := parsers.Load(file)
		if err != nil {
			continue
		}

		for policyID, policy := range domain.Policies {
			if strings.TrimSpace(policy.Rego) != "" {
				errors := lintPolicyWithDeps(file, domain, policyID, policy, tmpDir, reg, opaFlags)
				errorCount += errors
			}
		}
	}

	return errorCount
}

func lintMappersWithDependencies(files []string, tmpDir string, reg *registry.Registry, opaFlags string) int {
	errorCount := 0

	for _, file := range files {
		domain, err := parsers.Load(file)
		if err != nil {
			continue
		}

		for i, mapper := range domain.Mappers {
			if strings.TrimSpace(mapper.Rego) != "" {
				mapperID := mapper.IDSpec.ID
				if mapperID == "" {
					mapperID = fmt.Sprintf("mapper[%d]", i)
				}
				errors := lintMapperWithDeps(file, domain, mapperID, mapper, tmpDir, reg, opaFlags)
				errorCount += errors
			}
		}
	}

	return errorCount
}

func lintPolicyWithDeps(file string, domainModel *policydomain.IntermediateModel, policyID string, policy policydomain.Policy, tmpDir string, reg *registry.Registry, opaFlags string) int {
	var filesToCheck []string
	fileToEntityMap := make(map[string]string)

	// Add the policy itself
	policyFile := writeRegoToTempFile(tmpDir, file, "policy", policyID, policy.Rego)
	if policyFile == "" {
		return 0
	}
	filesToCheck = append(filesToCheck, policyFile)
	fileToEntityMap[filepath.Base(policyFile)] = fmt.Sprintf("%s:policy:%s", file, policyID)

	resolvedDeps, err := reg.ResolveDependencies(domainModel, policy.Dependencies)
	if err != nil {
		// Dependency resolution failed - this should have been caught earlier
		return 0
	}

	domains := reg.GetDomains()
	for _, depRef := range resolvedDeps {
		depDomainName, depLibID := parseDependencyReference(depRef, domainModel.Name)
		depDomainModel := domains[depDomainName]
		if depDomainModel != nil {
			if lib, ok := depDomainModel.PolicyLibraries[depLibID]; ok {
				if strings.TrimSpace(lib.Rego) != "" {
					libFile := writeRegoToTempFile(tmpDir, file, "library", depLibID, lib.Rego)
					if libFile != "" {
						filesToCheck = append(filesToCheck, libFile)
						fileToEntityMap[filepath.Base(libFile)] = fmt.Sprintf("%s:library:%s", file, depLibID)
					}
				}
			}
		}
	}

	return runOpaCheckOnFiles(filesToCheck, fileToEntityMap, tmpDir, opaFlags)
}

func lintMapperWithDeps(file string, domainModel *policydomain.IntermediateModel, mapperID string, mapper policydomain.Mapper, tmpDir string, reg *registry.Registry, opaFlags string) int {
	var filesToCheck []string
	fileToEntityMap := make(map[string]string)

	// Add the mapper itself (mappers don't have dependencies in this system)
	mapperFile := writeRegoToTempFile(tmpDir, file, "mapper", mapperID, mapper.Rego)
	if mapperFile == "" {
		return 0
	}
	filesToCheck = append(filesToCheck, mapperFile)
	fileToEntityMap[filepath.Base(mapperFile)] = fmt.Sprintf("%s:mapper:%s", file, mapperID)

	return runOpaCheckOnFiles(filesToCheck, fileToEntityMap, tmpDir, opaFlags)
}

func parseDependencyReference(ref, currentDomain string) (string, string) {
	// Check if it's a cross-domain reference (domain/libraryID)
	if strings.Contains(ref, "/") {
		parts := strings.SplitN(ref, "/", 2)
		return parts[0], parts[1]
	}
	// Otherwise it's in the current domain
	return currentDomain, ref
}

func runOpaCheckOnFiles(files []string, fileToEntityMap map[string]string, tmpDir string, opaFlags string) int {
	if len(files) == 0 {
		return 0
	}

	// Build the command arguments: opa check [flags] [files...]
	args := []string{"check"}

	// Add custom OPA flags if provided
	if opaFlags != "" {
		// Split the flags string by spaces to handle multiple flags
		flagParts := strings.Fields(opaFlags)
		args = append(args, flagParts...)
	}

	// Add the files to check
	args = append(args, files...)

	cmd := exec.Command("opa", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return parseOpaCheckOutput(string(output), fileToEntityMap, tmpDir)
	}

	return 0
}

func writeRegoToTempFile(tmpDir, sourceFile, entityType, entityID, regoCode string) string {
	// Create a safe filename
	safeID := strings.ReplaceAll(entityID, ":", "_")
	safeID = strings.ReplaceAll(safeID, "/", "_")
	safeFile := strings.ReplaceAll(filepath.Base(sourceFile), ".", "_")
	filename := fmt.Sprintf("%s_%s_%s.rego", safeFile, entityType, safeID)
	filePath := filepath.Join(tmpDir, filename)

	err := os.WriteFile(filePath, []byte(regoCode), 0600)
	if err != nil {
		fmt.Printf("✗ Failed to write temp file for %s %s: %v\n", entityType, entityID, err)
		return ""
	}

	return filePath
}

func parseOpaCheckOutput(output string, fileToEntityMap map[string]string, tmpDir string) int {
	errorCount := 0
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for file references in the error line
		foundError := false
		for tempFilename, entityInfo := range fileToEntityMap {
			fullPath := filepath.Join(tmpDir, tempFilename)
			if strings.Contains(line, fullPath) {
				// Parse entityInfo: "file:entityType:entityID"
				parts := strings.SplitN(entityInfo, ":", 3)
				if len(parts) == 3 {
					file, entityType, entityID := parts[0], parts[1], parts[2]

					// Clean up the error message
					cleanedLine := strings.ReplaceAll(line, fullPath, fmt.Sprintf("%s:%s", entityType, entityID))

					fmt.Printf("✗ %s (Rego in %s '%s')\n", file, entityType, entityID)
					fmt.Printf("  OPA Check Error: %s\n", cleanedLine)
					fmt.Println()
					errorCount++
					foundError = true
					break
				}
			}
		}

		// If we couldn't map the error to a specific entity, show generic error
		if !foundError && strings.Contains(line, tmpDir) {
			fmt.Printf("✗ OPA Check Error: %s\n", line)
			fmt.Println()
			errorCount++
		}
	}

	return errorCount
}

func formatYAMLError(err error) string {
	errStr := err.Error()
	if strings.Contains(errStr, "yaml:") {
		return errStr
	}

	if yamlErr, ok := err.(*yaml.TypeError); ok {
		if len(yamlErr.Errors) > 0 {
			return strings.Join(yamlErr.Errors, "\n  ")
		}
	}

	return errStr
}

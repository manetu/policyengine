//
//  Copyright © Manetu Inc. All rights reserved.
//

package build

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"
	"gopkg.in/yaml.v3"
)

// Result represents the outcome of a build operation.
type Result struct {
	InputFile  string
	OutputFile string
	Success    bool
	Error      error
}

// Execute runs the build command with the provided context and CLI command.
func Execute(ctx context.Context, cmd *cli.Command) error {
	files := cmd.StringSlice("file")
	if len(files) == 0 {
		return fmt.Errorf("no files specified, use --file/-f to specify PolicyDomainReference YAML files to build")
	}

	outputFile := cmd.String("output")

	// If multiple files but single output specified, that's an error
	if len(files) > 1 && outputFile != "" {
		return fmt.Errorf("cannot specify --output when building multiple files")
	}

	results := make([]Result, 0, len(files))
	hasErrors := false

	// Build all files
	for _, file := range files {
		result := File(file, outputFile)
		results = append(results, result)
		if !result.Success {
			hasErrors = true
		}
	}

	// Print results
	printResults(results)

	if hasErrors {
		return fmt.Errorf("build failed for one or more files")
	}

	return nil
}

func printResults(results []Result) {
	fmt.Println("Build Results:")
	fmt.Println()
	for _, result := range results {
		if result.Success {
			fmt.Printf("✓ %s → %s\n", result.InputFile, result.OutputFile)
		} else {
			fmt.Printf("✗ %s\n", result.InputFile)
			fmt.Printf("  Error: %s\n", result.Error)
		}
	}

	hasErrors := false
	for _, result := range results {
		if !result.Success {
			hasErrors = true
			break
		}
	}

	if !hasErrors {
		fmt.Println()
		fmt.Printf("Successfully built %d file(s)\n", len(results))
	} else {
		fmt.Println()
	}
}

// File builds a single policy domain file, reading rego_filename references and converting to PolicyDomain.
func File(inputFile, outputFile string) Result {
	result := Result{
		InputFile: inputFile,
		Success:   false,
	}

	if outputFile == "" {
		outputFile = generateOutputFilename(inputFile)
	}
	result.OutputFile = outputFile

	inputData, err := os.ReadFile(inputFile) // #nosec G304 -- CLI tool intentionally reads user-provided paths
	if err != nil {
		result.Error = fmt.Errorf("failed to read input file: %w", err)
		return result
	}

	var rootNode yaml.Node
	if err := yaml.Unmarshal(inputData, &rootNode); err != nil {
		result.Error = fmt.Errorf("failed to parse YAML: %w", err)
		return result
	}

	if err := processYAMLNode(&rootNode); err != nil {
		result.Error = err
		return result
	}

	if err := ensurePolicyDomainKind(&rootNode); err != nil {
		result.Error = err
		return result
	}

	outputData, err := yaml.Marshal(&rootNode)
	if err != nil {
		result.Error = fmt.Errorf("failed to marshal output YAML: %w", err)
		return result
	}

	if err := os.WriteFile(outputFile, outputData, 0600); err != nil {
		result.Error = fmt.Errorf("failed to write output file: %w", err)
		return result
	}

	result.Success = true
	return result
}

func generateOutputFilename(inputFile string) string {
	ext := filepath.Ext(inputFile)
	nameWithoutExt := strings.TrimSuffix(inputFile, ext)
	return nameWithoutExt + "-built" + ext
}

// IsPolicyDomainReference checks if a YAML file is a PolicyDomainReference by examining its kind field.
func IsPolicyDomainReference(filePath string) (bool, error) {
	data, err := os.ReadFile(filePath) // #nosec G304 -- CLI tool intentionally reads user-provided paths
	if err != nil {
		return false, fmt.Errorf("failed to read file: %w", err)
	}

	var doc struct {
		Kind string `yaml:"kind"`
	}

	if err := yaml.Unmarshal(data, &doc); err != nil {
		return false, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return doc.Kind == "PolicyDomainReference", nil
}

func processYAMLNode(node *yaml.Node) error {
	if node == nil {
		return nil
	}

	if node.Kind == yaml.DocumentNode {
		for _, child := range node.Content {
			if err := processYAMLNode(child); err != nil {
				return err
			}
		}
		return nil
	}

	if node.Kind == yaml.MappingNode {
		return processMappingNode(node)
	}

	if node.Kind == yaml.SequenceNode {
		for _, item := range node.Content {
			if err := processYAMLNode(item); err != nil {
				return err
			}
		}
		return nil
	}

	return nil
}

func processMappingNode(node *yaml.Node) error {
	if len(node.Content)%2 != 0 {
		return fmt.Errorf("invalid YAML mapping node")
	}

	hasRego := false
	hasRegoFilename := false
	var regoFilenameIndex int
	var regoFilenameValue string

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		if keyNode.Kind == yaml.ScalarNode {
			switch keyNode.Value {
			case "rego":
				hasRego = true
			case "rego_filename":
				hasRegoFilename = true
				regoFilenameIndex = i
				if valueNode.Kind == yaml.ScalarNode {
					regoFilenameValue = valueNode.Value
				}
			}
		}

		if err := processYAMLNode(valueNode); err != nil {
			return err
		}
	}

	if hasRego && hasRegoFilename {
		return fmt.Errorf("cannot specify both 'rego' and 'rego_filename' in the same block")
	}

	if hasRegoFilename {
		if regoFilenameValue == "" {
			return fmt.Errorf("rego_filename cannot be empty")
		}

		regoContent, err := readRegoFile(regoFilenameValue)
		if err != nil {
			return fmt.Errorf("failed to read rego file '%s': %w", regoFilenameValue, err)
		}

		keyNode := node.Content[regoFilenameIndex]
		keyNode.Value = "rego"

		valueNode := node.Content[regoFilenameIndex+1]

		trimmed := strings.TrimRight(regoContent, "\n")
		if trimmed != "" {
			valueNode.Value = trimmed + "\n"
		} else {
			valueNode.Value = ""
		}
		valueNode.Style = yaml.LiteralStyle
	}

	return nil
}

func readRegoFile(filename string) (string, error) {
	// Support both absolute and relative paths (relative to CWD)
	var filePath string
	if filepath.IsAbs(filename) {
		filePath = filename
	} else {
		// Relative to current working directory
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current working directory: %w", err)
		}
		filePath = filepath.Join(cwd, filename)
	}

	content, err := os.ReadFile(filePath) // #nosec G304 -- CLI tool intentionally reads user-provided paths
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("file not found: %s", filePath)
		}
		return "", err
	}

	return string(content), nil
}

func ensurePolicyDomainKind(node *yaml.Node) error {
	var rootMapping *yaml.Node
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		rootMapping = node.Content[0]
	} else if node.Kind == yaml.MappingNode {
		rootMapping = node
	} else {
		return nil
	}

	for i := 0; i < len(rootMapping.Content); i += 2 {
		keyNode := rootMapping.Content[i]
		valueNode := rootMapping.Content[i+1]

		if keyNode.Kind == yaml.ScalarNode && keyNode.Value == "kind" {
			if valueNode.Kind == yaml.ScalarNode {
				valueNode.Value = "PolicyDomain"
			}
			return nil
		}
	}

	return nil
}

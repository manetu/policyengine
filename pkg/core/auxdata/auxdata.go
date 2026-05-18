//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package auxdata provides functionality for loading auxiliary data from
// a directory of files. When mounted from a Kubernetes ConfigMap, each key
// in the ConfigMap becomes a file in the directory. The contents of each
// file are loaded as the value in a map keyed by filename.
//
// The loaded auxdata is merged into the mapper input under the "auxdata" key,
// making it accessible to Rego policies as input.auxdata.<filename>.
package auxdata

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadAuxData reads all files in the given directory and returns a map
// where each key is the filename (without path) and each value is the
// file's content as a string. Hidden files (starting with ".") are skipped.
//
// Returns nil if path is empty (auxdata not configured).
// Returns an error if the directory cannot be read or any file fails to read.
func LoadAuxData(path string) (map[string]interface{}, error) {
	if path == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read auxdata directory %s: %w", path, err)
	}

	result := make(map[string]interface{})
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Skip hidden files (e.g., Kubernetes ConfigMap metadata files)
		if strings.HasPrefix(name, ".") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(path, name)) // #nosec G304 -- intentionally reads from configured path
		if err != nil {
			return nil, fmt.Errorf("failed to read auxdata file %s: %w", name, err)
		}

		result[name] = string(data)
	}

	return result, nil
}

// MergeAuxData merges auxdata into the given input map under the "auxdata" key.
// If auxdata is nil or empty, the input is returned unchanged.
// If the input is a map[string]interface{}, auxdata is added as input["auxdata"].
// For other input types, the input is returned unchanged.
func MergeAuxData(input interface{}, auxdata map[string]interface{}) interface{} {
	if len(auxdata) == 0 {
		return input
	}

	if m, ok := input.(map[string]interface{}); ok {
		m["auxdata"] = auxdata
		return m
	}

	return input
}

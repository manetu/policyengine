//
//  Copyright © Manetu Inc. All rights reserved.
//

package lint

import (
	"fmt"
	"os"
)

// DataSource abstracts how lint obtains PolicyDomain YAML content.
// Implementations exist for file-system paths (FileSource) and in-memory
// strings (StringSource), allowing the core lint logic to be written once.
type DataSource interface {
	// Keys returns the logical identifiers for all items.
	// For FileSource these are file paths; for StringSource they are logical names.
	Keys() []string
	// Read returns the raw YAML bytes for the given key.
	Read(key string) ([]byte, error)
}

// FileSource reads PolicyDomain YAML from the filesystem.
// Keys are file paths.
type FileSource struct{ Paths []string }

func (fs FileSource) Keys() []string { return fs.Paths }
func (fs FileSource) Read(key string) ([]byte, error) {
	return os.ReadFile(key) // #nosec G304 -- linting tool intentionally reads user-provided paths
}

// StringSource provides PolicyDomain YAML from in-memory strings.
// Keys are logical file names (e.g. "my-domain.yaml").
type StringSource struct{ Files map[string]string }

func (ss StringSource) Keys() []string {
	keys := make([]string, 0, len(ss.Files))
	for k := range ss.Files {
		keys = append(keys, k)
	}
	return keys
}

func (ss StringSource) Read(key string) ([]byte, error) {
	if s, ok := ss.Files[key]; ok {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("key %q not found in source", key)
}

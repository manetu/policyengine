//
//  Copyright © Manetu Inc. All rights reserved.
//

package parsers

import (
	"fmt"
	"os"

	"github.com/manetu/policyengine/pkg/policydomain"
	"github.com/manetu/policyengine/pkg/policydomain/parsers/v1alpha3"
	"github.com/manetu/policyengine/pkg/policydomain/parsers/v1alpha4"
	"github.com/manetu/policyengine/pkg/policydomain/parsers/v1beta1"

	"gopkg.in/yaml.v3"
)

// Preamble represents the header information of a policy domain file
type Preamble struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

// LoadFromBytes loads a policy domain from raw YAML bytes.
// The name parameter is used only for error messages.
func LoadFromBytes(name string, data []byte) (*policydomain.IntermediateModel, error) {
	var preamble Preamble
	if err := yaml.Unmarshal(data, &preamble); err != nil {
		return nil, err
	}

	if preamble.Kind != "PolicyDomain" {
		return nil, fmt.Errorf("expected PolicyDomain got %s", preamble.Kind)
	}

	switch preamble.APIVersion {
	case "iamlite.manetu.io/v1alpha3":
		return v1alpha3.LoadFromBytes(data)
	case "iamlite.manetu.io/v1alpha4":
		return v1alpha4.LoadFromBytes(data)
	case "iamlite.manetu.io/v1beta1":
		return v1beta1.LoadFromBytes(data)
	}

	return nil, fmt.Errorf("unsupported PolicyDomain API Version %s", preamble.APIVersion)
}

// Load loads a policy domain from a file path.
func Load(path string) (*policydomain.IntermediateModel, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- CLI tool intentionally reads user-provided paths
	if err != nil {
		return nil, err
	}
	return LoadFromBytes(path, data)
}

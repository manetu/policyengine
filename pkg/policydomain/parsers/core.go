//
//  Copyright © Manetu Inc. All rights reserved.
//

package parsers

import (
	"fmt"
	"io"
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

// Load loads a policy domain from a file path
func Load(path string) (*policydomain.IntermediateModel, error) {
	f, err := os.Open(path) // #nosec G304 -- CLI tool intentionally reads user-provided paths
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var preamble Preamble

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &preamble)
	if err != nil {
		return nil, err
	}

	if preamble.Kind != "PolicyDomain" {
		return nil, fmt.Errorf("expected PolicyDomain got %s", preamble.Kind)
	}

	switch preamble.APIVersion {
	case "iamlite.manetu.io/v1alpha3":
		return v1alpha3.Load(path)
	case "iamlite.manetu.io/v1alpha4":
		return v1alpha4.Load(path)
	case "iamlite.manetu.io/v1beta1":
		return v1beta1.Load(path)
	}

	return nil, fmt.Errorf("unsupported PolicyDomain API Version %s", preamble.APIVersion)
}

//
//  Copyright © Manetu Inc. All rights reserved.
//

package v1alpha4

import (
	"crypto/sha256"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/manetu/policyengine/pkg/policydomain"

	"gopkg.in/yaml.v3"
)

// PolicyDefinition represents a policy definition in v1alpha4 format
type PolicyDefinition struct {
	Mrn          string   `yaml:"mrn"`
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	Rego         string   `yaml:"rego"`
	Dependencies []string `yaml:"dependencies"`
}

// Annotation represents a key-value annotation with optional merge strategy
type Annotation struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
	Merge string `yaml:"merge,omitempty"` // "replace", "append", "prepend", "deep", "union"
}

// AnnotationDefaults contains default settings for annotation merging
type AnnotationDefaults struct {
	Merge string `yaml:"merge,omitempty"` // Default merge strategy
}

// PolicyReference represents a reference to a policy in v1alpha4 format
type PolicyReference struct {
	Mrn         string       `yaml:"mrn"`
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Default     bool         `yaml:"default"`
	Policy      string       `yaml:"policy"`
	Annotations []Annotation `yaml:"annotations"`
}

// Group represents a group with roles in v1alpha4 format
type Group struct {
	Mrn         string       `yaml:"mrn"`
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Roles       []string     `yaml:"roles"`
	Annotations []Annotation `yaml:"annotations"`
}

// Operation represents an operation in v1alpha4 format
type Operation struct {
	Name     string   `yaml:"name"`
	Selector []string `yaml:"selector"`
	Policy   string   `yaml:"policy"`
}

// Mapper represents a mapper in v1alpha4 format
type Mapper struct {
	Name     string   `yaml:"name"`
	Selector []string `yaml:"selector"`
	Rego     string   `yaml:"rego"`
}

// Resource represents a resource in v1alpha4 format
type Resource struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Selector    []string     `yaml:"selector"`
	Group       string       `yaml:"group"`
	Annotations []Annotation `yaml:"annotations"`
}

func exportDefinition(def PolicyDefinition) policydomain.Policy {
	fingerprint := sha256.Sum256([]byte(def.Rego))
	return policydomain.Policy{
		IDSpec: policydomain.IDSpec{
			ID:          def.Mrn,
			Fingerprint: fingerprint[:],
		},
		Dependencies: def.Dependencies,
		Rego:         def.Rego,
	}
}

func exportDefinitions(defs []PolicyDefinition) map[string]policydomain.Policy {
	policies := make(map[string]policydomain.Policy, 0)
	for _, def := range defs {
		policies[def.Mrn] = exportDefinition(def)
	}

	return policies
}

func exportReference(def PolicyReference) policydomain.PolicyReference {
	annotations := make(map[string]policydomain.Annotation)
	for _, ann := range def.Annotations {
		annotations[ann.Name] = policydomain.Annotation{
			Value:         ann.Value,
			MergeStrategy: ann.Merge,
		}
	}
	return policydomain.PolicyReference{
		IDSpec: policydomain.IDSpec{
			ID: def.Mrn,
		},
		Policy:      def.Policy,
		Default:     def.Default,
		Annotations: annotations,
	}
}

func exportReferences(defs []PolicyReference) map[string]policydomain.PolicyReference {
	refs := make(map[string]policydomain.PolicyReference, 0)
	for _, def := range defs {
		refs[def.Mrn] = exportReference(def)
	}

	return refs
}

func exportGroup(def Group) policydomain.Group {
	annotations := make(map[string]policydomain.Annotation)
	for _, ann := range def.Annotations {
		annotations[ann.Name] = policydomain.Annotation{
			Value:         ann.Value,
			MergeStrategy: ann.Merge,
		}
	}
	return policydomain.Group{
		IDSpec: policydomain.IDSpec{
			ID: def.Mrn,
		},
		Roles:       def.Roles,
		Annotations: annotations,
	}
}

func exportGroups(defs []Group) map[string]policydomain.Group {
	refs := make(map[string]policydomain.Group, 0)
	for _, def := range defs {
		refs[def.Mrn] = exportGroup(def)
	}

	return refs
}

func anchorPattern(pattern string) string {
	hasStartAnchor := strings.HasPrefix(pattern, "^")
	hasEndAnchor := strings.HasSuffix(pattern, "$")

	result := pattern
	if !hasStartAnchor {
		result = "^" + result
	}
	if !hasEndAnchor {
		result = result + "$"
	}
	return result
}

func exportOperation(def Operation) (*policydomain.Operation, error) {
	selectors := make([]*regexp.Regexp, 0)
	for _, selector := range def.Selector {
		anchoredPattern := anchorPattern(selector)
		r, err := regexp.Compile(anchoredPattern)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, r)
	}

	return &policydomain.Operation{
		IDSpec: policydomain.IDSpec{
			ID: def.Name,
		},
		Selectors: selectors,
		Policy:    def.Policy,
	}, nil
}

func exportOperations(defs []Operation) ([]policydomain.Operation, error) {
	operations := make([]policydomain.Operation, 0)
	for _, def := range defs {
		operation, err := exportOperation(def)
		if err != nil {
			return nil, err
		}
		operations = append(operations, *operation)
	}

	return operations, nil
}

func exportMapper(def Mapper) (*policydomain.Mapper, error) {
	selectors := make([]*regexp.Regexp, 0)
	for _, selector := range def.Selector {
		anchoredPattern := anchorPattern(selector)
		r, err := regexp.Compile(anchoredPattern)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, r)
	}

	// Create fingerprint for the mapper's rego code
	fingerprint := sha256.Sum256([]byte(def.Rego))

	return &policydomain.Mapper{
		IDSpec: policydomain.IDSpec{
			ID:          def.Name,
			Fingerprint: fingerprint[:],
		},
		Selectors: selectors,
		Rego:      def.Rego,
	}, nil
}

func exportMappers(defs []Mapper) ([]policydomain.Mapper, error) {
	mappers := make([]policydomain.Mapper, 0)
	for _, def := range defs {
		mapper, err := exportMapper(def)
		if err != nil {
			return nil, err
		}
		mappers = append(mappers, *mapper)
	}

	return mappers, nil
}

func exportResource(def Resource) (*policydomain.Resource, error) {
	selectors := make([]*regexp.Regexp, 0)
	for _, selector := range def.Selector {
		anchoredPattern := anchorPattern(selector)
		r, err := regexp.Compile(anchoredPattern)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, r)
	}

	annotations := make(map[string]policydomain.Annotation)
	for _, ann := range def.Annotations {
		annotations[ann.Name] = policydomain.Annotation{
			Value:         ann.Value,
			MergeStrategy: ann.Merge,
		}
	}

	return &policydomain.Resource{
		IDSpec: policydomain.IDSpec{
			ID: def.Name,
		},
		Selectors:   selectors,
		Group:       def.Group,
		Annotations: annotations,
	}, nil
}

func exportResources(defs []Resource) ([]policydomain.Resource, error) {
	resources := make([]policydomain.Resource, 0)
	for _, def := range defs {
		resource, err := exportResource(def)
		if err != nil {
			return nil, err
		}
		resources = append(resources, *resource)
	}

	return resources, nil
}

// IntermediateModel represents the intermediate v1alpha4 YAML structure
type IntermediateModel struct {
	Metadata struct {
		Name string `yaml:"name"`
	}
	Spec struct {
		AnnotationDefaults AnnotationDefaults `yaml:"annotation-defaults"`
		PolicyLibraries    []PolicyDefinition `yaml:"policy-libraries"`
		Policies           []PolicyDefinition `yaml:"policies"`
		Roles              []PolicyReference  `yaml:"roles"`
		Groups             []Group            `yaml:"groups"`
		ResourceGroups     []PolicyReference  `yaml:"resource-groups"`
		Scopes             []PolicyReference  `yaml:"scopes"`
		Operations         []Operation        `yaml:"operations"`
		Mappers            []Mapper           `yaml:"mappers"`
		Resources          []Resource         `yaml:"resources"`
	}
}

// Load loads a v1alpha4 policy domain from a file path
func Load(path string) (*policydomain.IntermediateModel, error) {
	f, err := os.Open(path) // #nosec G304 -- CLI tool intentionally reads user-provided paths
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var intermediate IntermediateModel

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &intermediate)
	if err != nil {
		return nil, err
	}

	operations, err := exportOperations(intermediate.Spec.Operations)
	if err != nil {
		return nil, err
	}

	mappers, err := exportMappers(intermediate.Spec.Mappers)
	if err != nil {
		return nil, err
	}

	resources, err := exportResources(intermediate.Spec.Resources)
	if err != nil {
		return nil, err
	}

	return &policydomain.IntermediateModel{
		Name: intermediate.Metadata.Name,
		AnnotationDefaults: policydomain.AnnotationDefaults{
			MergeStrategy: intermediate.Spec.AnnotationDefaults.Merge,
		},
		PolicyLibraries: exportDefinitions(intermediate.Spec.PolicyLibraries),
		Policies:        exportDefinitions(intermediate.Spec.Policies),
		Roles:           exportReferences(intermediate.Spec.Roles),
		Groups:          exportGroups(intermediate.Spec.Groups),
		ResourceGroups:  exportReferences(intermediate.Spec.ResourceGroups),
		Scopes:          exportReferences(intermediate.Spec.Scopes),
		Operations:      operations,
		Mappers:         mappers,
		Resources:       resources,
	}, nil
}

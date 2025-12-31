//
//  Copyright © Manetu Inc. All rights reserved.
//

package validation

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing

type mockDomainMap struct {
	domains map[string]DomainModel
}

func newMockDomainMap() *mockDomainMap {
	return &mockDomainMap{
		domains: make(map[string]DomainModel),
	}
}

func (m *mockDomainMap) GetDomain(name string) (DomainModel, bool) {
	domain, ok := m.domains[name]
	return domain, ok
}

func (m *mockDomainMap) GetAllDomains() map[string]DomainModel {
	return m.domains
}

func (m *mockDomainMap) addDomain(name string, domain DomainModel) {
	m.domains[name] = domain
}

type mockDomainModel struct {
	name            string
	policies        map[string]PolicyEntity
	policyLibraries map[string]PolicyEntity
	roles           map[string]ReferenceEntity
	groups          map[string]GroupEntity
	resourceGroups  map[string]ReferenceEntity
	scopes          map[string]ReferenceEntity
	operations      []OperationEntity
	mappers         []MapperEntity
}

func newMockDomainModel(name string) *mockDomainModel {
	return &mockDomainModel{
		name:            name,
		policies:        make(map[string]PolicyEntity),
		policyLibraries: make(map[string]PolicyEntity),
		roles:           make(map[string]ReferenceEntity),
		groups:          make(map[string]GroupEntity),
		resourceGroups:  make(map[string]ReferenceEntity),
		scopes:          make(map[string]ReferenceEntity),
		operations:      make([]OperationEntity, 0),
		mappers:         make([]MapperEntity, 0),
	}
}

func (m *mockDomainModel) GetName() string                               { return m.name }
func (m *mockDomainModel) GetPolicies() map[string]PolicyEntity          { return m.policies }
func (m *mockDomainModel) GetPolicyLibraries() map[string]PolicyEntity   { return m.policyLibraries }
func (m *mockDomainModel) GetRoles() map[string]ReferenceEntity          { return m.roles }
func (m *mockDomainModel) GetGroups() map[string]GroupEntity             { return m.groups }
func (m *mockDomainModel) GetResourceGroups() map[string]ReferenceEntity { return m.resourceGroups }
func (m *mockDomainModel) GetScopes() map[string]ReferenceEntity         { return m.scopes }
func (m *mockDomainModel) GetOperations() []OperationEntity              { return m.operations }
func (m *mockDomainModel) GetMappers() []MapperEntity                    { return m.mappers }

type mockPolicyEntity struct {
	rego         string
	dependencies []string
}

func (m *mockPolicyEntity) GetRego() string           { return m.rego }
func (m *mockPolicyEntity) GetDependencies() []string { return m.dependencies }

type mockReferenceEntity struct {
	policy string
}

func (m *mockReferenceEntity) GetPolicy() string { return m.policy }

type mockGroupEntity struct {
	roles []string
}

func (m *mockGroupEntity) GetRoles() []string { return m.roles }

type mockOperationEntity struct {
	selectors []*regexp.Regexp
	policy    string
}

func (m *mockOperationEntity) GetSelectors() []*regexp.Regexp { return m.selectors }
func (m *mockOperationEntity) GetPolicy() string              { return m.policy }

type mockMapperEntity struct {
	id   string
	rego string
}

func (m *mockMapperEntity) GetID() string   { return m.id }
func (m *mockMapperEntity) GetRego() string { return m.rego }

// Tests for ReferenceResolver

func TestReferenceResolver_ParseReference(t *testing.T) {
	domains := newMockDomainMap()
	resolver := NewReferenceResolver(domains)

	tests := []struct {
		name           string
		reference      string
		sourceDomain   string
		expectedDomain string
		expectedID     string
		expectError    bool
	}{
		{
			name:           "unqualified reference",
			reference:      "mrn:iam:policy:allow-all",
			sourceDomain:   "test-domain",
			expectedDomain: "test-domain",
			expectedID:     "mrn:iam:policy:allow-all",
		},
		{
			name:           "qualified reference",
			reference:      "other-domain/mrn:iam:policy:allow-all",
			sourceDomain:   "test-domain",
			expectedDomain: "other-domain",
			expectedID:     "mrn:iam:policy:allow-all",
		},
		{
			name:        "empty reference",
			reference:   "",
			expectError: true,
		},
		{
			name:        "invalid qualified reference - empty domain",
			reference:   "/mrn:iam:policy:test",
			expectError: true,
		},
		{
			name:        "invalid qualified reference - empty id",
			reference:   "domain/",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, id, err := resolver.ParseReference(tt.reference, tt.sourceDomain)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedDomain, domain)
				assert.Equal(t, tt.expectedID, id)
			}
		})
	}
}

func TestReferenceResolver_QualifyReference(t *testing.T) {
	domains := newMockDomainMap()
	resolver := NewReferenceResolver(domains)

	tests := []struct {
		name         string
		reference    string
		sourceDomain string
		expected     string
	}{
		{
			name:         "unqualified reference",
			reference:    "mrn:policy:test",
			sourceDomain: "my-domain",
			expected:     "my-domain/mrn:policy:test",
		},
		{
			name:         "already qualified reference",
			reference:    "other-domain/mrn:policy:test",
			sourceDomain: "my-domain",
			expected:     "other-domain/mrn:policy:test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.QualifyReference(tt.reference, tt.sourceDomain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReferenceResolver_ValidateReference(t *testing.T) {
	domains := newMockDomainMap()
	domain := newMockDomainModel("test-domain")
	domain.policies["mrn:iam:policy:allow-all"] = &mockPolicyEntity{rego: "package authz\ndefault allow = true"}
	domain.policyLibraries["mrn:iam:library:utils"] = &mockPolicyEntity{rego: "package utils"}
	domain.roles["mrn:iam:role:admin"] = &mockReferenceEntity{policy: "mrn:iam:policy:allow-all"}
	domain.groups["mrn:iam:group:admins"] = &mockGroupEntity{roles: []string{"mrn:iam:role:admin"}}
	domain.resourceGroups["mrn:iam:resource-group:default"] = &mockReferenceEntity{policy: "mrn:iam:policy:allow-all"}
	domain.scopes["mrn:iam:scope:api"] = &mockReferenceEntity{policy: "mrn:iam:policy:allow-all"}
	domains.addDomain("test-domain", domain)

	resolver := NewReferenceResolver(domains)

	tests := []struct {
		name         string
		reference    string
		sourceDomain string
		expectedType string
		expectError  bool
	}{
		{
			name:         "valid policy reference",
			reference:    "mrn:iam:policy:allow-all",
			sourceDomain: "test-domain",
			expectedType: "policy",
		},
		{
			name:         "valid library reference",
			reference:    "mrn:iam:library:utils",
			sourceDomain: "test-domain",
			expectedType: "library",
		},
		{
			name:         "valid role reference",
			reference:    "mrn:iam:role:admin",
			sourceDomain: "test-domain",
			expectedType: "role",
		},
		{
			name:         "valid group reference",
			reference:    "mrn:iam:group:admins",
			sourceDomain: "test-domain",
			expectedType: "group",
		},
		{
			name:         "valid resource-group reference",
			reference:    "mrn:iam:resource-group:default",
			sourceDomain: "test-domain",
			expectedType: "resource-group",
		},
		{
			name:         "valid scope reference",
			reference:    "mrn:iam:scope:api",
			sourceDomain: "test-domain",
			expectedType: "scope",
		},
		{
			name:         "non-existent policy",
			reference:    "mrn:iam:policy:nonexistent",
			sourceDomain: "test-domain",
			expectedType: "policy",
			expectError:  true,
		},
		{
			name:         "non-existent domain",
			reference:    "other-domain/mrn:iam:policy:test",
			sourceDomain: "test-domain",
			expectedType: "policy",
			expectError:  true,
		},
		{
			name:         "empty reference is valid",
			reference:    "",
			sourceDomain: "test-domain",
			expectedType: "policy",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := resolver.ValidateReference(tt.reference, tt.sourceDomain, tt.expectedType)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceResolver_ResolveReference(t *testing.T) {
	domains := newMockDomainMap()
	domain := newMockDomainModel("test-domain")
	domain.policies["mrn:iam:policy:allow-all"] = &mockPolicyEntity{rego: "package authz\ndefault allow = true"}
	domains.addDomain("test-domain", domain)

	resolver := NewReferenceResolver(domains)

	t.Run("valid reference", func(t *testing.T) {
		targetDomain, targetModel, objectID, err := resolver.ResolveReference("mrn:iam:policy:allow-all", "test-domain", "policy")
		require.NoError(t, err)
		assert.Equal(t, "test-domain", targetDomain)
		assert.NotNil(t, targetModel)
		assert.Equal(t, "mrn:iam:policy:allow-all", objectID)
	})

	t.Run("non-existent domain", func(t *testing.T) {
		_, _, _, err := resolver.ResolveReference("other-domain/mrn:iam:policy:test", "test-domain", "policy")
		assert.Error(t, err)
	})

	t.Run("non-existent object", func(t *testing.T) {
		_, _, _, err := resolver.ResolveReference("mrn:iam:policy:nonexistent", "test-domain", "policy")
		assert.Error(t, err)
	})
}

func TestReferenceResolver_FindObjectAcrossDomains(t *testing.T) {
	domains := newMockDomainMap()

	domain1 := newMockDomainModel("domain1")
	domain1.policies["mrn:iam:policy:unique"] = &mockPolicyEntity{rego: "package authz"}
	domains.addDomain("domain1", domain1)

	domain2 := newMockDomainModel("domain2")
	domain2.policies["mrn:iam:policy:shared"] = &mockPolicyEntity{rego: "package authz"}
	domains.addDomain("domain2", domain2)

	domain3 := newMockDomainModel("domain3")
	domain3.policies["mrn:iam:policy:shared"] = &mockPolicyEntity{rego: "package authz"}
	domains.addDomain("domain3", domain3)

	resolver := NewReferenceResolver(domains)

	t.Run("find unique object", func(t *testing.T) {
		foundDomain, model, err := resolver.FindObjectAcrossDomains("mrn:iam:policy:unique", "policy")
		require.NoError(t, err)
		assert.Equal(t, "domain1", foundDomain)
		assert.NotNil(t, model)
	})

	t.Run("ambiguous object in multiple domains", func(t *testing.T) {
		_, _, err := resolver.FindObjectAcrossDomains("mrn:iam:policy:shared", "policy")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ambiguous")
	})

	t.Run("object not found", func(t *testing.T) {
		_, _, err := resolver.FindObjectAcrossDomains("mrn:iam:policy:nonexistent", "policy")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestReferenceResolver_MatchesAnyOperation(t *testing.T) {
	domains := newMockDomainMap()
	domain := newMockDomainModel("test-domain")

	selector, _ := regexp.Compile("^.*:read$")
	domain.operations = append(domain.operations, &mockOperationEntity{
		selectors: []*regexp.Regexp{selector},
		policy:    "mrn:iam:policy:test",
	})
	domains.addDomain("test-domain", domain)

	resolver := NewReferenceResolver(domains)

	t.Run("matching operation", func(t *testing.T) {
		err := resolver.ValidateReference("api:read", "test-domain", "operation")
		assert.NoError(t, err)
	})

	t.Run("non-matching operation", func(t *testing.T) {
		err := resolver.ValidateReference("api:write", "test-domain", "operation")
		assert.Error(t, err)
	})
}

// Tests for DomainValidator

func TestDomainValidator_ValidateAll(t *testing.T) {
	t.Run("valid domain", func(t *testing.T) {
		domains := newMockDomainMap()
		domain := newMockDomainModel("test-domain")
		domain.policies["mrn:iam:policy:allow-all"] = &mockPolicyEntity{
			rego: "package authz\ndefault allow = true",
		}
		domain.roles["mrn:iam:role:admin"] = &mockReferenceEntity{
			policy: "mrn:iam:policy:allow-all",
		}
		domains.addDomain("test-domain", domain)

		resolver := NewReferenceResolver(domains)
		validator := NewDomainValidator(resolver, domains)

		err := validator.ValidateAll()
		assert.NoError(t, err)
	})

	t.Run("invalid role reference", func(t *testing.T) {
		domains := newMockDomainMap()
		domain := newMockDomainModel("test-domain")
		domain.roles["mrn:iam:role:admin"] = &mockReferenceEntity{
			policy: "mrn:iam:policy:nonexistent",
		}
		domains.addDomain("test-domain", domain)

		resolver := NewReferenceResolver(domains)
		validator := NewDomainValidator(resolver, domains)

		err := validator.ValidateAll()
		assert.Error(t, err)
	})

	t.Run("invalid rego code", func(t *testing.T) {
		domains := newMockDomainMap()
		domain := newMockDomainModel("test-domain")
		domain.policies["mrn:iam:policy:invalid"] = &mockPolicyEntity{
			rego: "package authz\ninvalid syntax {{{",
		}
		domains.addDomain("test-domain", domain)

		resolver := NewReferenceResolver(domains)
		validator := NewDomainValidator(resolver, domains)

		err := validator.ValidateAll()
		assert.Error(t, err)
	})
}

func TestDomainValidator_ValidateWithSummary(t *testing.T) {
	t.Run("valid domain returns success", func(t *testing.T) {
		domains := newMockDomainMap()
		domain := newMockDomainModel("test-domain")
		domain.policies["mrn:iam:policy:allow-all"] = &mockPolicyEntity{
			rego: "package authz\ndefault allow = true",
		}
		domains.addDomain("test-domain", domain)

		resolver := NewReferenceResolver(domains)
		validator := NewDomainValidator(resolver, domains)

		valid, summary := validator.ValidateWithSummary()
		assert.True(t, valid)
		assert.Contains(t, summary, "passed successfully")
	})

	t.Run("invalid domain returns summary", func(t *testing.T) {
		domains := newMockDomainMap()
		domain := newMockDomainModel("test-domain")
		domain.roles["mrn:iam:role:admin"] = &mockReferenceEntity{
			policy: "mrn:iam:policy:nonexistent",
		}
		domains.addDomain("test-domain", domain)

		resolver := NewReferenceResolver(domains)
		validator := NewDomainValidator(resolver, domains)

		valid, summary := validator.ValidateWithSummary()
		assert.False(t, valid)
		assert.NotEmpty(t, summary)
	})
}

func TestDomainValidator_GetAllValidationErrors(t *testing.T) {
	domains := newMockDomainMap()
	domain := newMockDomainModel("test-domain")
	domain.roles["mrn:iam:role:admin"] = &mockReferenceEntity{
		policy: "mrn:iam:policy:nonexistent",
	}
	domain.scopes["mrn:iam:scope:api"] = &mockReferenceEntity{
		policy: "mrn:iam:policy:also-nonexistent",
	}
	domains.addDomain("test-domain", domain)

	resolver := NewReferenceResolver(domains)
	validator := NewDomainValidator(resolver, domains)

	errors := validator.GetAllValidationErrors()
	assert.NotEmpty(t, errors)
	assert.GreaterOrEqual(t, len(errors), 2)
}

func TestDomainValidator_ValidateDomain(t *testing.T) {
	domains := newMockDomainMap()
	domain := newMockDomainModel("test-domain")
	domain.policies["mrn:iam:policy:allow-all"] = &mockPolicyEntity{
		rego: "package authz\ndefault allow = true",
	}
	domains.addDomain("test-domain", domain)

	resolver := NewReferenceResolver(domains)
	validator := NewDomainValidator(resolver, domains)

	t.Run("existing domain", func(t *testing.T) {
		err := validator.ValidateDomain("test-domain")
		assert.NoError(t, err)
	})

	t.Run("non-existing domain", func(t *testing.T) {
		err := validator.ValidateDomain("nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestDomainValidator_CircularDependency(t *testing.T) {
	domains := newMockDomainMap()
	domain := newMockDomainModel("test-domain")

	// Create circular dependency: lib-a -> lib-b -> lib-c -> lib-a
	domain.policyLibraries["mrn:iam:library:lib-a"] = &mockPolicyEntity{
		rego:         "package lib_a",
		dependencies: []string{"mrn:iam:library:lib-b"},
	}
	domain.policyLibraries["mrn:iam:library:lib-b"] = &mockPolicyEntity{
		rego:         "package lib_b",
		dependencies: []string{"mrn:iam:library:lib-c"},
	}
	domain.policyLibraries["mrn:iam:library:lib-c"] = &mockPolicyEntity{
		rego:         "package lib_c",
		dependencies: []string{"mrn:iam:library:lib-a"},
	}
	domains.addDomain("test-domain", domain)

	resolver := NewReferenceResolver(domains)
	validator := NewDomainValidator(resolver, domains)

	err := validator.ValidateAll()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circular")
}

func TestDomainValidator_ValidateGroups(t *testing.T) {
	domains := newMockDomainMap()
	domain := newMockDomainModel("test-domain")
	domain.policies["mrn:iam:policy:allow-all"] = &mockPolicyEntity{
		rego: "package authz\ndefault allow = true",
	}
	domain.roles["mrn:iam:role:admin"] = &mockReferenceEntity{
		policy: "mrn:iam:policy:allow-all",
	}
	domain.groups["mrn:iam:group:admins"] = &mockGroupEntity{
		roles: []string{"mrn:iam:role:admin", "mrn:iam:role:nonexistent"},
	}
	domains.addDomain("test-domain", domain)

	resolver := NewReferenceResolver(domains)
	validator := NewDomainValidator(resolver, domains)

	err := validator.ValidateAll()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestDomainValidator_ValidateOperations(t *testing.T) {
	domains := newMockDomainMap()
	domain := newMockDomainModel("test-domain")

	selector, _ := regexp.Compile("^.*$")
	domain.operations = append(domain.operations, &mockOperationEntity{
		selectors: []*regexp.Regexp{selector},
		policy:    "mrn:iam:policy:nonexistent",
	})
	domains.addDomain("test-domain", domain)

	resolver := NewReferenceResolver(domains)
	validator := NewDomainValidator(resolver, domains)

	err := validator.ValidateAll()
	assert.Error(t, err)
}

// Tests for DependencyResolver

func TestDependencyResolver_ResolveDependencies(t *testing.T) {
	domains := newMockDomainMap()
	domain := newMockDomainModel("test-domain")
	domain.policyLibraries["mrn:iam:library:utils"] = &mockPolicyEntity{
		rego:         "package utils",
		dependencies: []string{},
	}
	domain.policyLibraries["mrn:iam:library:helpers"] = &mockPolicyEntity{
		rego:         "package helpers",
		dependencies: []string{"mrn:iam:library:utils"},
	}
	domains.addDomain("test-domain", domain)

	resolver := NewReferenceResolver(domains)
	depResolver := NewDependencyResolver(resolver)

	t.Run("resolve single dependency", func(t *testing.T) {
		deps, err := depResolver.ResolveDependencies(domain, []string{"mrn:iam:library:utils"})
		require.NoError(t, err)
		assert.Contains(t, deps, "mrn:iam:library:utils")
	})

	t.Run("resolve transitive dependencies", func(t *testing.T) {
		deps, err := depResolver.ResolveDependencies(domain, []string{"mrn:iam:library:helpers"})
		require.NoError(t, err)
		assert.Contains(t, deps, "mrn:iam:library:helpers")
		// Should also include transitive dependency
		found := false
		for _, d := range deps {
			if d == "mrn:iam:library:utils" || d == "test-domain/mrn:iam:library:utils" {
				found = true
				break
			}
		}
		assert.True(t, found, "Should include transitive dependency utils")
	})

	t.Run("non-existent dependency", func(t *testing.T) {
		_, err := depResolver.ResolveDependencies(domain, []string{"mrn:iam:library:nonexistent"})
		assert.Error(t, err)
	})
}

func TestDependencyResolver_CircularDependency(t *testing.T) {
	domains := newMockDomainMap()
	domain := newMockDomainModel("test-domain")
	domain.policyLibraries["mrn:iam:library:lib-a"] = &mockPolicyEntity{
		rego:         "package lib_a",
		dependencies: []string{"mrn:iam:library:lib-b"},
	}
	domain.policyLibraries["mrn:iam:library:lib-b"] = &mockPolicyEntity{
		rego:         "package lib_b",
		dependencies: []string{"mrn:iam:library:lib-a"},
	}
	domains.addDomain("test-domain", domain)

	resolver := NewReferenceResolver(domains)
	depResolver := NewDependencyResolver(resolver)

	_, err := depResolver.ResolveDependencies(domain, []string{"mrn:iam:library:lib-a"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circular")
}

// Tests for RegoValidator

func TestRegoValidator_ValidateRegoCode(t *testing.T) {
	validator := NewRegoValidator()

	tests := []struct {
		name        string
		rego        string
		expectError bool
	}{
		{
			name:        "valid rego",
			rego:        "package authz\ndefault allow = true",
			expectError: false,
		},
		{
			name:        "empty rego is valid",
			rego:        "",
			expectError: false,
		},
		{
			name:        "whitespace only is valid",
			rego:        "   \n\t  ",
			expectError: false,
		},
		{
			name:        "invalid rego syntax",
			rego:        "package authz\ninvalid {{{",
			expectError: true,
		},
		{
			name:        "complex valid rego",
			rego:        "package authz\n\nimport rego.v1\n\ndefault allow := false\n\nallow if {\n    input.user == \"admin\"\n}",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateRegoCode(tt.rego, "policy", "test-policy")
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRegoValidator_ValidateDomainRego(t *testing.T) {
	validator := NewRegoValidator()

	t.Run("all valid rego", func(t *testing.T) {
		domain := newMockDomainModel("test-domain")
		domain.policyLibraries["mrn:iam:library:utils"] = &mockPolicyEntity{
			rego: "package utils\nhelper := true",
		}
		domain.policies["mrn:iam:policy:allow-all"] = &mockPolicyEntity{
			rego: "package authz\ndefault allow = true",
		}
		domain.mappers = append(domain.mappers, &mockMapperEntity{
			id:   "test-mapper",
			rego: "package mapper\nporc := {}",
		})

		errors := NewValidationErrors()
		validator.ValidateDomainRego("test-domain", domain, errors)
		assert.False(t, errors.HasErrors())
	})

	t.Run("invalid library rego", func(t *testing.T) {
		domain := newMockDomainModel("test-domain")
		domain.policyLibraries["mrn:iam:library:invalid"] = &mockPolicyEntity{
			rego: "package utils\ninvalid {{{",
		}

		errors := NewValidationErrors()
		validator.ValidateDomainRego("test-domain", domain, errors)
		assert.True(t, errors.HasErrors())
	})

	t.Run("invalid policy rego", func(t *testing.T) {
		domain := newMockDomainModel("test-domain")
		domain.policies["mrn:iam:policy:invalid"] = &mockPolicyEntity{
			rego: "package authz\ninvalid {{{",
		}

		errors := NewValidationErrors()
		validator.ValidateDomainRego("test-domain", domain, errors)
		assert.True(t, errors.HasErrors())
	})

	t.Run("invalid mapper rego", func(t *testing.T) {
		domain := newMockDomainModel("test-domain")
		domain.mappers = append(domain.mappers, &mockMapperEntity{
			id:   "invalid-mapper",
			rego: "package mapper\ninvalid {{{",
		})

		errors := NewValidationErrors()
		validator.ValidateDomainRego("test-domain", domain, errors)
		assert.True(t, errors.HasErrors())
	})

	t.Run("mapper without id uses fallback", func(t *testing.T) {
		domain := newMockDomainModel("test-domain")
		domain.mappers = append(domain.mappers, &mockMapperEntity{
			id:   "",
			rego: "package mapper\ninvalid {{{",
		})

		errors := NewValidationErrors()
		validator.ValidateDomainRego("test-domain", domain, errors)
		assert.True(t, errors.HasErrors())
		// Error should contain mapper[0] as fallback ID
		assert.Contains(t, errors.Error(), "mapper")
	})
}

// Tests for ValidationErrors

func TestValidationErrors_Basic(t *testing.T) {
	errors := NewValidationErrors()

	assert.False(t, errors.HasErrors())
	assert.Equal(t, 0, errors.Count())

	errors.AddReferenceError("domain1", "role", "role-1", "policy", "not found")
	assert.True(t, errors.HasErrors())
	assert.Equal(t, 1, errors.Count())

	errors.AddCycleError("circular dependency detected")
	assert.Equal(t, 2, errors.Count())

	errors.AddRegoError("domain1", "policy", "policy-1", "syntax error")
	assert.Equal(t, 3, errors.Count())
}

func TestValidationErrors_Error(t *testing.T) {
	t.Run("no errors", func(t *testing.T) {
		errors := NewValidationErrors()
		assert.Equal(t, "no validation errors", errors.Error())
	})

	t.Run("single error", func(t *testing.T) {
		errors := NewValidationErrors()
		errors.AddReferenceError("domain1", "role", "role-1", "policy", "not found")
		errStr := errors.Error()
		assert.Contains(t, errStr, "domain1")
		assert.Contains(t, errStr, "role")
	})

	t.Run("multiple errors", func(t *testing.T) {
		errors := NewValidationErrors()
		errors.AddReferenceError("domain1", "role", "role-1", "policy", "not found")
		errors.AddCycleError("circular dependency")
		errStr := errors.Error()
		assert.Contains(t, errStr, "2 errors")
	})
}

func TestValidationErrors_Grouping(t *testing.T) {
	errors := NewValidationErrors()
	errors.AddReferenceError("domain1", "role", "role-1", "policy", "not found")
	errors.AddReferenceError("domain1", "scope", "scope-1", "policy", "not found")
	errors.AddReferenceError("domain2", "role", "role-2", "policy", "not found")
	errors.AddCycleError("circular dependency")

	byDomain := errors.ErrorsByDomain()
	assert.Len(t, byDomain["domain1"], 2)
	assert.Len(t, byDomain["domain2"], 1)
	assert.Len(t, byDomain["unknown"], 1) // cycle errors have no domain

	byType := errors.ErrorsByType()
	assert.Len(t, byType["reference"], 3)
	assert.Len(t, byType["cycle"], 1)
}

func TestValidationErrors_Summary(t *testing.T) {
	errors := NewValidationErrors()
	errors.AddReferenceError("domain1", "role", "role-1", "policy", "not found")
	errors.AddCycleError("circular dependency")

	summary := errors.Summary()
	assert.Contains(t, summary, "Validation Summary")
	assert.Contains(t, summary, "2 errors")
	assert.Contains(t, summary, "By Domain")
	assert.Contains(t, summary, "By Type")
}

func TestValidationErrors_First(t *testing.T) {
	t.Run("empty errors", func(t *testing.T) {
		errors := NewValidationErrors()
		assert.Nil(t, errors.First())
	})

	t.Run("with errors", func(t *testing.T) {
		errors := NewValidationErrors()
		errors.AddReferenceError("domain1", "role", "role-1", "policy", "first error")
		errors.AddReferenceError("domain2", "role", "role-2", "policy", "second error")

		first := errors.First()
		assert.NotNil(t, first)
		assert.Contains(t, first.Error(), "first error")
	})
}

func TestValidationErrors_ToSlice(t *testing.T) {
	errors := NewValidationErrors()
	errors.AddReferenceError("domain1", "role", "role-1", "policy", "error 1")
	errors.AddReferenceError("domain2", "role", "role-2", "policy", "error 2")

	slice := errors.ToSlice()
	assert.Len(t, slice, 2)
}

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		expected []string
	}{
		{
			name: "full error",
			err: &Error{
				Domain:   "domain1",
				Entity:   "role",
				EntityID: "role-1",
				Field:    "policy",
				Message:  "not found",
			},
			expected: []string{"domain1", "role", "role-1", "policy", "not found"},
		},
		{
			name: "no domain",
			err: &Error{
				Entity:   "role",
				EntityID: "role-1",
				Message:  "error message",
			},
			expected: []string{"role", "role-1", "error message"},
		},
		{
			name: "only message",
			err: &Error{
				Message: "simple error",
			},
			expected: []string{"simple error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, exp := range tt.expected {
				assert.Contains(t, errStr, exp)
			}
		})
	}
}

// Test helper functions

func TestRemoveDuplicates(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all same",
			input:    []string{"a", "a", "a"},
			expected: []string{"a"},
		},
		{
			name:     "empty",
			input:    []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeDuplicates(tt.input)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

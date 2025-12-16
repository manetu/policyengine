//
//  Copyright © Manetu Inc. All rights reserved.
//

package local

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/manetu/policyengine/pkg/core/opa"
	"github.com/manetu/policyengine/pkg/policydomain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper functions
func createTempFileFromTestData(t *testing.T, testdataFile string) string {
	// Read the testdata file
	content, err := os.ReadFile(filepath.Join("../../../../cmd/mpe/test", testdataFile))
	require.NoError(t, err, "Failed to read testdata file: %s", testdataFile)

	// Create temp file with the content
	tmpfile, err := os.CreateTemp("", "test-*.yml")
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(tmpfile.Name()) })

	_, err = tmpfile.Write(content)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	return tmpfile.Name()
}

func createBackend(domainPaths []string) (*Backend, error) {
	compiler := opa.NewCompiler()

	reg, err := registry.NewRegistry(domainPaths)
	if err != nil {
		return nil, err
	}

	// Compile all policies and mappers (as NewBackend does)
	if err := reg.CompileAllPolicies(compiler, compiler); err != nil {
		return nil, err
	}

	return newTestBackend(compiler, reg), nil
}

func TestGetMapper_SingleDomain(t *testing.T) {
	// Test with consolidated.yml which has a mapper
	consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

	be, err := createBackend([]string{consolidatedFile})
	assert.Nil(t, err, "Backend creation should succeed")
	assert.NotNil(t, be, "Backend should not be nil")

	// Test getting mapper without specifying domain name
	mapper, err := be.GetMapper(context.Background(), "")
	assert.Nil(t, err, "Should find mapper successfully")
	assert.NotNil(t, mapper, "Mapper should not be nil")
	assert.Equal(t, "consolidated", mapper.Domain, "Should find mapper in consolidated domain")
	//assert.Equal(t, "common-mapper", mapper.IdSpec.Id, "Should return the correct mapper")
	assert.NotNil(t, mapper.Ast, "Mapper should have Rego")
}

func TestGetMapper_NoDomain(t *testing.T) {
	// Test with valid-alpha.yml which has no mappers
	alphaFile := createTempFileFromTestData(t, "valid-alpha.yml")

	be, err := createBackend([]string{alphaFile})
	assert.Nil(t, err, "Backend creation should succeed")

	// Test getting mapper from domain with no mappers
	mapper, err := be.GetMapper(context.Background(), "")
	assert.NotNil(t, err, "Should fail when no mappers found")
	assert.Nil(t, mapper, "Mapper should be nil")
	assert.Contains(t, err.Error(), "no mappers found in any domain")
}

func TestGetMapper_SpecificDomain(t *testing.T) {
	// Test with consolidated.yml which has a mapper
	consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

	be, err := createBackend([]string{consolidatedFile})
	assert.Nil(t, err, "Backend creation should succeed")

	// Test getting mapper by specifying domain name
	mapper, err := be.GetMapper(context.Background(), "consolidated")
	assert.Nil(t, err, "Should find mapper in specified domain")
	assert.NotNil(t, mapper, "Mapper should not be nil")
	assert.Equal(t, "consolidated", mapper.Domain, "Should return specified domain")
	//assert.Equal(t, "common-mapper", mapper.IdSpec.Id, "Should return the correct mapper")
}

func TestGetMapper_InvalidDomain(t *testing.T) {
	consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

	be, err := createBackend([]string{consolidatedFile})
	assert.Nil(t, err, "Backend creation should succeed")

	// Test getting mapper from non-existent domain
	mapper, err := be.GetMapper(context.Background(), "nonexistent")
	assert.NotNil(t, err, "Should fail with non-existent domain")
	assert.Nil(t, mapper, "Mapper should be nil")
	assert.Contains(t, err.Error(), "domain 'nonexistent' not found")
}

func TestGetMapper_DomainWithoutMapper(t *testing.T) {
	alphaFile := createTempFileFromTestData(t, "valid-alpha.yml")

	be, err := createBackend([]string{alphaFile})
	assert.Nil(t, err, "Backend creation should succeed")

	// Test getting mapper from domain that has no mappers
	mapper, err := be.GetMapper(context.Background(), "alpha")
	assert.NotNil(t, err, "Should fail when specified domain has no mappers")
	assert.Nil(t, mapper, "Mapper should be nil")
	assert.Contains(t, err.Error(), "no mappers found in domain 'alpha'")
}

func TestGetMapper_MultipleDomains(t *testing.T) {
	// Test with multiple domains where only one has mappers
	consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")
	alphaFile := createTempFileFromTestData(t, "valid-alpha.yml")

	be, err := createBackend([]string{consolidatedFile, alphaFile})
	assert.Nil(t, err, "Backend creation should succeed")

	// Test getting mapper without specifying domain - should find the one with mapper
	mapper, err := be.GetMapper(context.Background(), "")
	assert.Nil(t, err, "Should find mapper when only one domain has mappers")
	assert.NotNil(t, mapper, "Mapper should not be nil")
	assert.Equal(t, "consolidated", mapper.Domain, "Should find mapper in consolidated domain")

	// Test getting mapper by specifying the domain with mapper
	mapper, err = be.GetMapper(context.Background(), "consolidated")
	assert.Nil(t, err, "Should find mapper in specified domain")
	assert.Equal(t, "consolidated", mapper.Domain, "Should return specified domain")

	// Test getting mapper by specifying domain without mapper
	_, err = be.GetMapper(context.Background(), "alpha")
	assert.NotNil(t, err, "Should fail when specified domain has no mappers")
	assert.Contains(t, err.Error(), "no mappers found in domain 'alpha'")
}

// Test Rego execution with real mapper code
func TestMapperRegoExecution_ConsolidatedDomain(t *testing.T) {
	consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

	be, err := createBackend([]string{consolidatedFile})
	require.Nil(t, err, "Backend creation should succeed")

	// Get the mapper from the registry
	mapper, err := be.GetMapper(context.Background(), "")
	require.Nil(t, err, "Should find mapper successfully")
	require.Equal(t, "consolidated", mapper.Domain, "Should find mapper in consolidated domain")

	// Create test Envoy input
	envoyInput := map[string]interface{}{
		"destination": map[string]interface{}{
			"principal": "spiffe://cluster.local/ns/manetu/sa/petstore",
		},
		"request": map[string]interface{}{
			"http": map[string]interface{}{
				"method": "GET",
				"path":   "/favicon.ico",
				"headers": map[string]interface{}{
					":method": "GET",
					":path":   "/favicon.ico",
				},
			},
		},
		"metadata_context":       map[string]interface{}{},
		"route_metadata_context": map[string]interface{}{},
		"source": map[string]interface{}{
			"principal": "spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account",
		},
	}

	result, err := mapper.Evaluate(context.Background(), envoyInput)
	require.Nil(t, err, "Rego execution should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Validate the PORC structure
	porcMap, ok := result.(map[string]interface{})
	require.True(t, ok, "Result should be a map")

	// Validate required PORC fields exist
	assert.Contains(t, porcMap, "principal", "PORC should contain principal")
	assert.Contains(t, porcMap, "operation", "PORC should contain operation")
	assert.Contains(t, porcMap, "resource", "PORC should contain resource")
	assert.Contains(t, porcMap, "context", "PORC should contain context")

	// Validate specific transformations from the consolidated.yml mapper
	assert.Equal(t, "petstore:http:get", porcMap["operation"], "Operation should be constructed correctly")

	// Validate resource structure
	resource, ok := porcMap["resource"].(map[string]interface{})
	require.True(t, ok, "Resource should be a map")

	assert.Equal(t, "http://petstore/favicon.ico", resource["id"], "Resource ID should be constructed correctly")
	assert.Equal(t, "mrn:iam:resource-group:allow-all", resource["group"], "Resource group should be set correctly")

	// Validate that context contains the original input
	context, ok := porcMap["context"].(map[string]interface{})
	require.True(t, ok, "Context should be a map")
	assert.Equal(t, envoyInput, context, "Context should contain the original Envoy input")

	// Validate principal (should be empty object since no JWT token in headers)
	principal, ok := porcMap["principal"].(map[string]interface{})
	require.True(t, ok, "Principal should be a map")
	assert.Empty(t, principal, "Principal should be empty when no JWT token provided")
}

func TestMapperRegoExecution_MinimalInput(t *testing.T) {
	consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

	be, err := createBackend([]string{consolidatedFile})
	require.Nil(t, err, "Backend creation should succeed")

	mapper, err := be.GetMapper(context.Background(), "")
	require.Nil(t, err, "Should find mapper successfully")

	// Test with minimal Envoy input
	minimalInput := map[string]interface{}{
		"destination": map[string]interface{}{
			"principal": "spiffe://cluster.local/ns/test/sa/testservice",
		},
		"request": map[string]interface{}{
			"http": map[string]interface{}{
				"method": "POST",
				"path":   "/api/test",
			},
		},
	}

	result, err := mapper.Evaluate(context.Background(), minimalInput)
	require.Nil(t, err, "Rego execution should succeed with minimal input")
	require.NotNil(t, result, "Result should not be nil")

	porcMap, ok := result.(map[string]interface{})
	require.True(t, ok, "Result should be a map")

	// Validate that different inputs produce different outputs
	assert.Equal(t, "testservice:http:post", porcMap["operation"], "Operation should reflect different service and method")

	resource, ok := porcMap["resource"].(map[string]interface{})
	require.True(t, ok, "Resource should be a map")
	assert.Equal(t, "http://testservice/api/test", resource["id"], "Resource ID should reflect different service and path")
}

// Test operation selector anchoring behavior
func TestOperationSelectorAnchoring(t *testing.T) {
	t.Run("Unanchored selectors test", func(t *testing.T) {
		// Create a domain with unanchored selector patterns
		alphaFile := createTempFileFromTestData(t, "alpha.yml")
		betaFile := createTempFileFromTestData(t, "beta-no-anchor.yml")

		be, err := createBackend([]string{alphaFile, betaFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test that "subalpha:foo" does NOT match "alpha:.*" pattern
		operation := "subalpha:foo"
		policyReference, policyErr := be.GetOperation(context.Background(), operation)
		require.Nil(t, policyErr, "Should not return policy error")
		require.NotNil(t, policyReference, "Should return policyReference")

		// Should match the catch-all ".*" pattern (mainapi), not the "alpha:.*" pattern (no-access)
		assert.Equal(t, "mrn:iam:policy:mainapi", policyReference.Policy.Mrn, "Should match mainapi policy, not no-access")
	})

	t.Run("Anchored Selectors test", func(t *testing.T) {
		alphaFile := createTempFileFromTestData(t, "alpha.yml")
		betaFile := createTempFileFromTestData(t, "beta-no-anchor.yml")

		be, err := createBackend([]string{alphaFile, betaFile})
		require.Nil(t, err, "Backend creation should succeed")

		testCases := []struct {
			operation      string
			expectedPolicy string
		}{
			{"alpha:foo", "mrn:iam:policy:no-access"},
			{"beta:foo", "mrn:iam:policy:read-only"},
			{"omega:foo", "mrn:iam:policy:mainapi"},
		}

		for _, tc := range testCases {
			t.Run(tc.operation, func(t *testing.T) {
				policyReference, policyErr := be.GetOperation(context.Background(), tc.operation)
				require.Nil(t, policyErr, "Should not return policy error")
				require.NotNil(t, policyReference, "Should return policyReference")
				assert.Equal(t, tc.expectedPolicy, policyReference.Policy.Mrn,
					"Operation %s should match %s", tc.operation, tc.expectedPolicy)
			})
		}
	})

	t.Run("Operations are evaluated in order", func(t *testing.T) {
		alphaFile := createTempFileFromTestData(t, "alpha.yml")
		betaFile := createTempFileFromTestData(t, "beta-no-anchor.yml")

		be, err := createBackend([]string{alphaFile, betaFile})
		require.Nil(t, err, "Backend creation should succeed")

		operation := "random:operation"
		policyReference, policyErr := be.GetOperation(context.Background(), operation)
		require.Nil(t, policyErr, "Should not return policy error")
		require.NotNil(t, policyReference, "Should return policyReference")
		assert.Equal(t, "mrn:iam:policy:mainapi", policyReference.Policy.Mrn,
			"Random operation should fall through to mainapi catch-all")
	})

	t.Run("Substring matches should not occur", func(t *testing.T) {
		alphaFile := createTempFileFromTestData(t, "alpha.yml")
		betaFile := createTempFileFromTestData(t, "beta-no-anchor.yml")

		be, err := createBackend([]string{alphaFile, betaFile})
		require.Nil(t, err, "Backend creation should succeed")

		substringTests := []struct {
			operation      string
			shouldNotMatch string
			shouldMatch    string
		}{
			{"subalpha:test", "alpha:.*", ".*"},
			{"mybeta:test", "beta:.*", ".*"},
			{"preomega:test", "omega:.*", ".*"},
			{"alpha_modified:test", "alpha:.*", ".*"},
		}

		for _, tc := range substringTests {
			t.Run(tc.operation, func(t *testing.T) {
				policyReference, policyErr := be.GetOperation(context.Background(), tc.operation)
				require.Nil(t, policyErr, "Should not return policy error")
				require.NotNil(t, policyReference, "Should return policyReference")
				assert.Equal(t, "mrn:iam:policy:mainapi", policyReference.Policy.Mrn,
					"Operation %s should not substring-match %s, should fall through to catch-all",
					tc.operation, tc.shouldNotMatch)
			})
		}
	})
}

//// Test that mapper selectors also have proper anchoring
//func TestMapperSelectorAnchoring(t *testing.T) {
//	consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")
//
//	be, err := createBackend([]string{consolidatedFile})
//	require.Nil(t, err, "Backend creation should succeed")
//
//	// Get the mapper
//	mapper, err := be.GetMapper(context.Background(), "")
//	require.Nil(t, err, "Should find mapper successfully")
//	require.Equal(t, "consolidated", mapper.Domain, "Should find mapper in consolidated domain")
//
//	assert.NotNil(t, mapper, "Mapper should not be nil")
//	assert.Len(t, mapper.Selectors, 1, "Mapper should have one selector")
//
//	// Test that the selector was compiled successfully (no panic on Match)
//	testInput := "test-service"
//	matched := mapper.Selectors[0].MatchString(testInput)
//	assert.True(t, matched, "Catch-all mapper selector should match any string")
//}

// Test operation selector anchoring with pre-anchored patterns
func TestOperationSelectorWithPreAnchoredPatterns(t *testing.T) {
	t.Run("Pre-anchored patterns test", func(t *testing.T) {
		alphaFile := createTempFileFromTestData(t, "alpha.yml")
		betaAnchoredFile := createTempFileFromTestData(t, "beta-anchored.yml")

		be, err := createBackend([]string{alphaFile, betaAnchoredFile})
		require.Nil(t, err, "Backend creation should succeed with pre-anchored patterns")

		testCases := []struct {
			operation      string
			expectedPolicy string
			description    string
		}{

			{"alpha:foo", "mrn:iam:policy:no-access", "start-anchored pattern should match"},
			{"alpha:bar:baz", "mrn:iam:policy:no-access", "start-anchored should match longer strings"},
			{"subalpha:foo", "mrn:iam:policy:mainapi", "start-anchored should not substring match"},

			{"beta:test", "mrn:iam:policy:read-only", "fully-anchored pattern should match"},
			{"mybeta:test", "mrn:iam:policy:mainapi", "fully-anchored should not substring match prefix"},
			{"beta:test:extra", "mrn:iam:policy:read-only", "fully-anchored should match with suffix"},

			{"gamma:test", "mrn:iam:policy:no-access", "end-anchored pattern should match"},
			{"subgamma:test", "mrn:iam:policy:mainapi", "end-anchored should not substring match"},

			{"delta:operation", "mrn:iam:policy:read-only", "explicit fully-anchored should match"},
			{"subdelta:operation", "mrn:iam:policy:mainapi", "explicit fully-anchored should not substring match"},
			{"anything:random", "mrn:iam:policy:mainapi", "catch-all should match anything not matched above"},
		}

		for _, tc := range testCases {
			t.Run(tc.operation+" - "+tc.description, func(t *testing.T) {
				policyReference, policyErr := be.GetOperation(context.Background(), tc.operation)
				require.Nil(t, policyErr, "Should not return policy error")
				require.NotNil(t, policyReference, "Should return policyReference")
				assert.Equal(t, tc.expectedPolicy, policyReference.Policy.Mrn,
					"%s: %s", tc.description, tc.operation)
			})
		}
	})

	t.Run("Verify no double-anchoring occurs", func(t *testing.T) {
		// This test verifies that patterns like "^alpha:.*" don't become "^^alpha:.*$$"
		alphaFile := createTempFileFromTestData(t, "alpha.yml")
		betaAnchoredFile := createTempFileFromTestData(t, "beta-anchored.yml")

		be, err := createBackend([]string{alphaFile, betaAnchoredFile})
		require.Nil(t, err, "Backend with pre-anchored patterns should compile without errors")

		testCases := []struct {
			operation      string
			shouldMatch    bool
			expectedPolicy string
		}{
			{"alpha:test", true, "mrn:iam:policy:no-access"},
			{"beta:test", true, "mrn:iam:policy:read-only"},
			{"gamma:test", true, "mrn:iam:policy:no-access"},
			{"delta:test", true, "mrn:iam:policy:read-only"},
		}

		for _, tc := range testCases {
			composition, policyErr := be.GetOperation(context.Background(), tc.operation)
			require.Nil(t, policyErr, "Should not return policy error for %s", tc.operation)

			if tc.shouldMatch {
				require.NotNil(t, composition, "Should find composition for %s", tc.operation)
				assert.Equal(t, tc.expectedPolicy, composition.Policy.Mrn,
					"Operation %s should match correct policy", tc.operation)
			}
		}
	})

	t.Run("Mixed anchoring test", func(t *testing.T) {
		alphaFile := createTempFileFromTestData(t, "alpha.yml")
		betaAnchoredFile := createTempFileFromTestData(t, "beta-anchored.yml")

		be, err := createBackend([]string{alphaFile, betaAnchoredFile})
		require.Nil(t, err, "Backend creation should succeed")

		substringTests := []struct {
			operation             string
			shouldNotMatchPattern string
		}{
			{"subalpha:test", "alpha"},
			{"mybeta:test", "beta"},
			{"pregamma:test", "gamma"},
			{"subdelta:test", "delta"},
		}

		for _, tc := range substringTests {
			policyReference, policyErr := be.GetOperation(context.Background(), tc.operation)
			require.Nil(t, policyErr, "Should not return policy error")
			require.NotNil(t, policyReference, "Should return policyReference")
			assert.Equal(t, "mrn:iam:policy:mainapi", policyReference.Policy.Mrn,
				"Operation %s should NOT match %s pattern, should fall through to mainapi",
				tc.operation, tc.shouldNotMatchPattern)
		}
	})
}

// Test GetRole method
func TestGetRole(t *testing.T) {
	t.Run("GetRole - consolidated domain with annotations", func(t *testing.T) {
		consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{consolidatedFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting an existing role with annotations
		role, policyErr := be.GetRole(context.Background(), "mrn:iam:role:admin")
		require.Nil(t, policyErr, "Should not return policy error")
		require.NotNil(t, role, "Role should not be nil")
		assert.Equal(t, "mrn:iam:role:admin", role.Mrn, "Role MRN should match")
		assert.NotEmpty(t, role.Policy, "Role should have policies")
		assert.Equal(t, "mrn:iam:policy:allow-all", role.Policy.Mrn, "Role should reference allow-all policy")
		assert.NotNil(t, role.Annotations, "Annotations should be initialized")
		// Annotations should be populated from the domain
		assert.Equal(t, 3, len(role.Annotations), "Admin role should have 3 annotations")
		assert.Equal(t, float64(42), role.Annotations["foo"], "Foo annotation should be '42'")
		//assert.Equal(t, 3, len(role.Annotations["bar"].([]float64)), "Bar annotation should be '[1, 2, 3]' and thus has 3 elements")
		//assert.Equal(t, 42, role.Annotations["baz"]["bat"], "baz.bat annotation should be '42'")
	})

	t.Run("GetRole - not found", func(t *testing.T) {
		consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{consolidatedFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting a non-existent role
		role, policyErr := be.GetRole(context.Background(), "mrn:iam:role:nonexistent")
		assert.NotNil(t, policyErr, "Should return policy error")
		assert.Nil(t, role, "Role should be nil")
		assert.Contains(t, policyErr.Error(), "role not found", "Error should indicate role not found")
	})

	t.Run("GetRole - multiple roles in domain", func(t *testing.T) {
		consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{consolidatedFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting admin role
		adminRole, policyErr := be.GetRole(context.Background(), "mrn:iam:role:admin")
		require.Nil(t, policyErr, "Should not return policy error for admin role")
		require.NotNil(t, adminRole, "Admin role should not be nil")
		assert.Equal(t, "mrn:iam:role:admin", adminRole.Mrn, "Admin role MRN should match")
		assert.Equal(t, "mrn:iam:policy:allow-all", adminRole.Policy.Mrn, "Admin role should reference allow-all policy")

		// Test getting no-access role
		noAccessRole, policyErr := be.GetRole(context.Background(), "mrn:iam:role:no-access")
		require.Nil(t, policyErr, "Should not return policy error for no-access role")
		require.NotNil(t, noAccessRole, "No-access role should not be nil")
		assert.Equal(t, "mrn:iam:role:no-access", noAccessRole.Mrn, "No-access role MRN should match")
		assert.Equal(t, "mrn:iam:policy:no-access", noAccessRole.Policy.Mrn, "No-access role should reference no-access policy")
	})
}

// Test GetScope method
func TestGetScope(t *testing.T) {
	t.Run("GetScope - consolidated domain with annotations", func(t *testing.T) {
		consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{consolidatedFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting an existing scope with annotations
		scope, policyErr := be.GetScope(context.Background(), "mrn:iam:scope:api")
		require.Nil(t, policyErr, "Should not return policy error")
		require.NotNil(t, scope, "Scope should not be nil")
		assert.Equal(t, "mrn:iam:scope:api", scope.Mrn, "Scope MRN should match")
		assert.NotNil(t, scope.Annotations, "Annotations should be initialized")
		// Annotations should be populated from the domain
		assert.Equal(t, 1, len(scope.Annotations), "API scope should have 1 annotation")
		assert.Equal(t, "scopes", scope.Annotations["testing"], "Testing annotation should be 'scopes'")
	})

	t.Run("GetScope - not found", func(t *testing.T) {
		consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{consolidatedFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting a non-existent scope
		scope, policyErr := be.GetScope(context.Background(), "mrn:iam:scope:nonexistent")
		assert.NotNil(t, policyErr, "Should return policy error")
		assert.Nil(t, scope, "Scope should be nil")
		assert.Contains(t, policyErr.Error(), "scope not found", "Error should indicate scope not found")
	})

	t.Run("GetScope - multiple scopes in domain", func(t *testing.T) {
		consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{consolidatedFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting api scope
		apiScope, policyErr := be.GetScope(context.Background(), "mrn:iam:scope:api")
		require.Nil(t, policyErr, "Should not return policy error for api scope")
		require.NotNil(t, apiScope, "API scope should not be nil")
		assert.Equal(t, "mrn:iam:scope:api", apiScope.Mrn, "API scope MRN should match")
		assert.NotNil(t, apiScope.Annotations, "API scope annotations should be initialized")
		assert.Equal(t, 1, len(apiScope.Annotations), "API scope should have 1 annotation")
		assert.Equal(t, "scopes", apiScope.Annotations["testing"], "Testing annotation should be 'scopes'")

		// Test getting read-api scope
		readAPIScope, policyErr := be.GetScope(context.Background(), "mrn:iam:scope:read-api")
		require.Nil(t, policyErr, "Should not return policy error for read-api scope")
		require.NotNil(t, readAPIScope, "Read-API scope should not be nil")
		assert.Equal(t, "mrn:iam:scope:read-api", readAPIScope.Mrn, "Read-API scope MRN should match")
		assert.NotNil(t, readAPIScope.Annotations, "Read-API scope annotations should be initialized")
		assert.Equal(t, 1, len(readAPIScope.Annotations), "Read-API scope should have 1 annotation")
		assert.Equal(t, "annotations", readAPIScope.Annotations["testing"], "Testing annotation should be 'annotations'")
	})
}

// Test GetGroup method
func TestGetGroup(t *testing.T) {
	t.Run("GetGroup - consolidated domain with annotations", func(t *testing.T) {
		consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{consolidatedFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting an existing group with annotations
		group, policyErr := be.GetGroup(context.Background(), "mrn:iam:group:admin")
		require.Nil(t, policyErr, "Should not return policy error")
		require.NotNil(t, group, "Group should not be nil")
		assert.Equal(t, "mrn:iam:group:admin", group.Mrn, "Group MRN should match")
		assert.NotEmpty(t, group.Roles, "Group should have roles")
		assert.Equal(t, "mrn:iam:role:admin", group.Roles[0], "Group should contain admin role")
		assert.NotNil(t, group.Annotations, "Annotations should be initialized")
		// Annotations should be populated from the domain
		assert.Equal(t, 2, len(group.Annotations), "Admin group should have 2 annotations")
		assert.Equal(t, "admin", group.Annotations["group_level"], "Group level annotation should be 'admin'")
		assert.Equal(t, "system", group.Annotations["group_type"], "Group type annotation should be 'system'")
	})

	t.Run("GetGroup - not found", func(t *testing.T) {
		simpleFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{simpleFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting a non-existent group
		group, policyErr := be.GetGroup(context.Background(), "mrn:iam:group:nonexistent")
		assert.NotNil(t, policyErr, "Should return policy error")
		assert.Nil(t, group, "Group should be nil")
		assert.Contains(t, policyErr.Error(), "group not found", "Error should indicate group not found")
	})

	t.Run("GetGroup - consolidated domain with annotations", func(t *testing.T) {
		consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{consolidatedFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting admin group from consolidated domain
		adminGroup, policyErr := be.GetGroup(context.Background(), "mrn:iam:group:admin")
		require.Nil(t, policyErr, "Should not return policy error for admin group")
		require.NotNil(t, adminGroup, "Admin group should not be nil")
		assert.Equal(t, "mrn:iam:group:admin", adminGroup.Mrn, "Admin group MRN should match")
		assert.Equal(t, 1, len(adminGroup.Roles), "Admin group should have 1 role")
		assert.Equal(t, "mrn:iam:role:admin", adminGroup.Roles[0], "Admin group should contain admin role")

		// Verify annotations are present
		assert.Equal(t, 2, len(adminGroup.Annotations), "Admin group should have 2 annotations")
		assert.Equal(t, "admin", adminGroup.Annotations["group_level"], "Admin group should have group_level annotation")
		assert.Equal(t, "system", adminGroup.Annotations["group_type"], "Admin group should have group_type annotation")
	})
}

// Test GetResourceGroup method
func TestGetResourceGroup(t *testing.T) {
	t.Run("GetResourceGroup - consolidated domain with annotations", func(t *testing.T) {
		consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{consolidatedFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting an existing resource group with annotations
		rg, policyErr := be.GetResourceGroup(context.Background(), "mrn:iam:resource-group:allow-all")
		require.Nil(t, policyErr, "Should not return policy error")
		require.NotNil(t, rg, "Resource group should not be nil")
		assert.Equal(t, "mrn:iam:resource-group:allow-all", rg.Mrn, "Resource group MRN should match")
		assert.NotNil(t, rg.Annotations, "Annotations should be initialized")
		// Annotations should be populated from the domain
		assert.Equal(t, 3, len(rg.Annotations), "Allow-all resource group should have 3 annotations")
		assert.Equal(t, float64(42), rg.Annotations["foo"], "Foo annotation should be 42")
		//assert.Equal(t, "[1, 2, 3]", rg.Annotations["bar"], "Bar annotation should be [1, 2, 3]")
		//assert.Equal(t, "{\"bat\": 42}", rg.Annotations["baz"], "Baz annotation should be {\"bat\": 42}")
	})

	t.Run("GetResourceGroup - not found", func(t *testing.T) {
		consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{consolidatedFile})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting a non-existent resource group
		rg, policyErr := be.GetResourceGroup(context.Background(), "mrn:iam:resource-group:nonexistent")
		assert.NotNil(t, policyErr, "Should return policy error")
		assert.Nil(t, rg, "Resource group should be nil")
		assert.Contains(t, policyErr.Error(), "resource group not found", "Error should indicate resource group not found")
	})
}

// Test GetResource method with v1alpha4 resources
func TestGetResource(t *testing.T) {
	t.Run("GetResource - match sensitive data resource", func(t *testing.T) {
		v1alpha4File := createTempFileFromTestData(t, "v1alpha4-resources.yml")

		be, err := createBackend([]string{v1alpha4File})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting a resource that matches the sensitive-data selector
		res, policyErr := be.GetResource(context.Background(), "mrn:data:sensitive:doc123")
		require.Nil(t, policyErr, "Should not return policy error")
		require.NotNil(t, res, "Resource should not be nil")
		assert.Equal(t, "mrn:data:sensitive:doc123", res.ID, "Resource ID should match input MRN")
		assert.Equal(t, "mrn:iam:resource-group:sensitive", res.Group, "Resource should be in sensitive group")
		assert.Equal(t, "HIGH", res.Annotations["classification"], "Classification annotation should be HIGH")
	})

	t.Run("GetResource - match restricted data resource", func(t *testing.T) {
		v1alpha4File := createTempFileFromTestData(t, "v1alpha4-resources.yml")

		be, err := createBackend([]string{v1alpha4File})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting a resource that matches the restricted-data selector
		res, policyErr := be.GetResource(context.Background(), "mrn:data:restricted:secret456")
		require.Nil(t, policyErr, "Should not return policy error")
		require.NotNil(t, res, "Resource should not be nil")
		assert.Equal(t, "mrn:data:restricted:secret456", res.ID, "Resource ID should match input MRN")
		assert.Equal(t, "mrn:iam:resource-group:restricted", res.Group, "Resource should be in restricted group")
		assert.Equal(t, "MAXIMUM", res.Annotations["classification"], "Classification annotation should be MAXIMUM")
		assert.Equal(t, true, res.Annotations["audit_required"], "audit_required annotation should be true")
	})

	t.Run("GetResource - match secret resource via second selector", func(t *testing.T) {
		v1alpha4File := createTempFileFromTestData(t, "v1alpha4-resources.yml")

		be, err := createBackend([]string{v1alpha4File})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting a resource that matches the second selector (mrn:secret:.*)
		res, policyErr := be.GetResource(context.Background(), "mrn:secret:api-key")
		require.Nil(t, policyErr, "Should not return policy error")
		require.NotNil(t, res, "Resource should not be nil")
		assert.Equal(t, "mrn:secret:api-key", res.ID, "Resource ID should match input MRN")
		assert.Equal(t, "mrn:iam:resource-group:restricted", res.Group, "Resource should be in restricted group")
	})

	t.Run("GetResource - fall back to default resource group", func(t *testing.T) {
		v1alpha4File := createTempFileFromTestData(t, "v1alpha4-resources.yml")

		be, err := createBackend([]string{v1alpha4File})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting a resource that doesn't match any selector - should fall back to default
		res, policyErr := be.GetResource(context.Background(), "mrn:app:public:item789")
		require.Nil(t, policyErr, "Should not return policy error")
		require.NotNil(t, res, "Resource should not be nil")
		assert.Equal(t, "mrn:app:public:item789", res.ID, "Resource ID should match input MRN")
		assert.Equal(t, "mrn:iam:resource-group:default", res.Group, "Resource should fall back to default group")
		assert.Empty(t, res.Annotations, "Annotations should be empty for default fallback")
	})

	t.Run("GetResource - fall back with v1alpha3 domain", func(t *testing.T) {
		// Test that v1alpha3 domains (no Resources) fall back to default resource group
		consolidatedFile := createTempFileFromTestData(t, "consolidated.yml")

		be, err := createBackend([]string{consolidatedFile})
		require.Nil(t, err, "Backend creation should succeed")

		// consolidated.yml has a default resource group but no Resources defined
		res, policyErr := be.GetResource(context.Background(), "mrn:any:resource:test")
		require.Nil(t, policyErr, "Should not return policy error")
		require.NotNil(t, res, "Resource should not be nil")
		assert.Equal(t, "mrn:any:resource:test", res.ID, "Resource ID should match input MRN")
		assert.Equal(t, "mrn:iam:resource-group:allow-all", res.Group, "Resource should use default group from consolidated.yml")
	})
}

// Test v1alpha4 parser
func TestV1Alpha4Parser(t *testing.T) {
	t.Run("Load v1alpha4 domain with resources", func(t *testing.T) {
		v1alpha4File := createTempFileFromTestData(t, "v1alpha4-resources.yml")

		be, err := createBackend([]string{v1alpha4File})
		require.Nil(t, err, "Backend creation should succeed")

		// Verify the mapper exists
		mapper, policyErr := be.GetMapper(context.Background(), "")
		require.Nil(t, policyErr, "Should find mapper")
		assert.NotNil(t, mapper, "Mapper should not be nil")
		assert.Equal(t, "v1alpha4-test", mapper.Domain, "Should load v1alpha4 domain")
	})

	t.Run("v1alpha4 operations work correctly", func(t *testing.T) {
		v1alpha4File := createTempFileFromTestData(t, "v1alpha4-resources.yml")

		be, err := createBackend([]string{v1alpha4File})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting an operation
		op, policyErr := be.GetOperation(context.Background(), "test:operation")
		require.Nil(t, policyErr, "Should find operation")
		require.NotNil(t, op, "Operation should not be nil")
		assert.Equal(t, "mrn:iam:policy:allow-all", op.Policy.Mrn, "Operation should use allow-all policy")
	})

	t.Run("v1alpha4 roles work correctly", func(t *testing.T) {
		v1alpha4File := createTempFileFromTestData(t, "v1alpha4-resources.yml")

		be, err := createBackend([]string{v1alpha4File})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting a role
		role, policyErr := be.GetRole(context.Background(), "mrn:iam:role:admin")
		require.Nil(t, policyErr, "Should find role")
		require.NotNil(t, role, "Role should not be nil")
		assert.Equal(t, "mrn:iam:role:admin", role.Mrn, "Role MRN should match")
		assert.Equal(t, "mrn:iam:policy:allow-all", role.Policy.Mrn, "Role should use allow-all policy")
	})

	t.Run("v1alpha4 scopes work correctly", func(t *testing.T) {
		v1alpha4File := createTempFileFromTestData(t, "v1alpha4-resources.yml")

		be, err := createBackend([]string{v1alpha4File})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting a scope
		scope, policyErr := be.GetScope(context.Background(), "mrn:iam:scope:api")
		require.Nil(t, policyErr, "Should find scope")
		require.NotNil(t, scope, "Scope should not be nil")
		assert.Equal(t, "mrn:iam:scope:api", scope.Mrn, "Scope MRN should match")
	})

	t.Run("v1alpha4 resource groups work correctly", func(t *testing.T) {
		v1alpha4File := createTempFileFromTestData(t, "v1alpha4-resources.yml")

		be, err := createBackend([]string{v1alpha4File})
		require.Nil(t, err, "Backend creation should succeed")

		// Test getting resource groups
		rg, policyErr := be.GetResourceGroup(context.Background(), "mrn:iam:resource-group:sensitive")
		require.Nil(t, policyErr, "Should find resource group")
		require.NotNil(t, rg, "Resource group should not be nil")
		assert.Equal(t, "mrn:iam:resource-group:sensitive", rg.Mrn, "Resource group MRN should match")
		assert.Equal(t, "mrn:iam:policy:read-only", rg.Policy.Mrn, "Resource group should use read-only policy")
	})
}

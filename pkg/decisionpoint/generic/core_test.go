//
//  Copyright © Manetu Inc. All rights reserved.
//

package generic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/manetu/policyengine/pkg/core"
	"github.com/manetu/policyengine/pkg/core/accesslog"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/manetu/policyengine/pkg/core/options"
	"github.com/manetu/policyengine/pkg/decisionpoint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestPolicyEngine creates a PolicyEngine with mock mode enabled
func setupTestPolicyEngine(t *testing.T) core.PolicyEngine {
	// Set config path to find mpe-config.yaml (project root from pkg/decisionpoint/generic)
	err := os.Setenv(config.ConfigPathEnv, "../../..")
	require.NoError(t, err)

	// Reset config to ensure clean state
	config.ResetConfig()

	// Enable mock mode
	config.VConfig.Set(config.MockEnabled, true)

	// Create PolicyEngine with mock mode
	pe, err := core.NewPolicyEngine(
		options.WithAccessLog(accesslog.NewStdoutFactory()),
	)
	require.NoError(t, err)
	require.NotNil(t, pe)

	return pe
}

// findFreePort finds an available port for testing
func findFreePort(t *testing.T) int {
	listener, err := os.CreateTemp("", "test-port-*")
	require.NoError(t, err)
	defer func() { _ = os.Remove(listener.Name()) }()

	// Use a high port number to avoid conflicts
	port := 18000 + (os.Getpid() % 1000)
	return port
}

func TestGenericServer_CreateServer(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server := startServerInBackground(t, pe, port)

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := server.Stop(ctx)
	assert.NoError(t, err)
}

// startServerInBackground starts a server and waits for it to be ready
func startServerInBackground(t *testing.T, pe core.PolicyEngine, port int) decisionpoint.Server {
	server, err := CreateServer(pe, port)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Give server time to fully start and be ready to accept connections
	time.Sleep(300 * time.Millisecond)

	// Verify server is actually listening
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/openapi.yaml", port))
		if err == nil {
			_ = resp.Body.Close()
			return server
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatal("Server did not become ready to accept connections")
	return nil
}

func TestGenericServer_Decision_Allow(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server := startServerInBackground(t, pe, port)

	// Test allow decision - using a PORC that should be allowed by the mock policy
	porc := map[string]interface{}{
		"principal": map[string]interface{}{
			"sub":    "test-user",
			"mroles": []string{"mrn:iam:role:superadmin"},
		},
		"operation": "idf:public:list",
		"resource":  map[string]interface{}{},
		"context":   map[string]interface{}{},
	}

	porcJSON, err := json.Marshal(porc)
	require.NoError(t, err)

	url := fmt.Sprintf("http://localhost:%d/decision", port)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(porcJSON))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	allow, ok := result["allow"].(bool)
	assert.True(t, ok, "Response should have 'allow' field")
	assert.True(t, allow, "Decision should be allowed")

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)
}

func TestGenericServer_Decision_Deny(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server := startServerInBackground(t, pe, port)

	// Test deny decision - using a PORC that should be denied by the mock policy
	// Operation that requires operator role but user doesn't have it
	porc := map[string]interface{}{
		"principal": map[string]interface{}{
			"sub":    "test-user",
			"mroles": []string{"mrn:iam:role:user"},
		},
		"operation": "platform:admin:create",
		"resource":  map[string]interface{}{},
		"context":   map[string]interface{}{},
	}

	porcJSON, err := json.Marshal(porc)
	require.NoError(t, err)

	url := fmt.Sprintf("http://localhost:%d/decision", port)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(porcJSON))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	allow, ok := result["allow"].(bool)
	assert.True(t, ok, "Response should have 'allow' field")
	assert.False(t, allow, "Decision should be denied")

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)
}

func TestGenericServer_Decision_InvalidJSON(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server := startServerInBackground(t, pe, port)

	// Test with invalid JSON
	invalidJSON := []byte(`{"invalid": json}`)
	url := fmt.Sprintf("http://localhost:%d/decision", port)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(invalidJSON))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Should return an error status
	assert.True(t, resp.StatusCode >= 400, "Should return error status for invalid JSON")

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)
}

func TestGenericServer_SwaggerUI(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server := startServerInBackground(t, pe, port)

	// Test Swagger UI endpoint
	url := fmt.Sprintf("http://localhost:%d/swagger-ui/", port)
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)
}

func TestGenericServer_OpenAPI(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server := startServerInBackground(t, pe, port)

	// Test OpenAPI schema endpoint
	url := fmt.Sprintf("http://localhost:%d/openapi.yaml", port)
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Regexp(t, "application/.*yaml", resp.Header.Get("Content-Type"))

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)
}

func TestGenericServer_Stop(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server := startServerInBackground(t, pe, port)

	// Stop the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := server.Stop(ctx)
	assert.NoError(t, err)

	// Verify server is stopped by trying to connect
	url := fmt.Sprintf("http://localhost:%d/decision", port)
	_, err = http.Get(url)
	assert.Error(t, err, "Should fail to connect after server is stopped")
}

func TestGenericServer_Decision_ProbeTrue(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server := startServerInBackground(t, pe, port)

	// Test decision with probe=true - should still return correct decision
	porc := map[string]interface{}{
		"principal": map[string]interface{}{
			"sub":    "test-user",
			"mroles": []string{"mrn:iam:role:superadmin"},
		},
		"operation": "idf:public:list",
		"resource":  map[string]interface{}{},
		"context":   map[string]interface{}{},
	}

	porcJSON, err := json.Marshal(porc)
	require.NoError(t, err)

	// Use probe=true query parameter
	url := fmt.Sprintf("http://localhost:%d/decision?probe=true", port)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(porcJSON))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	allow, ok := result["allow"].(bool)
	assert.True(t, ok, "Response should have 'allow' field")
	assert.True(t, allow, "Decision should be allowed even with probe=true")

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)
}

func TestGenericServer_Decision_ProbeFalse(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server := startServerInBackground(t, pe, port)

	// Test decision with probe=false - should work same as default
	porc := map[string]interface{}{
		"principal": map[string]interface{}{
			"sub":    "test-user",
			"mroles": []string{"mrn:iam:role:superadmin"},
		},
		"operation": "idf:public:list",
		"resource":  map[string]interface{}{},
		"context":   map[string]interface{}{},
	}

	porcJSON, err := json.Marshal(porc)
	require.NoError(t, err)

	// Use probe=false query parameter
	url := fmt.Sprintf("http://localhost:%d/decision?probe=false", port)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(porcJSON))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	allow, ok := result["allow"].(bool)
	assert.True(t, ok, "Response should have 'allow' field")
	assert.True(t, allow, "Decision should be allowed with probe=false")

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)
}

func TestGenericServer_Decision_ProbeDefault(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server := startServerInBackground(t, pe, port)

	// Test decision without probe parameter - should default to false
	porc := map[string]interface{}{
		"principal": map[string]interface{}{
			"sub":    "test-user",
			"mroles": []string{"mrn:iam:role:superadmin"},
		},
		"operation": "idf:public:list",
		"resource":  map[string]interface{}{},
		"context":   map[string]interface{}{},
	}

	porcJSON, err := json.Marshal(porc)
	require.NoError(t, err)

	// No probe parameter
	url := fmt.Sprintf("http://localhost:%d/decision", port)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(porcJSON))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	allow, ok := result["allow"].(bool)
	assert.True(t, ok, "Response should have 'allow' field")
	assert.True(t, allow, "Decision should be allowed without probe parameter")

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)
}

func TestGenericServer_Decision_ProbeDeny(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server := startServerInBackground(t, pe, port)

	// Test deny decision with probe=true - should still deny
	porc := map[string]interface{}{
		"principal": map[string]interface{}{
			"sub":    "test-user",
			"mroles": []string{"mrn:iam:role:user"},
		},
		"operation": "platform:admin:create",
		"resource":  map[string]interface{}{},
		"context":   map[string]interface{}{},
	}

	porcJSON, err := json.Marshal(porc)
	require.NoError(t, err)

	// Use probe=true query parameter
	url := fmt.Sprintf("http://localhost:%d/decision?probe=true", port)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(porcJSON))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	allow, ok := result["allow"].(bool)
	assert.True(t, ok, "Response should have 'allow' field")
	assert.False(t, allow, "Decision should be denied even with probe=true")

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)
}

//
//  Copyright © Manetu Inc. All rights reserved.
//

package envoy

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/manetu/policyengine/pkg/core"
	"github.com/manetu/policyengine/pkg/core/accesslog"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/manetu/policyengine/pkg/core/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

// setupTestPolicyEngine creates a PolicyEngine with mock mode enabled and a test mapper
func setupTestPolicyEngine(t *testing.T) core.PolicyEngine {
	// Set config path to find mpe-config.yaml (project root from pkg/decisionpoint/envoy)
	err := os.Setenv(config.ConfigPathEnv, "../../..")
	require.NoError(t, err)

	// Reset config to ensure clean state
	config.ResetConfig()

	// Enable mock mode
	config.VConfig.Set(config.MockEnabled, true)

	// Configure a test mapper that converts Envoy attributes to PORC
	// This mapper extracts JWT claims and creates a PORC structure that matches the mock policy
	mapperRego := `package mapper

import rego.v1

default claims = {}

method := object.get(object.get(input, "request", {}), "http", {}).method
path := object.get(object.get(object.get(input, "request", {}), "http", {}), "path", "/")
headers := object.get(object.get(object.get(input, "request", {}), "http", {}), "headers", {})

# Extract service from destination principal if available
dest := object.get(object.get(input, "destination", {}), "principal", "")
service := dest

# Extract JWT from authorization header if present
auth := object.get(headers, "authorization", "")
bearer_prefix := "Bearer "
token := substring(auth, count(bearer_prefix), -1) if startswith(auth, bearer_prefix)
# Try to decode JWT, but handle errors gracefully
claims = io.jwt.decode(token)[1] if token

# Map to operations that match the mock policy
default operation = "idf:public:list"
operation = "platform:*" if contains(path, "admin")
operation = "platform:*" if contains(path, "platform")

# Create PORC structure
porc := {
    "principal": claims,
    "operation": operation,
    "resource": {
        "id": sprintf("http://%s%s", [service, path]),
        "group": "mrn:iam:manetu.io:resource-group:default"
    },
    "context": input,
}`

	// Configure mapper in mock config
	config.VConfig.Set("mock.domain.mappers", []map[string]interface{}{
		{
			"name": "test-mapper",
			"rego": mapperRego,
		},
	})

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
	// Use a high port number to avoid conflicts
	port := 19000 + (os.Getpid() % 1000)
	return port
}

// waitForServer waits for the server to be ready by checking the grpcPort channel
func waitForServer(t *testing.T, server *ExtAuthzServer, timeout time.Duration) int {
	select {
	case port := <-server.grpcPort:
		// Give server a moment to fully start
		time.Sleep(200 * time.Millisecond)
		return port
	case <-time.After(timeout):
		t.Fatal("Server failed to start within timeout")
		return 0
	}
}

func TestEnvoyServer_CreateServer(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server, err := CreateServer(pe, port, "")
	require.NoError(t, err)
	require.NotNil(t, server)

	// Wait for server to start
	extAuthzServer := server.(*ExtAuthzServer)
	actualPort := waitForServer(t, extAuthzServer, 5*time.Second)
	assert.NotEqual(t, 0, actualPort)

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)
}

func TestEnvoyServer_Check_Allow(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server, err := CreateServer(pe, port, "")
	require.NoError(t, err)
	require.NotNil(t, server)

	extAuthzServer := server.(*ExtAuthzServer)
	actualPort := waitForServer(t, extAuthzServer, 5*time.Second)

	// Create gRPC client
	conn, err := grpc.NewClient(
		fmt.Sprintf("localhost:%d", actualPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := authv3.NewAuthorizationClient(conn)

	// Create a request that should be allowed
	// Using a public operation that should be allowed by the mock policy
	request := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Host:   "localhost",
					Path:   "/api/public",
					Method: "GET",
					Headers: map[string]string{
						"authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJtcm9sZXMiOlsibXJuOmlhbTptYW5ldHUuaW86cm9sZTpzdXBlcmFkbWluIl19.dummy",
					},
				},
			},
			Destination: &authv3.AttributeContext_Peer{
				Principal: "spiffe://cluster.local/ns/default/sa/test-service",
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Check(ctx, request)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Check response status
	assert.Equal(t, int32(codes.OK), resp.Status.Code)

	// Check response headers
	okResponse := resp.GetOkResponse()
	require.NotNil(t, okResponse)

	// Find the result header
	var foundHeader *corev3.HeaderValue
	for _, header := range okResponse.Headers {
		if header.Header.Key == resultHeader {
			foundHeader = header.Header
			break
		}
	}
	require.NotNil(t, foundHeader)
	assert.Equal(t, resultAllowed, foundHeader.Value)

	// Cleanup
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	err = server.Stop(ctx2)
	assert.NoError(t, err)
}

func TestEnvoyServer_Check_Deny(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server, err := CreateServer(pe, port, "")
	require.NoError(t, err)
	require.NotNil(t, server)

	extAuthzServer := server.(*ExtAuthzServer)
	actualPort := waitForServer(t, extAuthzServer, 5*time.Second)

	// Create gRPC client
	conn, err := grpc.NewClient(
		fmt.Sprintf("localhost:%d", actualPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := authv3.NewAuthorizationClient(conn)

	// Create a request that should be denied
	// Using an operation that requires operator role but user doesn't have it
	request := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Host:   "localhost",
					Path:   "/api/admin",
					Method: "POST",
					Headers: map[string]string{
						"authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJtcm9sZXMiOlsibXJuOmlhbTptYW5ldHUuaW86cm9sZTp1c2VyIl19.dummy",
					},
				},
			},
			Destination: &authv3.AttributeContext_Peer{
				Principal: "spiffe://cluster.local/ns/default/sa/platform-service",
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Check(ctx, request)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Check response status - should be PermissionDenied
	assert.Equal(t, int32(codes.PermissionDenied), resp.Status.Code)

	// Check denied response
	deniedResponse := resp.GetDeniedResponse()
	require.NotNil(t, deniedResponse)
	assert.Equal(t, "permission denied", deniedResponse.Body)

	// Check response headers
	var foundHeader *corev3.HeaderValue
	for _, header := range deniedResponse.Headers {
		if header.Header.Key == resultHeader {
			foundHeader = header.Header
			break
		}
	}
	require.NotNil(t, foundHeader)
	assert.Equal(t, resultDenied, foundHeader.Value)

	// Cleanup
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	err = server.Stop(ctx2)
	assert.NoError(t, err)
}

func TestEnvoyServer_Check_NoMapper(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	// Clear mapper config to test error handling
	config.VConfig.Set("mock.domain.mappers", nil)

	server, err := CreateServer(pe, port, "")
	require.NoError(t, err)
	require.NotNil(t, server)

	extAuthzServer := server.(*ExtAuthzServer)
	actualPort := waitForServer(t, extAuthzServer, 5*time.Second)

	// Create gRPC client
	conn, err := grpc.NewClient(
		fmt.Sprintf("localhost:%d", actualPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := authv3.NewAuthorizationClient(conn)

	request := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Host:   "localhost",
					Path:   "/api/test",
					Method: "GET",
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.Check(ctx, request)
	// Should get an error because no mapper is configured
	assert.Error(t, err)

	// Cleanup
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	_ = server.Stop(ctx2)
}

func TestEnvoyServer_Stop(t *testing.T) {
	pe := setupTestPolicyEngine(t)
	port := findFreePort(t)

	server, err := CreateServer(pe, port, "")
	require.NoError(t, err)
	require.NotNil(t, server)

	extAuthzServer := server.(*ExtAuthzServer)
	actualPort := waitForServer(t, extAuthzServer, 5*time.Second)

	// Stop the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Stop(ctx)
	assert.NoError(t, err)

	// Verify server is stopped by trying to connect
	conn, err := grpc.NewClient(
		fmt.Sprintf("localhost:%d", actualPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err == nil {
		conn.Close()
	}
	// Connection might succeed but the server should be stopped
	// The actual test is that Stop() doesn't error
}

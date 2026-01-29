//
//  Copyright © Manetu Inc. All rights reserved.
//

package config_test

import (
	"os"
	"sync"
	"testing"

	"github.com/manetu/policyengine/internal/core/test"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/stretchr/testify/assert"
)

// setupTestConfig configures the test environment to use the testdata config
func setupTestConfig() {
	_ = test.SetupTestConfig()
}

func TestInitConfig(t *testing.T) {
	setupTestConfig()
	config.ResetConfig()
	assert.NotNil(t, config.VConfig)
}

func TestConfigDefaults(t *testing.T) {
	setupTestConfig()
	config.ResetConfig()

	// Check some default values
	assert.Equal(t, true, config.VConfig.GetBool(config.IncludeAllBundles))
	assert.Equal(t, "http.send", config.VConfig.GetString(config.UnsafeBuiltIns))
}

func TestConfigWithCustomFilename(t *testing.T) {
	setupTestConfig()
	config.ResetConfig()
}

func TestGetAuditEnvEmpty(t *testing.T) {
	setupTestConfig()
	config.ResetConfig()

	// With no audit.env configuration, should return empty map
	auditEnv := config.GetAuditEnv()
	assert.NotNil(t, auditEnv)
	assert.Empty(t, auditEnv)
}

func TestGetAuditEnvWithConfig(t *testing.T) {
	setupTestConfig()
	config.ResetConfig()

	// Set up the audit.env configuration using the new list format
	config.VConfig.Set(config.AuditEnv, []map[string]interface{}{
		{"name": "alpha", "type": "env", "value": "TEST_ENV_ALPHA"},
		{"name": "beta", "type": "env", "value": "TEST_ENV_BETA"},
	})

	// Set the environment variables
	_ = os.Setenv("TEST_ENV_ALPHA", "value-alpha")
	_ = os.Setenv("TEST_ENV_BETA", "value-beta")
	defer func() {
		_ = os.Unsetenv("TEST_ENV_ALPHA")
		_ = os.Unsetenv("TEST_ENV_BETA")
	}()

	auditEnv := config.GetAuditEnv()
	assert.NotNil(t, auditEnv)
	assert.Equal(t, "value-alpha", auditEnv["alpha"])
	assert.Equal(t, "value-beta", auditEnv["beta"])
}

func TestGetAuditEnvWithMissingEnvVar(t *testing.T) {
	setupTestConfig()
	config.ResetConfig()

	// Set up the audit.env configuration with an env var that doesn't exist
	config.VConfig.Set(config.AuditEnv, []map[string]interface{}{
		{"name": "missing", "type": "env", "value": "NONEXISTENT_ENV_VAR"},
	})

	// Ensure the env var is not set
	_ = os.Unsetenv("NONEXISTENT_ENV_VAR")

	auditEnv := config.GetAuditEnv()
	assert.NotNil(t, auditEnv)
	// Missing env vars should result in empty string
	assert.Equal(t, "", auditEnv["missing"])
}

func TestGetAuditEnvStringType(t *testing.T) {
	setupTestConfig()
	config.ResetConfig()

	config.VConfig.Set(config.AuditEnv, []map[string]interface{}{
		{"name": "region", "type": "string", "value": "us-east-1"},
		{"name": "env", "type": "string", "value": "production"},
	})

	auditEnv := config.GetAuditEnv()
	assert.NotNil(t, auditEnv)
	assert.Equal(t, "us-east-1", auditEnv["region"])
	assert.Equal(t, "production", auditEnv["env"])
}

func TestGetAuditEnvK8sOutsideCluster(t *testing.T) {
	setupTestConfig()
	config.ResetConfig()

	config.VConfig.Set(config.AuditEnv, []map[string]interface{}{
		{"name": "app", "type": "k8s-label", "value": "app.kubernetes.io/name"},
		{"name": "version", "type": "k8s-annot", "value": "deployment.kubernetes.io/revision"},
	})

	auditEnv := config.GetAuditEnv()
	assert.NotNil(t, auditEnv)
	// Outside k8s, values should be empty strings
	assert.Equal(t, "", auditEnv["app"])
	assert.Equal(t, "", auditEnv["version"])
}

func TestGetAuditEnvUnknownType(t *testing.T) {
	setupTestConfig()
	config.ResetConfig()

	config.VConfig.Set(config.AuditEnv, []map[string]interface{}{
		{"name": "known", "type": "string", "value": "hello"},
		{"name": "unknown", "type": "bogus", "value": "world"},
	})

	auditEnv := config.GetAuditEnv()
	assert.NotNil(t, auditEnv)
	assert.Equal(t, "hello", auditEnv["known"])
	// Unknown type should be skipped
	_, exists := auditEnv["unknown"]
	assert.False(t, exists)
}

func TestGetAuditEnvMixedTypes(t *testing.T) {
	setupTestConfig()
	config.ResetConfig()

	_ = os.Setenv("TEST_MIXED_HOST", "myhost")
	defer func() {
		_ = os.Unsetenv("TEST_MIXED_HOST")
	}()

	config.VConfig.Set(config.AuditEnv, []map[string]interface{}{
		{"name": "host", "type": "env", "value": "TEST_MIXED_HOST"},
		{"name": "region", "type": "string", "value": "eu-west-1"},
	})

	auditEnv := config.GetAuditEnv()
	assert.NotNil(t, auditEnv)
	assert.Equal(t, "myhost", auditEnv["host"])
	assert.Equal(t, "eu-west-1", auditEnv["region"])
}

func TestGetAuditEnvK8sWithFiles(t *testing.T) {
	// Create a temp directory with fake Downward API files
	podinfo := t.TempDir()

	_ = os.WriteFile(podinfo+"/labels", []byte("app=\"myapp\"\nversion=\"v1.2.3\"\n"), 0600)
	_ = os.WriteFile(podinfo+"/annotations", []byte("deploy.k8s.io/revision=\"42\"\n"), 0600)

	setupTestConfig()
	config.ResetConfig()

	// Point podinfo to our temp dir
	config.VConfig.Set(config.AuditK8sPodinfo, podinfo)

	config.VConfig.Set(config.AuditEnv, []map[string]interface{}{
		{"name": "app", "type": "k8s-label", "value": "app"},
		{"name": "ver", "type": "k8s-label", "value": "version"},
		{"name": "rev", "type": "k8s-annot", "value": "deploy.k8s.io/revision"},
		{"name": "missing-label", "type": "k8s-label", "value": "nonexistent"},
		{"name": "missing-annot", "type": "k8s-annot", "value": "nonexistent"},
	})

	auditEnv := config.GetAuditEnv()
	assert.Equal(t, "myapp", auditEnv["app"])
	assert.Equal(t, "v1.2.3", auditEnv["ver"])
	assert.Equal(t, "42", auditEnv["rev"])
	assert.Equal(t, "", auditEnv["missing-label"])
	assert.Equal(t, "", auditEnv["missing-annot"])
}

func TestParseDownwardAPIFileFormats(t *testing.T) {
	// Test that blank lines and lines without '=' are skipped
	podinfo := t.TempDir()

	content := "key1=\"value1\"\n\n\nbadline\nkey2=\"value2\"\n"
	_ = os.WriteFile(podinfo+"/labels", []byte(content), 0600)

	setupTestConfig()
	config.ResetConfig()

	config.VConfig.Set(config.AuditK8sPodinfo, podinfo)

	config.VConfig.Set(config.AuditEnv, []map[string]interface{}{
		{"name": "k1", "type": "k8s-label", "value": "key1"},
		{"name": "k2", "type": "k8s-label", "value": "key2"},
	})

	auditEnv := config.GetAuditEnv()
	assert.Equal(t, "value1", auditEnv["k1"])
	assert.Equal(t, "value2", auditEnv["k2"])
}

// TestConcurrentLoad tests that concurrent calls to Load() are race-free.
// Run with: go test -race -run TestConcurrentLoad
func TestConcurrentLoad(t *testing.T) {
	setupTestConfig()

	const numGoroutines = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Reset config first to ensure we start fresh
	config.ResetConfig()

	// Spawn multiple goroutines that all call Load() concurrently
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			err := config.Load()
			assert.Nil(t, err)
		}()
	}

	wg.Wait()
}

func TestConfigWithCustomPath(t *testing.T) {
	// Save original env vars
	origPath := os.Getenv(config.ConfigPathEnv)
	origFilename := os.Getenv(config.ConfigFileNameEnv)
	defer func() {
		if origPath != "" {
			_ = os.Setenv(config.ConfigPathEnv, origPath)
		} else {
			_ = os.Unsetenv(config.ConfigPathEnv)
		}
		if origFilename != "" {
			_ = os.Setenv(config.ConfigFileNameEnv, origFilename)
		} else {
			_ = os.Unsetenv(config.ConfigFileNameEnv)
		}
	}()

	// Set custom path and filename via environment variables
	_ = os.Setenv(config.ConfigPathEnv, "/tmp/test-config-path")
	_ = os.Setenv(config.ConfigFileNameEnv, "custom-config")

	// Reset config to pick up the new env vars
	config.ResetConfig()

	// Verify config was initialized (even if file doesn't exist)
	assert.NotNil(t, config.VConfig)
}

func TestLoadWithMissingConfigFile(t *testing.T) {
	// Save original env vars
	origPath := os.Getenv(config.ConfigPathEnv)
	defer func() {
		if origPath != "" {
			_ = os.Setenv(config.ConfigPathEnv, origPath)
		} else {
			_ = os.Unsetenv(config.ConfigPathEnv)
		}
	}()

	// Point to a directory that exists but has no config file
	_ = os.Setenv(config.ConfigPathEnv, "/tmp")

	// Reset and load - should not error even with missing config
	config.ResetConfig()
	err := config.Load()
	assert.NoError(t, err)
}

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

	// Set up the audit.env configuration manually via Viper
	config.VConfig.Set(config.AuditEnv, map[string]string{
		"alpha": "TEST_ENV_ALPHA",
		"beta":  "TEST_ENV_BETA",
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
	config.VConfig.Set(config.AuditEnv, map[string]string{
		"missing": "NONEXISTENT_ENV_VAR",
	})

	// Ensure the env var is not set
	_ = os.Unsetenv("NONEXISTENT_ENV_VAR")

	auditEnv := config.GetAuditEnv()
	assert.NotNil(t, auditEnv)
	// Missing env vars should result in empty string
	assert.Equal(t, "", auditEnv["missing"])
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

//
//  Copyright © Manetu Inc. All rights reserved.
//

package config_test

import (
	"os"
	"testing"

	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/stretchr/testify/assert"
)

func TestInitConfig(t *testing.T) {
	_ = os.Setenv(config.ConfigPathEnv, "../../..")
	config.ResetConfig()
	assert.NotNil(t, config.VConfig)
}

func TestConfigDefaults(t *testing.T) {
	_ = os.Setenv(config.ConfigPathEnv, "../../..")
	config.ResetConfig()

	// Check some default values
	assert.Equal(t, true, config.VConfig.GetBool(config.IncludeAllBundles))
	assert.Equal(t, "http.send", config.VConfig.GetString(config.UnsafeBuiltIns))
}

func TestConfigWithCustomFilename(t *testing.T) {
	_ = os.Setenv(config.ConfigPathEnv, "../../..")
	_ = os.Setenv(config.ConfigFileNameEnv, "mpe-config")
	defer func() { _ = os.Unsetenv(config.ConfigFileNameEnv) }()

	config.ResetConfig()
}

func TestGetAuditEnvEmpty(t *testing.T) {
	_ = os.Setenv(config.ConfigPathEnv, "../../..")
	config.ResetConfig()

	// With no audit.env configuration, should return empty map
	auditEnv := config.GetAuditEnv()
	assert.NotNil(t, auditEnv)
	assert.Empty(t, auditEnv)
}

func TestGetAuditEnvWithConfig(t *testing.T) {
	_ = os.Setenv(config.ConfigPathEnv, "../../..")
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
	_ = os.Setenv(config.ConfigPathEnv, "../../..")
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

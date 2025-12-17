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

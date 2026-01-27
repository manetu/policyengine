//
//  Copyright © Manetu Inc. All rights reserved.
//

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetConfigPath_WithEnvVar(t *testing.T) {
	// Save original and restore after test
	orig := os.Getenv(ConfigPathEnv)
	defer func() {
		if orig != "" {
			_ = os.Setenv(ConfigPathEnv, orig)
		} else {
			_ = os.Unsetenv(ConfigPathEnv)
		}
	}()

	// Set custom path
	_ = os.Setenv(ConfigPathEnv, "/custom/config/path")

	result := getConfigPath()
	assert.Equal(t, "/custom/config/path", result)
}

func TestGetConfigPath_Default(t *testing.T) {
	// Save original and restore after test
	orig := os.Getenv(ConfigPathEnv)
	defer func() {
		if orig != "" {
			_ = os.Setenv(ConfigPathEnv, orig)
		} else {
			_ = os.Unsetenv(ConfigPathEnv)
		}
	}()

	// Ensure env var is not set
	_ = os.Unsetenv(ConfigPathEnv)

	result := getConfigPath()
	assert.Equal(t, ConfigDefaultPath, result)
}

func TestGetConfigFileName_WithEnvVar(t *testing.T) {
	// Save original and restore after test
	orig := os.Getenv(ConfigFileNameEnv)
	defer func() {
		if orig != "" {
			_ = os.Setenv(ConfigFileNameEnv, orig)
		} else {
			_ = os.Unsetenv(ConfigFileNameEnv)
		}
	}()

	// Set custom filename
	_ = os.Setenv(ConfigFileNameEnv, "custom-config-name")

	result := getConfigFileName()
	assert.Equal(t, "custom-config-name", result)
}

func TestGetConfigFileName_Default(t *testing.T) {
	// Save original and restore after test
	orig := os.Getenv(ConfigFileNameEnv)
	defer func() {
		if orig != "" {
			_ = os.Setenv(ConfigFileNameEnv, orig)
		} else {
			_ = os.Unsetenv(ConfigFileNameEnv)
		}
	}()

	// Ensure env var is not set
	_ = os.Unsetenv(ConfigFileNameEnv)

	result := getConfigFileName()
	assert.Equal(t, ConfigDefaultFilename, result)
}

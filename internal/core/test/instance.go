//
//  Copyright © Manetu Inc. All rights reserved.
//

package test

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/manetu/policyengine/internal/core/accesslog"
	"github.com/manetu/policyengine/pkg/core"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/manetu/policyengine/pkg/core/options"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

// TestConfigFilename is the name of the test configuration file (without extension).
const TestConfigFilename = "mpe-config"

// GetTestdataPath returns the absolute path to the testdata directory.
// This uses runtime.Caller to locate the source file and compute the path
// relative to it, ensuring tests work regardless of the working directory.
func GetTestdataPath() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		// Fallback to relative path if runtime.Caller fails
		return "testdata"
	}
	// thisFile is internal/core/test/instance.go
	// We need to go up 3 levels to reach the project root, then into testdata
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))))
	return filepath.Join(projectRoot, "testdata")
}

// SetupTestConfig configures the environment to use the test configuration.
// This sets both MPE_CONFIG_PATH and MPE_CONFIG_FILENAME to ensure tests
// use the correct configuration regardless of user environment variables.
func SetupTestConfig() error {
	if err := os.Setenv(config.ConfigPathEnv, GetTestdataPath()); err != nil {
		return err
	}
	if err := os.Setenv(config.ConfigFileNameEnv, TestConfigFilename); err != nil {
		return err
	}
	return nil
}

// NewTestPolicyEngine - instantiates a PE suitable for unit-testing.
// It uses the test configuration from the testdata directory.
func NewTestPolicyEngine(depth int) (core.PolicyEngine, chan *events.AccessRecord, error) {
	if err := SetupTestConfig(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *events.AccessRecord, depth)
	engine, err := core.NewPolicyEngine(
		options.WithAccessLog(accesslog.NewChannelLogger(ch)),
	)
	if err != nil {
		return nil, nil, err
	}

	return engine, ch, nil
}

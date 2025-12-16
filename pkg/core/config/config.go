//
//  Copyright © Manetu Inc. All rights reserved.
//

package config

import (
	"os"
	"strings"
	"sync"

	"github.com/manetu/policyengine/internal/logging"
	"github.com/spf13/viper"
)

// EnvVarPrefix is used in viper to set the prefix for Environment Variables
// ConfigPathEnv is an expected Environment Variable containing the path to the config file
const (
	EnvVarPrefix          string = "MPE"
	ConfigPathEnv         string = "MPE_CONFIG_PATH"
	ConfigFileNameEnv     string = "MPE_CONFIG_FILENAME"
	ConfigDefaultPath     string = "."
	ConfigDefaultFilename string = "mpe-config"
)

const (
	logLevel string = "log.level"

	// MockEnabled set to true overrides any supplied Backend with a mock, allowing applications to unit-test
	MockEnabled string = "mock.enabled"

	// UnsafeBuiltIns is a comma separated list of REGO built-in functions to remove from OPA capabilities
	UnsafeBuiltIns string = "opa.unsafebuiltins"

	// IncludeAllBundles defaults true.  If false, includes only up to final decision
	IncludeAllBundles string = "bundles.includeall"
)

var (
	once sync.Once

	// VConfig main viper-based config instance
	VConfig *viper.Viper
	logger  = logging.GetLogger("policyengine.config")
)

// Init performs lazy initialization of the config system.
// This is called automatically by Load() but can be called explicitly if needed.
func Init() {
	once.Do(func() {
		doInitialize()
	})
}

func getConfigPath() string {
	configPath, ok := os.LookupEnv(ConfigPathEnv)
	if ok {
		return configPath
	}

	return ConfigDefaultPath
}

func getConfigFileName() string {
	configName, ok := os.LookupEnv(ConfigFileNameEnv)
	if ok {
		return configName
	}

	return ConfigDefaultFilename
}

func doInitialize() {
	VConfig = viper.New()

	// set up config-file loading:  default is './mpe-config.yaml' but can be overridden with $(MPE_CONFIG_PATH)/$(MPE_CONFIG_FILENAME).yaml
	VConfig.AddConfigPath(getConfigPath())
	VConfig.SetConfigName(getConfigFileName())
	VConfig.SetConfigType("yaml")

	// set up envvar handling:  keys such as 'log.level' become 'MPE_LOG_LEVEL'
	VConfig.SetEnvPrefix(EnvVarPrefix)
	VConfig.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	VConfig.AutomaticEnv()

	// set up VConfig defaults
	VConfig.SetDefault(logLevel, ".:info")
	VConfig.SetDefault(UnsafeBuiltIns, "http.send")
	VConfig.SetDefault(IncludeAllBundles, true) // includes all bundles in AccessRecord by default.
}

// Load finalizes the loading of the configuration.
func Load() error {
	Init()

	// Add the path specified by the env var.
	err := VConfig.ReadInConfig()
	if err != nil {
		logger.SysWarnf("error reading config; using defaults: %+v", err)
		// fall through to continue loading
	}

	loglevel := VConfig.GetString(logLevel)
	if err := logging.UpdateLogLevels(loglevel); err != nil {
		logger.SysErrorf("Failed updating log level %s: %+v", loglevel, err)
		return err
	}

	if logger.IsDebugEnabled() {
		VConfig.DebugTo(logger.Out())
	}

	return nil
}

// ResetConfig releases any currently read configuration (used mainly for tests - be careful!).
func ResetConfig() {
	VConfig = nil
	once = sync.Once{} // reset the sync.Once to allow re-initialization
	Init()
	// ignore any reset errors
	_ = Load()
}

//
//  Copyright © Manetu Inc. All rights reserved.
//

// Package config provides configuration management for the policy engine
// using [Viper] for flexible configuration sources.
//
// Configuration can be provided via:
//   - YAML configuration files
//   - Environment variables with the MPE_ prefix
//   - Programmatic defaults
//
// # Configuration File
//
// By default, the engine looks for mpe-config.yaml in the current directory.
// Override the location using environment variables:
//
//	MPE_CONFIG_PATH=/etc/policyengine
//	MPE_CONFIG_FILENAME=production-config
//
// Example configuration file:
//
//	log:
//	  level: ".:info"
//	mock:
//	  enabled: false
//	opa:
//	  unsafebuiltins: "http.send"
//	audit:
//	  env:
//	    pod: HOSTNAME
//	    region: AWS_REGION
//
// # Environment Variables
//
// All configuration keys can be set via environment variables with the MPE_
// prefix. Dots in key names become underscores:
//
//	MPE_LOG_LEVEL=.:debug
//	MPE_MOCK_ENABLED=true
//	MPE_OPA_UNSAFEBUILTINS=http.send,opa.runtime
//
// # Configuration Keys
//
// Available configuration options:
//   - log.level: Log level configuration (default: ".:info")
//   - mock.enabled: Use mock backend instead of configured backend
//   - opa.unsafebuiltins: Comma-separated list of Rego built-ins to disable
//   - bundles.includeall: Include all policy bundles in access records (default: true)
//   - audit.env: Map of access log metadata keys to environment variable names
//
// [Viper]: https://github.com/spf13/viper
package config

import (
	"errors"
	"os"
	"strings"
	"sync"

	"github.com/manetu/policyengine/internal/logging"
	"github.com/spf13/viper"
)

// Environment variable and default path constants for configuration loading.
const (
	// EnvVarPrefix is the prefix for all policy engine environment variables.
	// For example, the key "log.level" becomes MPE_LOG_LEVEL.
	EnvVarPrefix string = "MPE"

	// ConfigPathEnv is the environment variable that specifies the directory
	// containing the configuration file.
	ConfigPathEnv string = "MPE_CONFIG_PATH"

	// ConfigFileNameEnv is the environment variable that specifies the
	// configuration file name (without extension).
	ConfigFileNameEnv string = "MPE_CONFIG_FILENAME"

	// ConfigDefaultPath is the default directory to search for config files.
	ConfigDefaultPath string = "."

	// ConfigDefaultFilename is the default configuration file name (without extension).
	ConfigDefaultFilename string = "mpe-config"
)

// Configuration key constants for use with [VConfig].
const (
	logLevel string = "log.level"

	// MockEnabled when set to true causes the policy engine to use a mock
	// backend regardless of any backend configured via [options.WithBackend].
	// This is useful for unit testing applications that use the policy engine.
	//
	// Set via environment: MPE_MOCK_ENABLED=true
	MockEnabled string = "mock.enabled"

	// UnsafeBuiltIns is a comma-separated list of Rego built-in function names
	// to remove from OPA capabilities. This prevents policies from using
	// potentially dangerous functions like http.send.
	//
	// Default: "http.send"
	// Set via environment: MPE_OPA_UNSAFEBUILTINS=http.send,opa.runtime
	UnsafeBuiltIns string = "opa.unsafebuiltins"

	// IncludeAllBundles controls whether all evaluated policy bundles are
	// included in access log records, or only the final decision bundle.
	//
	// Default: true (include all bundles)
	// Set via environment: MPE_BUNDLES_INCLUDEALL=false
	IncludeAllBundles string = "bundles.includeall"

	// AuditEnv defines a mapping from access log metadata keys to environment
	// variable names. The values of the specified environment variables are
	// included in every access log record.
	//
	// Example config:
	//
	//	audit:
	//	  env:
	//	    pod: HOSTNAME
	//	    region: AWS_REGION
	AuditEnv string = "audit.env"
)

var (
	once     sync.Once
	loadOnce sync.Once
	loadErr  error

	// VConfig is the global Viper configuration instance for the policy engine.
	//
	// VConfig provides access to all configuration values. Use the configuration
	// key constants ([MockEnabled], [UnsafeBuiltIns], etc.) to access specific
	// settings:
	//
	//	if config.VConfig.GetBool(config.MockEnabled) {
	//	    // Using mock backend
	//	}
	//
	// VConfig is initialized automatically when [Load] or [Init] is called.
	// In most cases, applications don't need to access VConfig directly;
	// configuration is handled automatically by [core.NewPolicyEngine].
	VConfig *viper.Viper
	logger  = logging.GetLogger("policyengine.config")
)

// Init initializes the configuration system without loading config files.
//
// Init sets up Viper with:
//   - Configuration file paths and names
//   - Environment variable handling (MPE_ prefix)
//   - Default values for all configuration keys
//
// This function is safe to call multiple times; subsequent calls are no-ops.
// Most applications don't need to call Init directly; it's called automatically
// by [Load], which is called by [core.NewPolicyEngine].
//
// Call Init explicitly only if you need to set Viper defaults before [Load]
// reads the configuration file.
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

// Load initializes configuration and loads settings from files and environment.
//
// Load performs the following steps:
//  1. Calls [Init] if not already called
//  2. Reads the configuration file (if present; missing files are not an error)
//  3. Applies environment variable overrides
//  4. Updates log levels based on configuration
//
// This function is safe to call concurrently from multiple goroutines.
// Subsequent calls after the first successful load are no-ops that return nil.
//
// Load is called automatically by [core.NewPolicyEngine]. Most applications
// don't need to call it directly.
//
// Returns an error if log level configuration is invalid.
func Load() error {
	loadOnce.Do(func() {
		Init()

		// Early log level update from environment variable allows us to debug the config loading.
		earlyLoglevel := os.Getenv("MPE_LOG_LEVEL")
		if earlyLoglevel != "" {
			if err := logging.UpdateLogLevels(earlyLoglevel); err != nil {
				logger.SysErrorf("Failed updating early log level %s: %+v", earlyLoglevel, err)
				loadErr = err
				return
			}
		}

		logger.SysDebugf("Loading configuration from %s/%s.yaml", getConfigPath(), getConfigFileName())
		// Add the path specified by the env var.
		err := VConfig.ReadInConfig()
		if err != nil {
			// Only log if it's an actual error, not just a missing config file
			var configNotFound viper.ConfigFileNotFoundError
			if !errors.As(err, &configNotFound) {
				logger.SysWarnf("error reading config; using defaults: %+v", err)
			}
			// fall through to continue loading
			logger.SysDebugf("No config file found at %s/%s.yaml", getConfigPath(), getConfigFileName())
		}

		// Update log levels based on final configuration
		loglevel := VConfig.GetString(logLevel)
		if err := logging.UpdateLogLevels(loglevel); err != nil {
			logger.SysErrorf("Failed updating log level %s: %+v", loglevel, err)
			loadErr = err
			return
		}

		if logger.IsDebugEnabled() {
			VConfig.DebugTo(logger.Out())
		}
	})

	return loadErr
}

// ResetConfig clears all configuration and reinitializes with defaults.
//
// WARNING: This function is intended for testing only. It resets the global
// configuration state, which can cause race conditions in concurrent code.
//
// After calling ResetConfig, the configuration system is reinitialized with
// default values. Any previously loaded configuration file or environment
// variable overrides are discarded.
func ResetConfig() {
	VConfig = nil
	once = sync.Once{}     // reset the sync.Once to allow re-initialization
	loadOnce = sync.Once{} // reset the loadOnce to allow re-loading
	loadErr = nil          // reset any previous load error
	Init()
	// ignore any reset errors
	_ = Load()
}

// GetAuditEnv returns resolved audit environment metadata for access log records.
//
// This function reads the audit.env configuration section and resolves each
// configured environment variable to its current value. The result is a map
// suitable for inclusion in access log records as metadata.
//
// Configuration format:
//
//	audit:
//	  env:
//	    pod: HOSTNAME
//	    region: AWS_REGION
//
// With HOSTNAME=pod-123 and AWS_REGION=us-east-1, this returns:
//
//	{"pod": "pod-123", "region": "us-east-1"}
//
// Environment variables that are not set will have empty string values in the
// result. Returns an empty map if no audit.env configuration is present.
func GetAuditEnv() map[string]string {
	result := make(map[string]string)

	envConfig := VConfig.GetStringMapString(AuditEnv)
	if envConfig == nil {
		return result
	}

	for key, envVarName := range envConfig {
		result[key] = os.Getenv(envVarName)
	}

	return result
}

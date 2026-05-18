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
//	    - name: pod
//	      type: env
//	      value: HOSTNAME
//	    - name: region
//	      type: string
//	      value: us-east-1
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
//   - audit.env: List of typed entries for access log metadata (supports env, string, k8s-label, k8s-annot)
//   - audit.k8s.podinfo: Path to Kubernetes Downward API podinfo directory (default: "/etc/podinfo")
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

// AuditEnvType identifies the source type for an audit environment entry.
type AuditEnvType string

const (
	// AuditEnvTypeEnv resolves the value as an environment variable name.
	AuditEnvTypeEnv AuditEnvType = "env"

	// AuditEnvTypeString uses the value as a literal string.
	AuditEnvTypeString AuditEnvType = "string"

	// AuditEnvTypeK8sLabel looks up the value in Kubernetes pod labels
	// via the Downward API. The podinfo directory is configurable via
	// [AuditK8sPodinfo] (default: /etc/podinfo).
	AuditEnvTypeK8sLabel AuditEnvType = "k8s-label"

	// AuditEnvTypeK8sAnnot looks up the value in Kubernetes pod annotations
	// via the Downward API. The podinfo directory is configurable via
	// [AuditK8sPodinfo] (default: /etc/podinfo).
	AuditEnvTypeK8sAnnot AuditEnvType = "k8s-annot"
)

// AuditEnvEntry represents a single typed entry in the audit.env configuration.
type AuditEnvEntry struct {
	Name  string       `mapstructure:"name"`
	Type  AuditEnvType `mapstructure:"type"`
	Value string       `mapstructure:"value"`
}

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

	// AuditEnv defines a list of typed entries for access log metadata.
	// Each entry specifies a name (the key in the AccessRecord), a type
	// (how to resolve the value), and a value (interpreted per type).
	//
	// Supported types:
	//   - env: resolve value as an environment variable name
	//   - string: use value as a literal string
	//   - k8s-label: look up value in Kubernetes pod labels (via Downward API)
	//   - k8s-annot: look up value in Kubernetes pod annotations (via Downward API)
	//
	// Example config:
	//
	//	audit:
	//	  env:
	//	    - name: pod
	//	      type: env
	//	      value: HOSTNAME
	//	    - name: region
	//	      type: string
	//	      value: us-east-1
	AuditEnv string = "audit.env"

	// AuditK8sPodinfo specifies the directory where Kubernetes Downward API
	// files (labels and annotations) are mounted.
	//
	// Default: "/etc/podinfo"
	// Set via environment: MPE_AUDIT_K8S_PODINFO=/custom/path
	AuditK8sPodinfo string = "audit.k8s.podinfo"

	// AuxDataPath specifies the directory where auxiliary data files are mounted.
	// When set, all files in this directory are loaded and made available to
	// the mapper as input.auxdata, allowing Rego policies to reference
	// external configuration data.
	//
	// Set via environment: MPE_AUXDATA_PATH=/etc/mpe/auxdata
	AuxDataPath string = "auxdata.path"
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
	VConfig.SetDefault(IncludeAllBundles, true)         // includes all bundles in AccessRecord by default.
	VConfig.SetDefault(AuditK8sPodinfo, "/etc/podinfo") // default Downward API mount path
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
	resetK8sCache()        // reset cached Downward API data
	Init()
	// ignore any reset errors
	_ = Load()
}

// GetAuditEnv returns resolved audit environment metadata for access log records.
//
// This function reads the audit.env configuration section and resolves each
// entry according to its type. The result is a map suitable for inclusion in
// access log records as metadata.
//
// Configuration format:
//
//	audit:
//	  env:
//	    - name: pod
//	      type: env
//	      value: HOSTNAME
//	    - name: region
//	      type: string
//	      value: us-east-1
//
// With HOSTNAME=pod-123, this returns:
//
//	{"pod": "pod-123", "region": "us-east-1"}
//
// Missing environment variables or unavailable Kubernetes metadata result in
// empty string values. Returns an empty map if no audit.env configuration is
// present.
func GetAuditEnv() map[string]string {
	result := make(map[string]string)

	var entries []AuditEnvEntry
	if err := VConfig.UnmarshalKey(AuditEnv, &entries); err != nil {
		// Check if the old map format is being used
		if old := VConfig.GetStringMapString(AuditEnv); len(old) > 0 {
			logger.SysErrorf("audit.env uses the old map format which is no longer supported; please migrate to the new list format (see documentation)")
			return result
		}
		return result
	}

	for _, entry := range entries {
		switch entry.Type {
		case AuditEnvTypeEnv:
			result[entry.Name] = os.Getenv(entry.Value)
		case AuditEnvTypeString:
			result[entry.Name] = entry.Value
		case AuditEnvTypeK8sLabel:
			labels := getK8sLabels()
			if labels != nil {
				result[entry.Name] = labels[entry.Value]
			} else {
				result[entry.Name] = ""
			}
		case AuditEnvTypeK8sAnnot:
			annotations := getK8sAnnotations()
			if annotations != nil {
				result[entry.Name] = annotations[entry.Value]
			} else {
				result[entry.Name] = ""
			}
		default:
			logger.SysWarnf("audit.env: unknown type %q for entry %q, skipping", entry.Type, entry.Name)
		}
	}

	return result
}

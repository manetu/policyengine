//
//  Copyright © Manetu Inc. All rights reserved.
//

package logging

//lint:file-ignore U1001 Ignore all unused code, it's external

import (
	"strings"
	"sync"

	"go.uber.org/zap/zapcore"
)

// LogManager keeps track of all instantiated loggers
type LogManager struct {
	loggers  map[string]*Logger
	defLevel zapcore.Level
}

// Manager's singleton variables
var (
	manager *LogManager
	mu      sync.RWMutex
	once    sync.Once
)

// resetForTesting resets the manager state - only for testing
func resetForTesting() {
	mu.Lock()
	defer mu.Unlock()
	manager = nil
	once = sync.Once{}
}

// GetLogger returns a logger for the specified module
func GetLogger(module string) *Logger {
	once.Do(func() {
		initManager()
	})

	mu.RLock()
	aLogger := manager.loggers[module]
	if aLogger != nil {
		mu.RUnlock()
		return aLogger
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring write lock
	if aLogger := manager.loggers[module]; aLogger != nil {
		return aLogger
	}

	// Create new logger with default level
	aLogger = newLogger(module)
	aLogger.SetLevel(manager.defLevel)
	manager.loggers[module] = aLogger

	return aLogger
}

func initManager() {
	manager = &LogManager{
		loggers:  make(map[string]*Logger),
		defLevel: zapcore.InfoLevel,
	}
}

// parseLevel converts a string level to zapcore.Level
func parseLevel(levelStr string) (zapcore.Level, error) {
	switch strings.ToLower(levelStr) {
	case "panic":
		return zapcore.PanicLevel, nil
	case "fatal":
		return zapcore.FatalLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	case "warn", "warning":
		return zapcore.WarnLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "debug", "trace":
		return zapcore.DebugLevel, nil
	default:
		return zapcore.InfoLevel, nil // Return InfoLevel as default, no error
	}
}

// UpdateLogLevels updates log levels from a string of the form:
// "mod1:debug;mod2:error;.:info"
// Allows whitespace for readability
func UpdateLogLevels(logstr string) error {
	once.Do(func() {
		initManager()
	})

	// Strip whitespace
	ws := []string{" ", "\t", "\n"}
	for _, s := range ws {
		logstr = strings.ReplaceAll(logstr, s, "")
	}

	mu.Lock()
	defer mu.Unlock()

	// Track which modules have explicit levels set
	explicitModules := make(map[string]bool)
	var defaultLevel zapcore.Level
	hasDefault := false

	logs := strings.Split(logstr, ";")

	// First pass: process all non-default entries
	for _, l := range logs {
		parts := strings.Split(l, ":")
		if len(parts) != 2 {
			continue
		}

		module := parts[0]
		levelStr := parts[1]

		level, err := parseLevel(levelStr)
		if err != nil {
			continue
		}

		if module == "." {
			// Store default level to apply later
			defaultLevel = level
			hasDefault = true
		} else {
			// Update specific module
			explicitModules[module] = true
			logger := manager.loggers[module]
			if logger == nil {
				// Create logger if it doesn't exist
				logger = newLogger(module)
				manager.loggers[module] = logger
			}
			logger.SetLevel(level)
		}
	}

	// Second pass: apply default level to non-explicit modules and update defLevel
	if hasDefault {
		manager.defLevel = defaultLevel
		// Only update loggers that don't have explicit levels
		for mod, logger := range manager.loggers {
			if !explicitModules[mod] {
				logger.SetLevel(defaultLevel)
			}
		}
	}

	return nil
}

//
//  Copyright © Manetu Inc. All rights reserved.
//

package logging

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
)

func TestGetLogger(t *testing.T) {
	// Reset manager for clean test
	resetForTesting()

	// Get logger - should create with default level
	l := GetLogger("testmodule")
	assert.NotNil(t, l)
	assert.Equal(t, l.IsLevelEnabled(zapcore.InfoLevel), true)
	assert.Equal(t, l.IsLevelEnabled(zapcore.DebugLevel), false)
}

func TestUpdateConfigFromString(t *testing.T) {
	// Reset manager for clean test
	resetForTesting()

	// Set up initial config
	err := UpdateLogLevels(".:info;module1:debug;module2:warn")
	assert.NoError(t, err)

	// Test module1 should be debug
	l1 := GetLogger("module1")
	assert.Equal(t, l1.IsLevelEnabled(zapcore.DebugLevel), true)

	// Test module2 should be warn
	l2 := GetLogger("module2")
	assert.Equal(t, l2.IsLevelEnabled(zapcore.WarnLevel), true)
	assert.Equal(t, l2.IsLevelEnabled(zapcore.InfoLevel), false)

	// Test undeclared module should get default (info)
	l3 := GetLogger("undeclaredModule")
	assert.Equal(t, l3.IsLevelEnabled(zapcore.InfoLevel), true)
	assert.Equal(t, l3.IsLevelEnabled(zapcore.DebugLevel), false)

	// Update default level to debug
	err = UpdateLogLevels(".:debug")
	assert.NoError(t, err)

	// New undeclared module should get debug
	l4 := GetLogger("undeclaredModule2")
	assert.Equal(t, l4.IsLevelEnabled(zapcore.DebugLevel), true)

	// Existing undeclared module should also be updated to debug
	assert.Equal(t, l3.IsLevelEnabled(zapcore.DebugLevel), true)
}

func TestUpdateConfigFromStringWithWhitespace(t *testing.T) {
	// Reset manager for clean test
	resetForTesting()

	// Test with whitespace
	err := UpdateLogLevels("  mod1: debug  ;  mod2: error  ;  .: info  ")
	assert.NoError(t, err)

	l1 := GetLogger("mod1")
	assert.Equal(t, l1.IsLevelEnabled(zapcore.DebugLevel), true)

	l2 := GetLogger("mod2")
	assert.Equal(t, l2.IsLevelEnabled(zapcore.ErrorLevel), true)
	assert.Equal(t, l2.IsLevelEnabled(zapcore.WarnLevel), false)
}

func TestTraceLevelMapsToDebug(t *testing.T) {
	// Reset manager for clean test
	resetForTesting()

	// Set trace level - should map to debug since zap doesn't support trace
	err := UpdateLogLevels(".:trace")
	assert.NoError(t, err)

	l := GetLogger("testmodule")
	assert.Equal(t, true, l.IsLevelEnabled(zapcore.DebugLevel))
	assert.Equal(t, true, l.IsTraceEnabled())
}

// TestRaceCondition makes sure that logger support multi-threaded caller;
// that is, we don't have a race condition in the logger.
func TestRaceCondition(t *testing.T) {
	// Reset manager for clean test
	resetForTesting()

	done := make(chan bool, 15)
	for i := 0; i < 15; i++ {
		go func(k int) {
			module := fmt.Sprintf("module%d", k)
			l := GetLogger(module)
			l.SysDebug("this is a test")
			done <- true
		}(i % 5)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 15; i++ {
		<-done
	}
}

//
//  Copyright © Manetu Inc. All rights reserved.
//

package logging

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
)

func TestLogging(t *testing.T) {
	//t.Skip()
	logger := newLogger("testmodule")
	var buffer bytes.Buffer
	logger.SetOut(&buffer)
	logger.SetLevel(zapcore.InfoLevel)

	// As default, the logging level must be at info
	assert.Equal(t, logger.IsLevelEnabled(zapcore.InfoLevel), true)
	// Debug should be off
	assert.Equal(t, logger.IsLevelEnabled(zapcore.DebugLevel), false)

	// Note: We'll handle panic separately below

	actorID := "tester"
	actionID := "123abc"

	// Debug log should not be printed
	logger.Debug(actorID, actionID, "debug message")
	logger.Debugf(actorID, actionID, "debug message %s", "hello")
	assert.Empty(t, buffer.Bytes())

	//assert.Equal(t, string(buffer.Bytes()), "")

	// The other logs should be printed
	buffer.Reset()
	logger.Info(actorID, actionID, "info message")
	assert.NotEmpty(t, buffer.Bytes())
	buffer.Reset()
	logger.Infof(actorID, actionID, "info message %s", "hello")
	assert.NotEmpty(t, buffer.Bytes())
	buffer.Reset()
	logger.Warn(actorID, actionID, "warning message")
	assert.NotEmpty(t, buffer.Bytes())
	buffer.Reset()
	logger.Warnf(actorID, actionID, "warning message %s", "hello")
	assert.NotEmpty(t, buffer.Bytes())
	buffer.Reset()
	logger.Error(actorID, actionID, "error message")
	assert.NotEmpty(t, buffer.Bytes())
	buffer.Reset()
	logger.Errorf(actorID, actionID, "error message %s", "hello")
	assert.NotEmpty(t, buffer.Bytes())
	// Note: Fatal calls os.Exit() which would terminate the test, so we skip those
	// buffer.Reset()
	// logger.Fatal(actorID, actionID, "fatal message")
	// assert.NotEmpty(t, buffer.Bytes())
	// buffer.Reset()
	// logger.Fatalf(actorID, actionID, "fatal message %s", "hello")
	// assert.NotEmpty(t, buffer.Bytes())

	// Test panic (will be caught by defer)
	buffer.Reset()
	defer func() {
		if r := recover(); r != nil {
			// Panic was caught, check that something was logged
			assert.NotEmpty(t, buffer.Bytes(), "Panic should have logged something")
		}
	}()
	logger.Panic(actorID, actionID, "panic message")
}

func TestSysLogging(t *testing.T) {
	//t.Skip()
	logger := newLogger("testsysmodule")
	var buffer bytes.Buffer
	logger.SetOut(&buffer)

	// Change logging level to error and test
	logger.SetLevel(zapcore.ErrorLevel)
	assert.Equal(t, logger.IsLevelEnabled(zapcore.ErrorLevel), true)

	// trap panic log
	defer func() {
		if r := recover(); r != nil {
			t.Log("Recovered")
		}
		// Log panic must have been written out
		assert.NotEmpty(t, buffer.Bytes())

	}()

	// debug, info, and warning levels should be off
	assert.Equal(t, logger.IsLevelEnabled(zapcore.DebugLevel), false)
	assert.Equal(t, logger.IsLevelEnabled(zapcore.InfoLevel), false)
	assert.Equal(t, logger.IsLevelEnabled(zapcore.WarnLevel), false)

	logger.SysDebug("debug message")
	logger.SysDebugf("debug message %s", "hello")
	logger.SysInfo("info message")
	logger.SysInfof("info message %s", "hello")
	logger.SysWarn("warning message")
	logger.SysWarnf("warning message %s", "hello")
	assert.Empty(t, buffer.Bytes())

	buffer.Reset()
	logger.SysError("error message")
	assert.NotEmpty(t, buffer.Bytes())
	buffer.Reset()
	logger.SysErrorf("error message %s", "hello")
	assert.NotEmpty(t, buffer.Bytes())
	// Note: Fatal calls os.Exit() which would terminate the test, so we skip those
	// buffer.Reset()
	// logger.SysFatal("fatal message")
	// assert.NotEmpty(t, buffer.Bytes())
	// buffer.Reset()
	// logger.SysFatalf("fatal message %s", "hello")
	// assert.NotEmpty(t, buffer.Bytes())

	// Test panic (will be caught by defer)
	buffer.Reset()
	defer func() {
		if r := recover(); r != nil {
			// Panic was caught, check that something was logged
			assert.NotEmpty(t, buffer.Bytes(), "Panic should have logged something")
		}
	}()
	logger.SysPanic("panic message")
}

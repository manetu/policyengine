//
//  Copyright © Manetu Inc. All rights reserved.
//

package logging

import (
	"io"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

//lint:file-ignore U1001 Ignore all unused code, it's external

// Logger is a wrapper around zap.Logger
type Logger struct {
	module string
	logger *zap.Logger
	sugar  *zap.SugaredLogger
	level  zapcore.Level
	writer io.Writer // For compatibility with tests and viper
}

const (
	actor     = "actor"
	action    = "action"
	defActor  = "sys"
	defAction = "unk"
	module    = "module"
)

// internal function to create a logger without tracking. Application should
// call GetLogger() to retrieved a configured logger.
func newLogger(module string) *Logger {
	// Configure encoder
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder

	// Determine formatter from environment
	var encoder zapcore.Encoder
	logFormatter := os.Getenv("LOG_FORMATTER")
	switch logFormatter {
	case "text":
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	default:
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	// Determine if we should report caller
	reportCaller := os.Getenv("LOG_REPORT_CALLER") != ""

	// Create core
	core := zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zapcore.InfoLevel)

	// Build logger
	options := []zap.Option{
		zap.AddCallerSkip(1), // Skip this wrapper function
	}
	if reportCaller {
		options = append(options, zap.AddCaller())
	}

	logger := zap.New(core, options...)

	return &Logger{
		module: module,
		logger: logger,
		sugar:  logger.Sugar(),
		level:  zapcore.InfoLevel,
	}
}

// IsDebugEnabled returns true if the current logging level is debug or higher.
// This function should be used as condition guard to logging debug where a lot
// of computation is needed to generate log output and in a performance critical
// location.
//
//	Ex   if logger.IsDebugEnabled() {
//	         computing what to pass to debug call
//	         logger.Debugf()
//	     }
func (l *Logger) IsDebugEnabled() bool {
	return l.level <= zapcore.DebugLevel
}

// IsTraceEnabled ...
func (l *Logger) IsTraceEnabled() bool {
	return l.level <= zapcore.DebugLevel // zap doesn't have trace, use debug
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level zapcore.Level) {
	l.level = level
	// Recreate the logger with the new level
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder

	var encoder zapcore.Encoder
	logFormatter := os.Getenv("LOG_FORMATTER")
	switch logFormatter {
	case "text":
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	default:
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	reportCaller := os.Getenv("LOG_REPORT_CALLER") != ""

	// Use custom writer if set, otherwise use stdout
	var output io.Writer = os.Stdout
	if l.writer != nil {
		output = l.writer
	}

	core := zapcore.NewCore(encoder, zapcore.AddSync(output), level)

	options := []zap.Option{
		zap.AddCallerSkip(1),
	}
	if reportCaller {
		options = append(options, zap.AddCaller())
	}

	l.logger = zap.New(core, options...)
	l.sugar = l.logger.Sugar()
}

// IsLevelEnabled checks if a level is enabled
func (l *Logger) IsLevelEnabled(level zapcore.Level) bool {
	return l.level <= level
}

// Out is for compatibility with tests and viper - returns the output writer
func (l *Logger) Out() io.Writer {
	if l.writer != nil {
		return l.writer
	}
	return os.Stdout
}

// SetOut sets the output writer (for tests)
func (l *Logger) SetOut(w io.Writer) {
	l.writer = w
	// Recreate logger with custom writer
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder

	var encoder zapcore.Encoder
	logFormatter := os.Getenv("LOG_FORMATTER")
	switch logFormatter {
	case "text":
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	default:
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	reportCaller := os.Getenv("LOG_REPORT_CALLER") != ""
	core := zapcore.NewCore(encoder, zapcore.AddSync(w), l.level)

	options := []zap.Option{
		zap.AddCallerSkip(1),
	}
	if reportCaller {
		options = append(options, zap.AddCaller())
	}

	l.logger = zap.New(core, options...)
	l.sugar = l.logger.Sugar()
}

// Fatal logs fatal message
func (l *Logger) Fatal(actorID, actionID string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Fatal(args...)
}

// Fatalf logs fatal message
func (l *Logger) Fatalf(actorID, actionID string, format string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Fatalf(format, args...)
}

// Panic logs panic message
func (l *Logger) Panic(actorID, actionID string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Panic(args...)
}

// Panicf logs panic message
func (l *Logger) Panicf(actorID, actionID string, format string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Panicf(format, args...)
}

// Trace log trace message
func (l *Logger) Trace(actorID, actionID string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Debug(args...)
}

// Tracef log trace message
func (l *Logger) Tracef(actorID, actionID string, format string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Debugf(format, args...)
}

// Debug log debug message
func (l *Logger) Debug(actorID, actionID string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Debug(args...)
}

// Debugf log debug message
func (l *Logger) Debugf(actorID, actionID string, format string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Debugf(format, args...)
}

// Info logs info message
func (l *Logger) Info(actorID, actionID string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Info(args...)
}

// Infof logs info message
func (l *Logger) Infof(actorID, actionID string, format string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Infof(format, args...)
}

// Warn logs warning message
func (l *Logger) Warn(actorID, actionID string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Warn(args...)
}

// Warnf logs warning message
func (l *Logger) Warnf(actorID, actionID string, format string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Warnf(format, args...)
}

// Error logs error message
func (l *Logger) Error(actorID, actionID string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Error(args...)
}

// Errorf logs error message
func (l *Logger) Errorf(actorID, actionID string, format string, args ...interface{}) {
	l.sugar.With(
		zap.String(actor, actorID),
		zap.String(action, actionID),
		zap.String(module, l.module),
	).Errorf(format, args...)
}

// Below are functions using default actor and action

// SysFatal logs fatal message with default actor and action
func (l *Logger) SysFatal(args ...interface{}) {
	l.Fatal(defActor, defAction, args...)
}

// SysFatalf logs fatal message with default actor and action
func (l *Logger) SysFatalf(format string, args ...interface{}) {
	l.Fatalf(defActor, defAction, format, args...)
}

// SysPanic logs panic message with default actor and action
func (l *Logger) SysPanic(args ...interface{}) {
	l.Panic(defActor, defAction, args...)
}

// SysPanicf logs panic message with default actor and action
func (l *Logger) SysPanicf(format string, args ...interface{}) {
	l.Panicf(defActor, defAction, format, args...)
}

// SysTrace logs trace message with default actor and action
func (l *Logger) SysTrace(args ...interface{}) {
	l.Trace(defActor, defAction, args...)
}

// SysTracef logs trace message with default actor and action
func (l *Logger) SysTracef(format string, args ...interface{}) {
	l.Tracef(defActor, defAction, format, args...)
}

// SysDebug logs debug message with default actor and action
func (l *Logger) SysDebug(args ...interface{}) {
	l.Debug(defActor, defAction, args...)
}

// SysDebugf logs debug message with default actor and action
func (l *Logger) SysDebugf(format string, args ...interface{}) {
	l.Debugf(defActor, defAction, format, args...)
}

// SysInfo logs info message with default actor and action
func (l *Logger) SysInfo(args ...interface{}) {
	l.Info(defActor, defAction, args...)
}

// SysInfof logs info message with default actor and action
func (l *Logger) SysInfof(format string, args ...interface{}) {
	l.Infof(defActor, defAction, format, args...)
}

// SysWarn logs warning message with default actor and action
func (l *Logger) SysWarn(args ...interface{}) {
	l.Warn(defActor, defAction, args...)
}

// SysWarnf logs warning message with default actor and action
func (l *Logger) SysWarnf(format string, args ...interface{}) {
	l.Warnf(defActor, defAction, format, args...)
}

// SysError logs error message with default actor and action
func (l *Logger) SysError(args ...interface{}) {
	l.Error(defActor, defAction, args...)
}

// SysErrorf logs error message with default actor and action
func (l *Logger) SysErrorf(format string, args ...interface{}) {
	l.Errorf(defActor, defAction, format, args...)
}

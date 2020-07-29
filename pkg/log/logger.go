package log

import (
	"fmt"
	"log"
	"os"
)

var stdoutLogger = log.New(os.Stdout, "INFO:  ", log.LUTC|log.Ldate|log.Ltime|log.Lshortfile)
var errorLogger = log.New(os.Stderr, "ERROR: ", log.LUTC|log.Ldate|log.Ltime|log.Lshortfile)
var isDebug = false

// Error log and error to stderr
func Error(errorMessage string, args ...interface{}) error {
	errorLogger.Output(2, fmt.Sprintf(errorMessage, args...))
	return fmt.Errorf(errorMessage, args...)
}

// Info log info to stdout
func Info(infoMessage string, args ...interface{}) {
	stdoutLogger.SetPrefix("INFO: ")
	stdoutLogger.Output(2, fmt.Sprintf(infoMessage, args...))
}

// Warn log warning to stdout
func Warn(infoMessage string, args ...interface{}) {
	stdoutLogger.SetPrefix("WARN: ")
	stdoutLogger.Output(2, fmt.Sprintf(infoMessage, args...))
}

// Debug log debug to stdout
func Debug(infoMessage string, args ...interface{}) {
	if isDebug {
		stdoutLogger.SetPrefix("DEBUG: ")
		stdoutLogger.Output(2, fmt.Sprintf(infoMessage, args...))
	}
}

// EnableDebugMode Log debug to stdout
func EnableDebugMode() {
	stdoutLogger.SetPrefix("DEBUG: ")
	stdoutLogger.Output(2, "Debug mode is enabled")
	isDebug = true
}

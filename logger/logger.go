package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// Initialize the logger to use accross packages.
var (
	logged = NewLogger()
	Loger  = *logged
)

type Logger struct {
	useJSON bool
}

// NewLogger initializes the logger based on an environment variable or flag
func NewLogger() *Logger {
	useJSON := os.Getenv("LOG_FORMAT") == "json"
	if useJSON {
		return &Logger{useJSON: useJSON}
	} else {
		return &Logger{}
	}

}

// Info logs in emoji or JSON mode
func (l *Logger) Info(msg string, args ...interface{}) {
	if l.useJSON {
		logData := map[string]interface{}{
			"level":   "info",
			"message": fmt.Sprintf(msg, args...),
		}
		jsonData, _ := json.Marshal(logData)
		log.Println(string(jsonData))
	} else {
		log.Printf(msg, args...)
	}
}

// Fatal logs in emoji or JSON mode
func (l *Logger) Fatal(msg string, args ...interface{}) {
	if l.useJSON {
		logData := map[string]interface{}{
			"level":   "fatal",
			"message": fmt.Sprintf(msg, args...),
		}
		jsonData, _ := json.Marshal(logData)
		log.Println(string(jsonData))
	} else {
		log.Fatalf(msg, args...)
	}
}

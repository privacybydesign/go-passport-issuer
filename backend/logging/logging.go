package logging

import (
	"log"
	"os"
)

var (
	Info  *log.Logger
	Error *log.Logger
)

func init() {
	Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	Info = log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func InitFileLogger(fileName string) {
	logFile, err := os.Create(fileName)

	if err != nil {
		log.Fatalf("failed to open error log file: %v", err)
	}

	Error = log.New(logFile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	Info = log.New(logFile, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
}

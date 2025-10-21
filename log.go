package main

import (
	"futils"
	"os"
	"sockets"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var SylogMsgBan string
var SylogMsgDetect string
var LogsRotateDefaultSizeRotation int64
var LogFileName = "/var/log/articarest.log"

func initZerolog() bool {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	LogsRotateDefaultSizeRotation = sockets.GET_INFO_INT("LogsRotateDefaultSizeRotation")
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if *GoInDebug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
		log.Logger = log.Output(consoleWriter)
		return true
	}

	logFile, err := os.OpenFile(LogFileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open log file")
		return false
	}

	log.Logger = log.Output(logFile)

	return true
}
func LogRotate() {
	if LogsRotateDefaultSizeRotation == 0 {
		LogsRotateDefaultSizeRotation = 100
	}

	CurrentSize := futils.FileSizeMB(LogFileName)
	log.Debug().Msgf("%v Current: %vMB, MAX:%vMB", futils.GetCalleRuntime(), CurrentSize, LogsRotateDefaultSizeRotation)

	if CurrentSize > LogsRotateDefaultSizeRotation {
		futils.DeleteFile(LogFileName)
		initZerolog()
		log.Info().Msgf("%v Removed service log file...", futils.GetCalleRuntime())
	}

}
func FileSizeBytes(filePath string) int64 {

	if !futils.FileExists(filePath) {
		return 0
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		log.Err(err).Msg(filePath)
		return 0
	}

	// Calculate the size in MB
	return fileInfo.Size()

}

func FileSizeMB(filePath string) int64 {

	if !futils.FileExists(filePath) {
		return 0
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		log.Err(err).Msg(filePath)
		return 0
	}

	// Calculate the size in MB
	fileSizeInBytes := fileInfo.Size()
	return fileSizeInBytes / (1024 * 1024)
}

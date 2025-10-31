package main

import (
	"DashBoard"
	"LogForward"
	"Update"
	"logrotate"
	"suricata"
	"surirules"
)

func Each2Minutes() {
	Update.Run()
}

func Each5Minutes() {
	LogForward.ParseQueueFailed()
	surirules.CheckRulesCounter()
}
func Each15Minutes() {
	DashBoard.Build()
	logrotate.RotateEveJsonByPeriod()
}
func Each10Minutes() {

}
func Each12Hours() {
	suricata.EveJsonPurge()
}
func EachRotation() {
	logrotate.RotateEveJson()
}

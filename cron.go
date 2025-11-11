package main

import (
	"DashBoard"
	"DataShieldIPv4Blocklist"
	"LogForward"
	"Maintenance"
	"Update"
	"logrotate"
	"suricata"
	"surirules"
)

func Each2Minutes() {
	Update.Run()
}
func EachMinutes() {
	Maintenance.CheckSuricataSocket()
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
func Each30Minutes() {
	DataShieldIPv4Blocklist.Run(true)
}

func Each12Hours() {
	suricata.EveJsonPurge()
}
func EachRotation() {
	logrotate.RotateEveJson()
}

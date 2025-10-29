package main

import (
	"LogForward"
	"Update"
	"logrotate"
	"suricata"
	"suricata/SuricataDashboard"
	"suricata/suricataConfig"
)

func Each5Minutes() {
	LogForward.ParseQueueFailed()
}
func Each15Minutes() {
	suricataConfig.SuricataDashboard()
	logrotate.RotateEveJsonByPeriod()
}
func Each10Minutes() {
	Update.Run()
	SuricataDashboard.CountOfSuricata()

}
func Each12Hours() {
	suricata.EveJsonPurge()
}
func EachRotation() {
	logrotate.RotateEveJson()
}

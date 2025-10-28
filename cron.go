package main

import (
	"LogForward"
	"logrotate"
	"suricata"
	"suricata/SuricataDashboard"
	"suricata/SuricataUpdates"
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
	SuricataUpdates.Schedule()
	SuricataDashboard.CountOfSuricata()

}
func Each12Hours() {
	suricata.EveJsonPurge()
}
func EachRotation() {
	logrotate.RotateEveJson()
}

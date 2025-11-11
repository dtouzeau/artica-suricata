package Reconfigure

import (
	"PFRing"
	"SuriConf"
	"futils"
	"notifs"
	"suricata/SuricataTools"
	"sync"

	"github.com/rs/zerolog/log"
)

var rsst sync.Mutex

const DumpRulesPF = "dumprules.progress"
const DumpRulesLock = "/etc/suricata/dump.rules.lock"

func Run() {
	notifs.BuildProgress(30, "{reconfiguring}", "suricata.reconfigure.progress")
	md51 := futils.MD5File("/etc/suricata/suricata.yaml")
	notifs.BuildProgress(50, "{checking} PF_RING", "suricata.reconfigure.progress")
	PFRing.Check()
	//suricata.progress
	notifs.BuildProgress(52, "{building}", "suricata.reconfigure.progress")
	err := SuriConf.Build(true)
	if err != nil {
		notifs.BuildProgress(110, err.Error(), "suricata.reconfigure.progress")
		return
	}
	md52 := futils.MD5File("/etc/suricata/suricata.yaml")

	md511 := futils.MD5File("/etc/suricata/rules/Production.rules")

	md522 := futils.MD5File("/etc/suricata/rules/Production.rules")

	if md51 == md52 || md511 == md522 {
		notifs.BuildProgress(100, "{reconfiguring} {success}", "suricata.reconfigure.progress")
		return
	}
	notifs.BuildProgress(90, "{reconfiguring} {reloading}", "suricata.reconfigure.progress")
	SuricataTools.Reload()
	notifs.BuildProgress(100, "{restarting} {success}", "suricata.reconfigure.progress")
}
func Smooth() {
	md51 := futils.MD5File("/etc/suricata/suricata.yaml")
	err := SuriConf.Build(false)

	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	md52 := futils.MD5File("/etc/suricata/suricata.yaml")
	if md51 == md52 {
		return
	}
	SuricataTools.Reload()
}
func ReconfigureAndRestart() {
	rsst.Lock()
	defer rsst.Unlock()
	md51 := futils.MD5File("/etc/suricata/suricata.yaml")
	err := SuriConf.Build(false)

	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	md52 := futils.MD5File("/etc/suricata/suricata.yaml")
	if md51 == md52 {
		return
	}
	SuricataTools.RestartSimple()
}

func BuildRules() {

	if futils.FileExists(DumpRulesLock) {
		Mins := futils.FileTimeMin(DumpRulesLock)
		if Mins < 5 {
			notifs.BuildProgress(110, "a process alrady exists", DumpRulesPF)
			return
		}
	}
	futils.TouchFile(DumpRulesLock)
	defer futils.DeleteFile(DumpRulesLock)

	md511 := futils.MD5File("/etc/suricata/rules/Production.rules")
	err := SuriConf.DumpRules()
	if err != nil {
		notifs.BuildProgress(110, err.Error(), DumpRulesPF)
		return
	}
	md522 := futils.MD5File("/etc/suricata/rules/Production.rules")

	if md511 == md522 {
		notifs.BuildProgress(100, "{reconfiguring} {success}", DumpRulesPF)
		return
	}
	notifs.BuildProgress(99, "{reconfiguring} {reloading}", DumpRulesPF)
	SuricataTools.Reload()
	notifs.BuildProgress(100, "{restarting} {success}", DumpRulesPF)
}

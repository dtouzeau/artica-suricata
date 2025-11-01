package Reconfigure

import (
	"PFRing"
	"SuriConf"
	"futils"
	"notifs"
	"suricata/SuricataTools"
)

const DumpRulesPF = "dumprules.progress"
const ProgressF = "suricata.progress"
const DumpRulesLock = "/etc/suricata/dump.rules.lock"

func Run() {
	notifs.BuildProgress(30, "{reconfiguring}", ProgressF)
	md51 := futils.MD5File("/etc/suricata/suricata.yaml")
	notifs.BuildProgress(50, "{reconfiguring}", ProgressF)
	PFRing.Check()
	err := SuriConf.Build(true)
	if err != nil {
		notifs.BuildProgress(110, err.Error(), ProgressF)
		return
	}
	md52 := futils.MD5File("/etc/suricata/suricata.yaml")

	md511 := futils.MD5File("/etc/suricata/rules/Production.rules")

	md522 := futils.MD5File("/etc/suricata/rules/Production.rules")

	if md51 == md52 && md511 == md522 {
		notifs.BuildProgress(100, "{reconfiguring} {success}", ProgressF)
		return
	}
	notifs.BuildProgress(60, "{reconfiguring} {reloading}", ProgressF)
	SuricataTools.Reload()
	notifs.BuildProgress(100, "{restarting} {success}", ProgressF)
}
func BuildRules() {

	if futils.FileExists(DumpRulesLock) {
		notifs.BuildProgress(110, "a process alrady exists", DumpRulesPF)
		return
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

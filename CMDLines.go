package main

import (
	"LogForward"
	"PFRing"
	"Reconfigure"
	"SuriTables"
	"SuricataACLS"
	"Update"
	"Update/Otx"
	"encoding/json"
	"fmt"
	"os"
	"suricata"
	"suricata/SuricataTools"
	"surirules"
	"surisock"
)

func ParseCmdLines() {
	if *CMDAclsExplains {
		SuricataACLS.SetACLsExplain()
		os.Exit(0)
	}

	if *CMDPostgreSQL {
		SuriTables.Check()
		surirules.RulesToPostgres()
		os.Exit(0)
	}

	if *CMDParseRules {
		err := surirules.ImportSuricataRulesToSQLite()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	if *CMDOtx {
		Otx.Run()
		os.Exit(0)
	}
	if *CMDCleanQueue {
		LogForward.CleanQueueFailed()
		os.Exit(0)
	}
	if *CMDClassify {
		surirules.Classifications()
		os.Exit(0)
	}
	if *CMDRules {
		data := surisock.RuleStats()
		jsonBytes, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(jsonBytes))
		os.Exit(0)
	}
	if *cmdstopsuricata {
		suricata.Stop()
		os.Exit(0)
	}
	if *cmdstartsuricata {
		_ = suricata.Start()
		os.Exit(0)
	}
	if *CMDSuricataLUpdate {
		Update.Run()
		os.Exit(0)
	}
	if *CMDSuricataUpdates {
		err := Update.OpenInfoSecFoundation()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *cmdrestartsuricata {
		suricata.Restart()
		os.Exit(0)
	}
	if *cmdinstallsuricata {
		suricata.Install()
		os.Exit(0)
	}
	if *cmduninstallsuricata {
		suricata.Uninstall()
		os.Exit(0)
	}
	if *cmdreconfiguresuricata {
		Reconfigure.Run()
		os.Exit(0)
	}
	if *cmdPFRing {
		PFRing.Check()
		os.Exit(0)
	}

	if *cmdstatussuricata {
		fmt.Println("Version:", suricata.GetVersion())
		fmt.Println(suricata.Status(false))
		os.Exit(0)
	}
	if *cmdFixDuplicatesssuricata {
		//SuricataTools.FixDuplicateRules()
		os.Exit(0)
	}
	if len(*CMDSuricataSock) > 1 {
		err, sr := SuricataTools.UnixCommand(*CMDSuricataSock)
		if err != nil {
			fmt.Println("Error", err.Error())
			os.Exit(1)
		}
		fmt.Println(sr)
	}
}

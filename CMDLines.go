package main

import (
	"fmt"
	"os"
	"suricata"

	"suricata/SuricataTools"
	"suricata/SuricataUpdates"
)

func ParseCmdLines() {

	if *cmdstopsuricata {
		suricata.Stop()
		os.Exit(0)
	}
	if *cmdstartsuricata {
		_ = suricata.Start()
		os.Exit(0)
	}
	if *CMDSuricataUpdates {
		err := SuricataUpdates.OpenInfoSecFoundation()
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
		suricata.Reconfigure()
		os.Exit(0)
	}
	if *cmdPFRing {
		suricata.CheckPFRing()
		os.Exit(0)
	}

	if *cmdstatussuricata {
		fmt.Println("Version:", suricata.GetVersion())
		fmt.Println(suricata.Status(false))
		os.Exit(0)
	}
	if *cmdFixDuplicatesssuricata {
		SuricataTools.FixDuplicateRules()
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

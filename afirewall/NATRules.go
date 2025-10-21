package afirewall

import (
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"sockets"
)

func BuildFirewallByNATs(simulate bool) {
	// La table pnic_nat indique les NAT à realiser Dans iptables_main -> %NAT:$ID // ipRuleForInet Fonctionne
	FireHolEnable := sockets.GET_INFO_INT("FireHolEnable")

	if FireHolEnable == 0 {
		return
	}

	db, err := ConnectDB()
	if err != nil {
		log.Error().Msgf("%v Error connecting DB %v", futils.GetCalleRuntime(), err)
		return
	}
	defer db.Close()
	sNAT_TYPE := make(map[int]string)
	sNAT_TYPE[0] = "DNAT"
	sNAT_TYPE[1] = "SNAT"
	sNAT_TYPE[2] = "RNAT"
	sNAT_TYPE[3] = "XNAT"

	rows, err := db.Query(`SELECT ID,nic,NAT_TYPE FROM pnic_nat WHERE enabled=1`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		_ = db.Close()
		return
	}

	defer rows.Close()

	var GbCommands []string

	for rows.Next() {
		var ID, NAT_TYPE int
		var eth string
		err := rows.Scan(&ID, &eth, &NAT_TYPE)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return
		}
		InterfaceName := fmt.Sprintf("%v:%d", sNAT_TYPE[NAT_TYPE], ID)
		log.Debug().Msgf("%v: Found NAT %v", futils.GetCalleRuntime(), InterfaceName)
		GbCommands = ipRuleForInet(GbCommands, InterfaceName)
	}

	if simulate {
		for _, command := range GbCommands {
			fmt.Println(command)
		}
		return
	}
	for _, command := range GbCommands {
		err, out := futils.ExecuteShell(command)
		if err != nil {
			log.Error().Msgf("%v [%v] %v", futils.GetCalleRuntime(), command, out)
		}
	}
}

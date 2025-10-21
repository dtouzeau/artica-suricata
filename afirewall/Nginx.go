package afirewall

import (
	"afirewall/aFirewallTools"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"sockets"
)

func NginxFireWall() {
	aFirewallTools.CleanRulesByString([]string{"REVERSEPROXY", "fw-nginx", "NGNIX_FW_DROP_IN"})
	iptables := futils.FindProgram("iptables")
	EnableNginxFW := sockets.GET_INFO_INT("EnableNginxFW")
	var f []string

	f = append(f, "-t filter -N REVERSEPROXY")
	f = append(f, "-A REVERSEPROXY -j ACCEPT -m comment --comment \"RULE.REVERSEPROXY\"")

	if EnableNginxFW == 1 {
		comment := "-m comment --comment \"fw-nginx\""
		f = append(f, "-t filter -N NGNIX_FW_DROP_IN "+comment)
		f = append(f, fmt.Sprintf("-A NGNIX_FW_DROP_IN %v -j LOG --log-prefix fw-nginx-in: --log-level 6", comment))
		f = append(f, fmt.Sprintf("-A NGNIX_FW_DROP_IN %v -j REJECT --reject-with tcp-reset", comment))
	}
	for _, cmd := range f {
		cmd = fmt.Sprintf("%v %v", iptables, cmd)
		err, out := futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msgf("%v [%v] %v", futils.GetCalleRuntime(), cmd, out)
		}
	}
}

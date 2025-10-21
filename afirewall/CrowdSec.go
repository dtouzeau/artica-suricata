package afirewall

import (
	"afirewall/aFirewallTools"
	"fmt"
	"futils"
	"ipclass"
	"notifs"
	"sockets"
	"strings"

	"github.com/rs/zerolog/log"
)

func CrowdSecRules() {
	EnableCrowdsecFirewallBouncer := IsCrowdSecEnabled()
	aFirewallTools.CleanRulesByString([]string{"RULE.CROWDSEC", "in_crowdsec"})
	if EnableCrowdsecFirewallBouncer == 0 {
		return
	}

	ActiveDirectoryRestPort := sockets.GET_INFO_INT("ActiveDirectoryRestPort")
	if ActiveDirectoryRestPort == 0 {
		ActiveDirectoryRestPort = 9503
	}
	iptables := futils.FindProgram("iptables")
	content := aFirewallTools.IpTablesSave()

	log.Warn().Msgf("%v: Building IpTables rules for CrowdSec", futils.GetCalleRuntime())
	notifs.SquidAdminMysql(2, "Create local CrowdSec firewall rules", content, futils.GetCalleRuntime(), 572)

	var Conf []string

	Conf = append(Conf, fmt.Sprintf("%v -t filter -N in_crowdsec -m comment --comment \"RULE.CROWDSEC\"|| true", iptables))
	Conf = append(Conf, fmt.Sprintf("%v -t filter -I INPUT -m set --match-set crowdsec6-blacklists src -j in_crowdsec -m comment --comment \"RULE.CROWDSEC\"", iptables))
	Conf = append(Conf, fmt.Sprintf("%v -t filter -I INPUT -m set --match-set crowdsec-blacklists src -j in_crowdsec -m comment --comment \"RULE.CROWDSEC\"", iptables))
	Conf = append(Conf, fmt.Sprintf("%v -I in_crowdsec -j DROP -m comment --comment \"RULE.CROWDSEC\"", iptables))
	Conf = append(Conf, fmt.Sprintf("%v -I in_crowdsec -m limit --limit 1/sec -j LOG --log-prefix \"FIREHOL: CROWDSEC: \" -m comment --comment \"RULE.CROWDSEC\" --log-level 6", iptables))

	allIps := ipclass.SaveAllIPs()
	tbIps := strings.Split(allIps, ",")
	tbIps = append(tbIps, "127.0.0.1")
	tcpPort := fmt.Sprintf("-m multiport --dports %v,4503,80,443,3334,5516", ActiveDirectoryRestPort)
	udport := "-m multiport --dports 5516,53"

	for _, LocalIP := range tbIps {
		Conf = append(Conf, fmt.Sprintf("%v -I INPUT -i lo -s 127.0.0.1 -j ACCEPT -m comment --comment \"RULE.CROWDSEC\"", iptables))
		Conf = append(Conf, fmt.Sprintf("%v -I INPUT -s %v -p tcp %v -j ACCEPT -m comment --comment \"RULE.CROWDSEC\"", iptables, LocalIP, tcpPort))
		Conf = append(Conf, fmt.Sprintf("%v -I INPUT -s %v -p udp %v -j ACCEPT -m comment --comment \"RULE.CROWDSEC\"", iptables, LocalIP, udport))

	}

	for _, cmd := range Conf {

		log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
		err, out := futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msgf("%v Error while executing  %v", futils.GetCalleRuntime(), out)
		}
	}
	TrustedAddRules()

}

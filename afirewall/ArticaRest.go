package afirewall

import (
	"afirewall/aFirewallTools"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"ipclass"
	"sockets"
	"strings"
)

func articarestRules() {
	filename := "/home/artica/firewall/ipset.articarest.txt"
	ArticaRestAllIps := sockets.GET_INFO_STR("ArticaRestAllIps")
	ActiveDirectoryRestPort := sockets.GET_INFO_INT("ActiveDirectoryRestPort")
	if ActiveDirectoryRestPort == 0 {
		ActiveDirectoryRestPort = 9503
	}
	var Ips []string
	Ips = append(Ips, "127.0.0.1")
	Ips = append(Ips, "127.0.0.55")
	Ips = append(Ips, "127.0.0.118")
	if len(ArticaRestAllIps) > 2 {
		tb := strings.Split(ArticaRestAllIps, ",")
		for _, ipaddr := range tb {
			if ipclass.IsIPv6(ipaddr) {
				continue
			}

			if !ipclass.IsValidIpOrCDIR(ipaddr) {
				continue
			}
			Ips = append(Ips, ipaddr)
		}
	}
	ipsetBin := futils.FindProgram("ipset")
	aFirewallTools.CleanRulesByString([]string{"ARTICAREST.ALLOW"})
	MatchSet := "-m set --match-set internals src"

	var script []string
	if IpSetExists("internals") {
		log.Info().Msgf("%v ipset:internals exists, force remove it", futils.GetCalleRuntime())
		script = append(script, fmt.Sprintf("-exist -F internals"))
		script = append(script, fmt.Sprintf("-exist -X internals"))
	}
	script = append(script, fmt.Sprintf("create internals hash:net hashsize 16384 maxelem %d", len(Ips)*10))
	for _, sNet := range Ips {
		script = append(script, fmt.Sprintf("add internals %s", sNet))
	}
	err := futils.FilePutContents(filename, strings.Join(script, "\n"))
	if err != nil {
		log.Error().Msgf("%v Error creating internals %v: %v", futils.GetCalleRuntime(), filename, err)
	}
	log.Info().Msgf("%v importing internals from %v", futils.GetCalleRuntime(), filename)
	err, out := futils.ExecuteShell(fmt.Sprintf("%v restore -! < %s", ipsetBin, filename))
	if err != nil {
		log.Error().Msgf("%v failed to restore ipset: %v [%v]", futils.GetCalleRuntime(), err, out)
		return
	}

	tcpPort := fmt.Sprintf("-m multiport --dports %v,4503,80,443,3334,5516", ActiveDirectoryRestPort)
	udport := "-m multiport --dports 5516,53"
	iptables := futils.FindProgram("iptables")
	Obs := "-m comment --comment \"ARTICAREST.ALLOW\""
	cmd := fmt.Sprintf("%v -I INPUT -p tcp %v %v -j ACCEPT %v", iptables, MatchSet, tcpPort, Obs)
	err, out = futils.ExecuteShell(cmd)
	if err != nil {
		log.Error().Msgf("%v [%v] %v (%v)", futils.GetCalleRuntime(), cmd, err.Error(), out)
	}
	cmd = fmt.Sprintf("%v -I INPUT -p udp %v %v -j ACCEPT %v", iptables, MatchSet, udport, Obs)
	err, out = futils.ExecuteShell(cmd)
	if err != nil {
		log.Error().Msgf("%v [%v] %v (%v)", futils.GetCalleRuntime(), cmd, err.Error(), out)
	}

}

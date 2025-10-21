package afirewall

import (
	"IptablesTools"
	"MyNets"
	"afirewall/aFirewallTools"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"ipclass"
	"sockets"
	"strings"
)

func trustedRulesExists() bool {

	defer func() {
		IptablesTools.IPtablesLArr = []string{}
	}()

	if !IptablesTools.IsGroupN("trustednets") {
		log.Warn().Msgf("%v trustednets chain not exists", futils.GetCalleRuntime())
		return false
	}
	if !IpSetExists("PublicServers") {
		log.Warn().Msgf("%v PublicServers ipset not found", futils.GetCalleRuntime())
		return false
	}

	if !IptablesTools.IsCommentExists("TRUSTED.NETS") {
		log.Warn().Msgf("%v TRUSTED.NETS not found", futils.GetCalleRuntime())
		return false
	}
	if !IptablesTools.IsCommentExists("RULE.1000395") {
		log.Warn().Msgf("%v RULE.1000395 not found", futils.GetCalleRuntime())
		return false
	}
	if !IptablesTools.IsCommentExists("ARTICAREST.ALLOW") {
		log.Warn().Msgf("%v ARTICAREST.ALLOW not found", futils.GetCalleRuntime())
		return false
	}
	return true
}

func TrustedAddRules() {
	filename := "/home/artica/firewall/ipset.trustednet.txt"
	futils.CreateDir("/home/artica/firewall")
	iptables := futils.FindProgram("iptables")
	Masqs := make(map[string]string)
	Masqs["255.255.255.255"] = "32"
	Masqs["255.255.255.254"] = "31"
	Masqs["255.255.255.252"] = "30"
	Masqs["255.255.255.248"] = "29"
	Masqs["255.255.255.240"] = "28"
	Masqs["255.255.255.224"] = "27"
	Masqs["255.255.255.192"] = "26"
	Masqs["255.255.255.128"] = "25"
	Masqs["255.255.255.0"] = "24"
	Masqs["255.255.254.0"] = "23"
	Masqs["255.255.252.0"] = "22"
	Masqs["255.255.248.0"] = "21"
	Masqs["255.255.240.0"] = "20"
	Masqs["255.255.224.0"] = "19"
	Masqs["255.255.192.0"] = "18"
	Masqs["255.255.128.0"] = "17"
	Masqs["255.255.0.0"] = "16"
	Masqs["255.254.0.0"] = "15"
	Masqs["255.252.0.0)"] = "14"
	Masqs["255.248.0.0"] = "13"
	Masqs["255.240.0.0"] = "12"
	Masqs["255.224.0.0"] = "11"
	Masqs["255.192.0.0"] = "10"
	Masqs["255.128.0.0"] = "9"
	Masqs["255.0.0.0"] = "8"
	Masqs["254.0.0.0"] = "7"
	Masqs["252.0.0.0)"] = "6"
	Masqs["248.0.0.0"] = "5"
	Masqs["240.0.0.0"] = "4"
	Masqs["224.0.0.0"] = "3"
	Masqs["192.0.0.0"] = "2"
	Masqs["128.0.0.0"] = "1"

	Nets := MyNets.TrustedNets()
	ipsetBin := futils.FindProgram("ipset")
	var script []string
	var subs []string

	for sNet, _ := range Nets {
		if sNet == "0.0.0.0/0" {
			continue
		}
		if ipclass.IsIPv6(sNet) {
			continue
		}

		for masq, bit := range Masqs {
			sNet = strings.ReplaceAll(sNet, fmt.Sprintf("/%v", masq), "/"+bit)
		}
		subs = append(subs, fmt.Sprintf("add trustednet %s", sNet))
	}
	if IpSetExists("trustednet") {
		log.Info().Msgf("%v ipset:trustednet exists, force remove it", futils.GetCalleRuntime())
		script = append(script, fmt.Sprintf("-exist -F trustednet"))
	} else {
		script = append(script, fmt.Sprintf("create trustednet hash:net maxelem %d", 1000000))
	}
	script = append(script, strings.Join(subs, "\n"))
	err := futils.FilePutContents(filename, strings.Join(script, "\n"))
	if err != nil {
		log.Error().Msgf("%v Error on trustednet %v: %v", futils.GetCalleRuntime(), filename, err)
	}
	log.Info().Msgf("%v importing trustednet from %v", futils.GetCalleRuntime(), filename)
	err, out := futils.ExecuteShell(fmt.Sprintf("%v restore -! < %s", ipsetBin, filename))
	if err != nil {
		log.Error().Msgf("%v failed to restore ipset: %v [%v]", futils.GetCalleRuntime(), err, out)
		return
	}
	if trustedRulesExists() {
		log.Info().Msgf("%v success updated trustednet ipset from %v", futils.GetCalleRuntime(), filename)
		return
	}

	aFirewallTools.CleanRulesByString([]string{"TRUSTED.NETS", "match-set trustednet", "CLIDNS_ALLOW", "RULE.1000395", "CLIWEB_ALLOW"})
	var Conf []string
	if !IsGroupN("trustednets") {
		Conf = append(Conf, fmt.Sprintf("%v -t filter -N trustednets -m comment --comment \"TRUSTED.NETS\"", iptables))
	}
	if !IpSetExists("PublicServers") {
		log.Info().Msgf("%v ipset:PublicServers doesn't exists, create it it", futils.GetCalleRuntime())
		err := PublicServers()
		if err != nil {
			log.Error().Msgf("%v Error creating PublicServers: %v", futils.GetCalleRuntime(), err)
		}
	}

	Conf = append(Conf, fmt.Sprintf("%v -I INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment \"TRUSTED.NETS\"", iptables))
	Conf = append(Conf, fmt.Sprintf("%v -I INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment \"TRUSTED.NETS\"", iptables))
	Conf = append(Conf, fmt.Sprintf("%v -I trustednets -j ACCEPT -m comment --comment \"TRUSTED.NETS\"", iptables))
	FireHoleLogAllEvents := sockets.GET_INFO_INT("FireHoleLogAllEvents")
	if FireHoleLogAllEvents == 1 {
		Conf = append(Conf, fmt.Sprintf("%v -I trustednets -m limit --limit 1/sec -j LOG --log-prefix \"FIREHOL: TRUSTEDNETS: \" -m comment --comment \"TRUSTED.NETS\" --log-level 6", iptables))
	}
	Conf = append(Conf, fmt.Sprintf("%v -I INPUT -m set --match-set trustednet src -m comment --comment \"TRUSTED.NETS\" -j trustednets", iptables))
	Conf = append(Conf, fmt.Sprintf("%v -I INPUT -m set --match-set PublicServers src,src -m state --state ESTABLISHED -m comment --comment \"RULE.1000395\" -j ACCEPT", iptables))
	Conf = append(Conf, fmt.Sprintf("%v -I OUTPUT -m set --match-set PublicServers dst,dst -m state --state NEW,ESTABLISHED -m comment --comment \"RULE.1000395\" -j ACCEPT", iptables))

	if FireHoleLogAllEvents == 1 {
		Conf = append(Conf, fmt.Sprintf("%v -I OUTPUT -m set --match-set PublicServers dst,dst -m state --state NEW,ESTABLISHED -m comment --comment \"RULE.1000395\" -m limit --limit 1/sec -j LOG --log-prefix \"FIREHOL: CLIWEB_ALLOW: \" --log-level 6", iptables))
		Conf = append(Conf, fmt.Sprintf("%v -I INPUT -m set --match-set PublicServers src,src -m state --state ESTABLISHED -m comment --comment \"RULE.1000395\" -m limit --limit 1/sec -j LOG --log-prefix \"FIREHOL: CLIWEB_ALLOW: \" --log-level 6", iptables))
	}

	for _, line := range Conf {
		log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), line)
		err, out := futils.ExecuteShell(line)
		if err != nil {
			log.Error().Msgf("%v [%v] %v (%v)", futils.GetCalleRuntime(), line, err.Error(), out)
		}
	}
	articarestRules()
}

func OutDNS() {

}

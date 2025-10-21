package ProxyFirewall

import (
	"afirewall/aFirewallTools"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"ipclass"
	"notifs"
	"regexp"
	"sockets"
	"strings"
)

var reExPorts = regexp.MustCompile(`^(.+?):([0-9]+)`)
var ReProxyPorts = regexp.MustCompile(`^http_port.*?:([0-9]+).*?name=MyPortName`)

func deleteSquidRules() {

	Current, _ := aFirewallTools.GetCurrentIPTablesRules()
	CurrentRules := strings.Split(Current, "\n")
	Update := false
	var NewRule []string
	for _, rule := range CurrentRules {
		if strings.Contains(rule, "PROXYRULES") || strings.Contains(rule, "out_proxy") || strings.Contains(rule, "in_proxy") {
			Update = true
			continue
		}
		NewRule = append(NewRule, rule)

	}
	if !Update {
		return
	}
	iptablesRestore := futils.FindProgram("iptables-restore")
	TMPFILE := futils.TempFileName()
	_ = futils.FilePutContents(TMPFILE, strings.Join(NewRule, "\n"))
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v < %v", iptablesRestore, TMPFILE))
	futils.DeleteFile(TMPFILE)
}

func SquidRules() []string {
	deleteSquidRules()
	jLogIn := fmt.Sprintf("-m limit --limit 1/sec -j LOG --log-prefix \"FIREHOL: PROXYRULES_IN: \" --log-level 6")
	jLogOut := fmt.Sprintf("-m limit --limit 1/sec -j LOG --log-prefix \"FIREHOL: PROXYRULES_OUT: \" --log-level 6")
	SQUIDEnableFirewall := sockets.GET_INFO_INT("SQUIDEnableFirewall")
	if SQUIDEnableFirewall == 0 {
		return []string{}
	}
	SQUIDEnable := sockets.GET_INFO_INT("SQUIDEnable")
	if SQUIDEnable == 0 {
		return []string{}
	}
	iptables := futils.FindProgram("iptables")
	var GbCommands []string
	commentIN := fmt.Sprintf("-m comment --comment \"PROXYRULES_IN\"")
	commentOut := fmt.Sprintf("-m comment --comment \"PROXYRULES_OUT\"")
	commentLOG := fmt.Sprintf("-m comment --comment \"PROXYRULES_LOG\"")
	TFilter := "-t filter"
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -N in_proxy %v", iptables, TFilter, commentIN))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -N out_proxy %v", iptables, TFilter, commentOut))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A OUTPUT -p udp -m owner --uid-owner proxy %v -j out_proxy", iptables, TFilter, commentOut))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A OUTPUT -p tcp -m owner --uid-owner proxy %v -j out_proxy", iptables, TFilter, commentOut))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A out_proxy -p tcp -s 127.0.0.1 -d 127.0.0.1 %v -j ACCEPT", iptables, TFilter, commentOut))

	Ipaddresses := ipclass.AllLocalIPs()
	for _, IPStr := range Ipaddresses {
		if strings.HasSuffix(IPStr, "127.0.0") {
			continue
		}
		if ipclass.IsIPv6(IPStr) {
			continue
		}
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A in_proxy -s %v -d %v %v -j ACCEPT", iptables, TFilter, IPStr, IPStr, commentIN))
	}

	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A out_proxy -d 127.0.0.0/8 %v -j ACCEPT", iptables, TFilter, commentOut))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A in_proxy -s 127.0.0.1 -d 127.0.0.1 %v -j ACCEPT", iptables, TFilter, commentIN))
	sPorts := futils.RegexGroup1File(ReProxyPorts, "/etc/squid3/listen_ports.conf", true)
	dports := strings.Join(sPorts, ",")
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A INPUT -p tcp -m multiport --dports %v %v -j in_proxy", iptables, TFilter, dports, commentIN))

	SquidFirewallOutUDP := futils.Base64Decode(sockets.GET_INFO_STR("SquidFirewallOutUDP"))
	SquidFirewallOutTCP := futils.Base64Decode(sockets.GET_INFO_STR("SquidFirewallOutTCP"))
	SquidFirewallInTCP := futils.Base64Decode(sockets.GET_INFO_STR("SquidFirewallInTCP"))
	OutUDP := strings.Split(SquidFirewallOutUDP, "\n")
	OutTCP := strings.Split(SquidFirewallOutTCP, "\n")
	InTCP := strings.Split(SquidFirewallInTCP, "\n")

	var OutUDPArray []string
	var OutTCPArray []string

	// Regular expression to match "hostname:port" format

	// Process OutUDP
	for _, line := range OutUDP {
		line = strings.TrimSpace(line)
		if !reExPorts.MatchString(line) {
			continue
		}
		OutUDPArray = append(OutUDPArray, line)
	}
	if len(OutUDPArray) == 0 {
		OutUDPArray = append(OutUDPArray, "*:53")
	}

	// Process OutTCP
	for _, line := range OutTCP {
		line = strings.TrimSpace(line)
		if !reExPorts.MatchString(line) {
			continue
		}
		OutTCPArray = append(OutTCPArray, line)
	}
	if len(OutTCPArray) == 0 {
		OutTCPArray = append(OutTCPArray, "*:80", "*:443")
	}

	for _, line := range OutUDPArray {
		ip, port := futils.RegexGroup2(reExPorts, line)
		if len(ip) == 0 {
			continue
		}
		IntPort := futils.StrToInt(port)
		if IntPort == 0 {
			continue
		}

		if ip == "*" {
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A out_proxy -p udp --dport %d %v -j ACCEPT", iptables, TFilter, IntPort, commentOut))
			continue
		}
		if !ipclass.IsValidIpOrCDIR(ip) {
			continue
		}
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A out_proxy -p udp --dport %d -d %v %v -j ACCEPT", iptables, TFilter, IntPort, ip, commentOut))
	}
	for _, line := range OutTCP {
		ip, port := futils.RegexGroup2(reExPorts, line)
		if len(ip) == 0 {
			continue
		}
		IntPort := futils.StrToInt(port)
		if IntPort == 0 {
			continue
		}

		if ip == "*" {
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A out_proxy -p tcp --dport %d %v -j ACCEPT", iptables, TFilter, IntPort, commentOut))
			continue
		}
		if !ipclass.IsValidIpOrCDIR(ip) {
			continue
		}
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A out_proxy -p tcp --dport %d -d %v %v -j ACCEPT", iptables, TFilter, IntPort, ip, commentOut))
	}

	for _, line := range InTCP {
		line = strings.TrimSpace(line)
		if !ipclass.IsValidIpOrCDIR(line) {
			continue
		}
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A in_proxy -s %v %v -j ACCEPT", iptables, TFilter, line, commentIN))
	}

	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A in_proxy %v %v", iptables, TFilter, commentLOG, jLogIn))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A in_proxy %v -j DROP", iptables, TFilter, commentIN))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A out_proxy %v %v", iptables, TFilter, commentLOG, jLogOut))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A out_proxy -p tcp %v -j REJECT --reject-with tcp-reset", iptables, TFilter, commentOut))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A out_proxy -p udp %v -j REJECT --reject-with icmp-port-unreachable", iptables, TFilter, commentOut))

	for _, line := range GbCommands {
		err, out := futils.ExecuteShell(line)
		if err != nil {
			notifs.SquidAdminMysql(0, "Error create Proxy Firewall rules", out, futils.GetCalleRuntime(), 152)
			log.Error().Msgf("%v [%v]", futils.GetCalleRuntime(), line)
			log.Error().Msgf("%v Error create Proxy Firewall rules, %s", futils.GetCalleRuntime(), out)
		}

	}

	return GbCommands
}

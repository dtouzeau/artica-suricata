package afirewall

import (
	"InterfacesDB"
	"SqliteConns"
	"afirewall/Rules"
	"afirewall/acls"
	"database/sql"
	"fmt"
	"futils"
	"ipclass"
	"regexp"
	"sockets"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

var RegexNATInterface = regexp.MustCompile(`([A-Z])NAT:([0-9]+)`)

func BuildFirewallByInterfaces(Simulate bool) {

	FireHolEnable := sockets.GET_INFO_INT("FireHolEnable")
	var Cleaning []string
	Interfaces := ipclass.LocalInterfaces()
	Cleaning = append(Cleaning, "in_ALL")
	Cleaning = append(Cleaning, "out_ALL")
	Cleaning = append(Cleaning, "IFACE_ALL")

	for _, iface := range Interfaces {
		if iface == "lo" {
			continue
		}
		ifaceStamp := iface

		Cleaning = append(Cleaning, "in_"+ifaceStamp)
		Cleaning = append(Cleaning, "out_"+ifaceStamp)
		Cleaning = append(Cleaning, "IFACE_"+ifaceStamp)
		Cleaning = append(Cleaning, fmt.Sprintf("pr_%v_nsn3", ifaceStamp))
		Cleaning = append(Cleaning, fmt.Sprintf("pr_%v_ifl4", ifaceStamp))
		Cleaning = append(Cleaning, fmt.Sprintf("pr_%v_sfl5", ifaceStamp))
		Cleaning = append(Cleaning, fmt.Sprintf("pr_%v_mxs6", ifaceStamp))
		Cleaning = append(Cleaning, fmt.Sprintf("pr_%v_mnl7", ifaceStamp))
		Cleaning = append(Cleaning, fmt.Sprintf("pr_%v_mbd8", ifaceStamp))
		Cleaning = append(Cleaning, fmt.Sprintf("FINAL.%v", ifaceStamp))

	}
	//CleanRulesByString(Cleaning)
	if FireHolEnable == 0 {
		return
	}
	iptables := futils.FindProgram("iptables")
	TfilterA := fmt.Sprintf("%v -t filter -A", iptables)
	ArticaHttpsPort := sockets.GET_INFO_INT("ArticaHttpsPort")
	FireHoleLogAllEvents := sockets.GET_INFO_INT("FireHoleLogAllEvents")
	EnableDHCPServer := sockets.GET_INFO_INT("EnableDHCPServer")
	if ArticaHttpsPort == 0 {
		ArticaHttpsPort = 9000
	}
	mcontrack := "-m conntrack --ctstate"
	var GbCommands []string

	GbCommands = interfaceDefaultGroups(GbCommands)

	log.Info().Msgf("%v Checking %d Interfaces", futils.GetCalleRuntime(), len(Interfaces))
	xtIpv4optionsInstalled := sockets.GET_INFO_INT("xtIpv4optionsInstalled")
	InterfacesList := make(map[string]string)

	for _, iface := range Interfaces {
		if iface == "lo" {
			continue
		}
		log.Info().Msgf("%v Checking %v Interface", futils.GetCalleRuntime(), iface)
		comment := fmt.Sprintf("-m comment --comment \"IFACE_%v\"", iface)
		GroupIn := fmt.Sprintf("in_%v", iface)
		GroupOut := fmt.Sprintf("out_%v", iface)
		Conf := InterfacesDB.LoadInterface(iface)
		if xtIpv4optionsInstalled == 0 {
			Conf.XtIpv4options = 0
		}
		DHCP := false
		if Conf.Enabled == 0 {
			log.Info().Msgf("%v Interface %v is not enabled", futils.GetCalleRuntime(), iface)
			continue
		}
		if Conf.FireWallMasquerade == 1 {
			GbCommands = append(GbCommands, fmt.Sprintf("%v -t nat -A POSTROUTING -o %v %v -m conntrack --ctstate NEW -j MASQUERADE", iptables, iface, comment))
		}
		if Conf.IsFW == 0 {
			log.Info().Msgf("%v Interface %v is not enabled in the Firewall", futils.GetCalleRuntime(), iface)
			continue
		}
		if EnableDHCPServer == 1 {
			if isDHCPD(iface) {
				DHCP = true
			}
		}
		if Conf.Udhcpd == 1 {
			DHCP = true
		}
		InterfacesList[iface] = iface
		GbCommands = append(GbCommands, fmt.Sprintf("%v -t filter -N %v %v", iptables, GroupIn, comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v -t filter -N %v %v", iptables, GroupOut, comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v INPUT -i %v -j %v %v", TfilterA, iface, GroupIn, comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v OUTPUT -o %v -j %v %v", TfilterA, iface, GroupOut, comment))

		if Conf.FirewallPing == "accept" {
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p icmp -m conntrack --ctstate RELATED -j ACCEPT %v", TfilterA, GroupIn, comment))
		}
		if Conf.FirewallPing == "deny" {
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p icmp -m conntrack --ctstate RELATED -j SMART_REJECT %v", TfilterA, GroupOut, comment))
		}

		iptlog := ruleLogs("SCANNER")
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --tcp-flags ALL NONE -m limit --limit 3/min --limit-burst 5 %v %v", TfilterA, GroupIn, iptlog, comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --tcp-flags ALL FIN,PSH,URG -m limit --limit 3/min --limit-burst 5 %v %v", TfilterA, GroupIn, iptlog, comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --tcp-flags ALL FIN -m limit --limit 3/min --limit-burst 5 %v %v", TfilterA, GroupIn, iptlog, comment))
		if Conf.XtIpv4options == 1 {
			iptlog := ruleLogs("IPV4OPTS")
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -m ipv4options --flags lsrr,ssrr,timestamp,record-route --any %v %v", TfilterA, GroupIn, iptlog, comment))
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -m ipv4options --flags lsrr,ssrr,timestamp,record-route --any -j DROP %v", TfilterA, GroupIn, comment))
		}

		if Conf.FirewallPing == "trusted" {
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p icmp %v -m conntrack --ctstate RELATED -j ACCEPT %v", TfilterA, GroupIn, groupSrcip("trustednet", "src"), comment))
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p icmp -m conntrack --ctstate RELATED -j SMART_REJECT %v", TfilterA, GroupIn, comment))
		}

		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT %v", TfilterA, GroupOut, comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -m conntrack --ctstate ESTABLISHED -j ACCEPT %v", TfilterA, GroupIn, comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p icmp -m conntrack --ctstate RELATED -j ACCEPT %v", TfilterA, GroupOut, comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp -m conntrack --ctstate RELATED --tcp-flags ALL ACK,RST -j ACCEPT %v", TfilterA, GroupOut, comment))

		if Conf.FirewallArtica == 1 {
			if FireHoleLogAllEvents == 1 {
				GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --dport %d %v NEW,ESTABLISHED %v %v", TfilterA, GroupIn, ArticaHttpsPort, mcontrack, ruleLogs("ACCEPT_-992"), comment))
			}
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --dport %d %v NEW,ESTABLISHED -j ACCEPT %v", TfilterA, GroupIn, ArticaHttpsPort, mcontrack, comment))
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --sport %d %v ESTABLISHED -j ACCEPT %v", TfilterA, GroupOut, ArticaHttpsPort, mcontrack, comment))
		}

		if Conf.DenyDHCP == 1 {
			if FireHoleLogAllEvents == 1 {
				GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp %v --sport 67 --dst 255.255.255.255 %v", TfilterA, GroupIn, ruleLogs("DENY_DHCP"), comment))
				GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp %v --dport 67:68 %v", TfilterA, GroupIn, ruleLogs("DENY_DHCP"), comment))
			}

			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp --sport 67 --dst 255.255.255.255 -j DROP %v", TfilterA, GroupIn, comment))
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp --dport 67:68 -j DROP %v", TfilterA, GroupIn, comment))
		}

		if DHCP {
			if Conf.DenyDHCP == 0 {
				if FireHoleLogAllEvents == 1 {
					GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp %v --dport 67:68 -m conntrack --ctstate NEW,ESTABLISHED %v %v", TfilterA, GroupIn, groupSrcip("trustednet", "dst"), ruleLogs("ACCEPT_-993"), comment))
				}
				GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp %v --dport 67:68 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT %v", TfilterA, GroupIn, groupSrcip("trustednet", "dst"), comment))
			}
		}

		InterfaceSysCTLDefault(iface)
		if Conf.FirewallBehavior == 2 {
			interfacesSyCTLBehv2(iface)
			GbCommands = WanProtectionIface(GbCommands, iface)
			GbCommands = byInterfaceNginx(GbCommands, iface)
		}
		if Conf.FirewallBehavior == 1 {
			if FireHoleLogAllEvents == 1 {
				GbCommands = append(GbCommands, fmt.Sprintf("%v %v %v -m conntrack --ctstate NEW,ESTABLISHED %v %v", TfilterA, GroupIn, groupSrcip("trustednet", "src"), ruleLogs("POLICY_ACCEPT"), comment))
			}
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v %v -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT %v", TfilterA, GroupIn, groupSrcip("trustednet", "src"), comment))
		}

		GbCommands = ipRuleForInet(GbCommands, iface)

		if Conf.FireWallPolicy == "reject" {
			if FireHoleLogAllEvents == 1 {
				GbCommands = append(GbCommands, fmt.Sprintf("%v %v %v %v", TfilterA, GroupIn, ruleLogs("POLICY_REJECT"), comment))
			}
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -j SMART_REJECT %v", TfilterA, GroupIn, comment))
		}

		if Conf.FireWallPolicy == "accept" {
			if FireHoleLogAllEvents == 1 {
				GbCommands = append(GbCommands, fmt.Sprintf("%v %v %v %v", TfilterA, GroupIn, ruleLogs("POLICY_ACCEPT"), comment))
			}
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -j ACCEPT %v", TfilterA, GroupIn, comment))
		}
	}

	log.Info().Msgf("%v Building rules for no interfaces", futils.GetCalleRuntime())

	GbCommands = interfaceDefault(GbCommands, InterfacesList)

	if Simulate {
		for _, command := range GbCommands {
			command := strings.ReplaceAll(command, "-A -A", "-A")
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
func interfaceDefaultGroups(GbCommands []string) []string {
	comment := fmt.Sprintf("-m comment --comment \"IFACE_ALL\"")
	GroupIn := fmt.Sprintf("in_%v", "ALL")
	GroupOut := fmt.Sprintf("out_%v", "ALL")
	iptables := futils.FindProgram("iptables")
	GbCommands = append(GbCommands, fmt.Sprintf("%v -t filter -N %v %v", iptables, GroupIn, comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v -t filter -N %v %v", iptables, GroupOut, comment))
	return GbCommands
}

func interfaceDefault(GbCommands []string, alreadyInterfaces map[string]string) []string {
	GbCommands = ipRuleForInet(GbCommands, "")
	comment := fmt.Sprintf("-m comment --comment \"IFACE_ALL\"")
	GroupIn := fmt.Sprintf("in_%v", "ALL")
	GroupOut := fmt.Sprintf("out_%v", "ALL")
	iptables := futils.FindProgram("iptables")
	TfilterA := fmt.Sprintf("%v -t filter -A", iptables)
	ArticaHttpsPort := sockets.GET_INFO_INT("ArticaHttpsPort")
	FireHoleLogAllEvents := sockets.GET_INFO_INT("FireHoleLogAllEvents")
	mcontrack := "-m conntrack --ctstate"

	if ArticaHttpsPort == 0 {
		ArticaHttpsPort = 9000
	}
	FireWallDefault := futils.UnserializeMap1(futils.Base64Decode(sockets.GET_INFO_STR("FireWallDefaultInterfacesParams")))
	if futils.StrToInt(FireWallDefault["isFW"]) == 0 {
		FireWallDefault["firewall_policy"] = "accept"
		FireWallDefault["firewall_behavior"] = "0"
		FireWallDefault["firewall_artica"] = "1"
		FireWallDefault["AntiDDOS"] = "0"
		FireWallDefault["denydhcp"] = "0"
		FireWallDefault["firewall_ping"] = "accept"
		FireWallDefault["xtIpv4optionsEnabled"] = "0"
	}
	FireWallPolicy := FireWallDefault["firewall_policy"]
	FirewallArtica := futils.StrToInt(FireWallDefault["firewall_artica"])
	FirewallBehavior := futils.StrToInt(FireWallDefault["firewall_behavior"])
	DenyDHCP := futils.StrToInt(FireWallDefault["denydhcp"])
	ipv4options := futils.StrToInt(FireWallDefault["xtIpv4optionsEnabled"])

	ifacesNotInMap := make(map[string]bool)
	ifacesNotOutMap := make(map[string]bool)

	for ziface, _ := range alreadyInterfaces {
		ifacesNotInMap[fmt.Sprintf("! -i %v", ziface)] = true
		ifacesNotOutMap[fmt.Sprintf("! -o %v", ziface)] = true
	}

	if ipv4options == 1 {
		xtIpv4optionsInstalled := sockets.GET_INFO_INT("xtIpv4optionsInstalled")
		if xtIpv4optionsInstalled == 0 {
			ipv4options = 0
		}

	}
	if ipv4options == 1 {
		err := futils.RunModeProbe("xt_ipv4options")
		if err != nil {
			err := futils.RunDepmod()
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			}
			err = futils.RunModeProbe("xt_ipv4options")
			if err != nil {
				log.Error().Msgf("%v xt_ipv4options [%v]", futils.GetCalleRuntime(), err)
			}
		}
	}

	for zCommandIface, _ := range ifacesNotInMap {
		GbCommands = append(GbCommands, fmt.Sprintf("%v INPUT %v -j %v %v", TfilterA, zCommandIface, GroupIn, comment))

	}
	for zCommandIface2, _ := range ifacesNotOutMap {
		GbCommands = append(GbCommands, fmt.Sprintf("%v OUTPUT %v -j %v %v", TfilterA, zCommandIface2, GroupOut, comment))
	}

	if FireWallDefault["firewall_ping"] == "accept" {
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p icmp -m conntrack --ctstate RELATED -j ACCEPT %v", TfilterA, GroupIn, comment))
	}
	if FireWallDefault["firewall_ping"] == "deny" {
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p icmp -m conntrack --ctstate RELATED -j SMART_REJECT %v", TfilterA, GroupOut, comment))
	}
	if ipv4options == 1 {
		iptlog := ruleLogs("IPV4OPTS")
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -m ipv4options --flags lsrr,ssrr,timestamp,record-route --any %v %v", TfilterA, GroupIn, iptlog, comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -m ipv4options --flags lsrr,ssrr,timestamp,record-route --any -j DROP %v", TfilterA, GroupIn, comment))
	}
	iptlog := ruleLogs("SCANNER")
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --tcp-flags ALL NONE -m limit --limit 3/min --limit-burst 5 %v %v", TfilterA, GroupIn, iptlog, comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --tcp-flags ALL FIN,PSH,URG -m limit --limit 3/min --limit-burst 5 %v %v", TfilterA, GroupIn, iptlog, comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --tcp-flags ALL FIN -m limit --limit 3/min --limit-burst 5 %v %v", TfilterA, GroupIn, iptlog, comment))

	if FireWallDefault["firewall_ping"] == "trusted" {
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p icmp %v -m conntrack --ctstate RELATED -j ACCEPT %v", TfilterA, GroupIn, groupSrcip("trustednet", "src"), comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p icmp -m conntrack --ctstate RELATED -j SMART_REJECT %v", TfilterA, GroupIn, comment))
	}
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT %v", TfilterA, GroupOut, comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -m conntrack --ctstate ESTABLISHED -j ACCEPT %v", TfilterA, GroupIn, comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p icmp -m conntrack --ctstate RELATED -j ACCEPT %v", TfilterA, GroupOut, comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp -m conntrack --ctstate RELATED --tcp-flags ALL ACK,RST -j ACCEPT %v", TfilterA, GroupOut, comment))

	if FirewallArtica == 1 {
		if FireHoleLogAllEvents == 1 {
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --dport %d %v NEW,ESTABLISHED %v %v", TfilterA, GroupIn, ArticaHttpsPort, mcontrack, ruleLogs("ACCEPT_-992"), comment))
		}
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --dport %d %v NEW,ESTABLISHED -j ACCEPT %v", TfilterA, GroupIn, ArticaHttpsPort, mcontrack, comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --sport %d %v ESTABLISHED -j ACCEPT %v", TfilterA, GroupOut, ArticaHttpsPort, mcontrack, comment))
	}

	if DenyDHCP == 1 {
		if FireHoleLogAllEvents == 1 {
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp %v --sport 67 --dst 255.255.255.255 %v", TfilterA, GroupIn, ruleLogs("DENY_DHCP"), comment))
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp %v --dport 67:68 %v", TfilterA, GroupIn, ruleLogs("DENY_DHCP"), comment))
		}
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp --sport 67 --dst 255.255.255.255 -j DROP %v", TfilterA, GroupIn, comment))
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp --dport 67:68 -j DROP %v", TfilterA, GroupIn, comment))
	}

	if DenyDHCP == 0 {
		if FireHoleLogAllEvents == 1 {
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp %v --dport 67:68 -m conntrack --ctstate NEW,ESTABLISHED %v %v", TfilterA, GroupIn, groupSrcip("trustednet", "dst"), ruleLogs("ACCEPT_-993"), comment))
		}
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p udp %v --dport 67:68 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT %v", TfilterA, GroupIn, groupSrcip("trustednet", "dst"), comment))
	}

	if FirewallBehavior == 2 {
		iface := ""
		GbCommands = WanProtectionIface(GbCommands, iface)
	}

	if FirewallBehavior == 1 {
		if FireHoleLogAllEvents == 1 {
			GbCommands = append(GbCommands, fmt.Sprintf("%v A %v %v -m conntrack --ctstate NEW,ESTABLISHED %v %v", TfilterA, GroupIn, groupSrcip("trustednet", "src"), ruleLogs("POLICY_ACCEPT"), comment))
		}
		GbCommands = append(GbCommands, fmt.Sprintf("%v A %v %v -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT %v", TfilterA, GroupIn, groupSrcip("trustednet", "src"), comment))
	}

	GbCommands = ipRuleForInet(GbCommands, "")

	if FireWallPolicy == "reject" {
		if FireHoleLogAllEvents == 1 {
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v %v %v", TfilterA, GroupIn, ruleLogs("POLICY_REJECT"), comment))
		}
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -j SMART_REJECT %v", TfilterA, GroupIn, comment))
	}

	if FireWallPolicy == "accept" {
		if FireHoleLogAllEvents == 1 {
			GbCommands = append(GbCommands, fmt.Sprintf("%v %v %v %v", TfilterA, GroupIn, ruleLogs("POLICY_ACCEPT"), comment))
		}
		GbCommands = append(GbCommands, fmt.Sprintf("%v %v -j ACCEPT %v", TfilterA, GroupIn, comment))
	}
	return GbCommands
}
func WanProtectionIface(GbCommands []string, iface string) []string {

	iiface := fmt.Sprintf("-i %v", iface)
	iptables := futils.FindProgram("iptables")
	Object := fmt.Sprintf("WAN_%v", iface)
	PortScanningName := fmt.Sprintf("PORT_SCANNING_%v", iface)
	comment := fmt.Sprintf("-m comment --comment \"IFACE_%v\"", iface)
	TfilterA := fmt.Sprintf("%v -t filter -A", iptables)
	if len(iface) == 0 {
		comment = "-m comment --comment \"IFACE_ALL\""
		Object = "WAN_ALL"
		PortScanningName = "PORT_SCANNING_ALL"
		iiface = ""
	}

	GbCommands = append(GbCommands, fmt.Sprintf("%v -t filter -N %v %v", iptables, PortScanningName, comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v -t filter -N %v %v", iptables, Object, comment))

	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 %v -j RETURN", TfilterA, PortScanningName, comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v %v %v", TfilterA, PortScanningName, ruleLogs("WAN_PROTECTION"), comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v %v %v", TfilterA, PortScanningName, "-j DROP", comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v %v %v", TfilterA, Object, ruleLogs("WAN_PROTECTION"), comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v %v %v", TfilterA, Object, "-j DROP", comment))
	//Drop packets with invalid states
	GbCommands = append(GbCommands, fmt.Sprintf("%v INPUT %v -m conntrack --ctstate INVALID %v -j %v", TfilterA, iiface, comment, Object))
	GbCommands = append(GbCommands, fmt.Sprintf("%v INPUT %v -m conntrack --ctstate NEW ! --syn %v -j %v", TfilterA, iiface, comment, Object))
	GbCommands = append(GbCommands, fmt.Sprintf("%v INPUT %v -p tcp --tcp-flags ALL ALL %v -j %v", TfilterA, iiface, comment, Object))
	GbCommands = append(GbCommands, fmt.Sprintf("%v INPUT %v -p tcp --tcp-flags ALL NONE %v -j %v", TfilterA, iiface, comment, Object))
	GbCommands = append(GbCommands, fmt.Sprintf("%v INPUT %v -p tcp --tcp-flags SYN,FIN SYN,FIN %v -j %v", TfilterA, iiface, comment, Object))
	GbCommands = append(GbCommands, fmt.Sprintf("%v INPUT %v -p tcp --tcp-flags SYN,RST SYN,RST %v -j %v", TfilterA, iiface, comment, Object))
	GbCommands = append(GbCommands, fmt.Sprintf("%v INPUT %v -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG %v -j %v", TfilterA, iiface, comment, Object))
	GbCommands = append(GbCommands, fmt.Sprintf("%v INPUT %v -p tcp --tcp-flags ALL FIN,URG,PSH %v -j %v", TfilterA, iiface, comment, Object))
	GbCommands = append(GbCommands, fmt.Sprintf("%v INPUT %v %v -j %v", TfilterA, iiface, comment, PortScanningName))
	return GbCommands
}
func interfacesSyCTLBehv2(iface string) {
	sysctl := futils.FindProgram("sysctl")
	cmd := fmt.Sprintf("%v -w net.ipv4.conf.%v.log_martians=1", sysctl, iface)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)
	cmd = fmt.Sprintf("%v -w net.ipv4.conf.%v.accept_redirects=0", sysctl, iface)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)
	cmd = fmt.Sprintf("%v -w net.ipv4.conf.%v.send_redirects=0", sysctl, iface)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)
	cmd = fmt.Sprintf("%v -w net.ipv4.conf.%v.accept_source_route=0", sysctl, iface)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)
	cmd = fmt.Sprintf("%v -w net.ipv4.conf.%v.log_martians=%d", sysctl, iface, 1)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)

	cmd = fmt.Sprintf("%v -w net.ipv4.conf.%v.accept_redirects=%d", sysctl, iface, 0)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)

	cmd = fmt.Sprintf("%v -w net.ipv4.conf.%v.send_redirects=%d", sysctl, iface, 0)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)

	cmd = fmt.Sprintf("%v -w net.ipv4.conf.%v.accept_source_route=%d", sysctl, iface, 0)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)

}
func InterfaceSysCTLDefault(iface string) {
	sysctl := futils.FindProgram("sysctl") + " -w"
	cmd := fmt.Sprintf("%v net.ipv4.conf.%v.log_martians=0", sysctl, iface)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)
	cmd = fmt.Sprintf("%v net.ipv4.conf.%v.accept_redirects=1", sysctl, iface)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)
	cmd = fmt.Sprintf("%v net.ipv4.conf.%v.send_redirects=1", sysctl, iface)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)
	cmd = fmt.Sprintf("%v net.ipv4.conf.%v.accept_source_route=1", sysctl, iface)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	_, _ = futils.ExecuteShell(cmd)
}
func groupSrcip(groupname string, dir string) string {
	if len(dir) < 2 {
		dir = "src"
	}
	return fmt.Sprintf("-m set --match-set %v %v", groupname, dir)
}

func isDHCPD(iface string) bool {
	db, err := SqliteConns.DHCPDConnectRO()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return false
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	var ID int
	err = db.QueryRow(`SELECT ID FROM dhcpd WHERE key='listen_nic' AND interface=? AND val=?`, iface, iface).Scan(&ID)
	if err != nil {
		return false
	}
	if ID == 0 {
		return false
	}
	return true
}
func byInterfaceReverseProxy(GbCommands []string, iface string, Ports []int) []string {
	comment := fmt.Sprintf("-m comment --comment \"IFACE_%v\"", iface)
	if len(Ports) == 0 {
		return GbCommands
	}
	EnableNginx := sockets.GET_INFO_INT("EnableNginx")
	if EnableNginx == 0 {
		return GbCommands
	}
	iptables := futils.FindProgram("iptables")
	multi := fmt.Sprintf("--match multiport --dports %v", joinPorts(Ports))
	FINAL := fmt.Sprintf("%v -j REVERSEPROXY", comment)
	GbCommands = append(GbCommands, fmt.Sprintf("%v -t filter -A in_%v -p tcp %v %v", iptables, iface, multi, FINAL))
	return GbCommands
}
func byInterfaceNginx(GbCommands []string, iface string) []string {
	comment := fmt.Sprintf("-m comment --comment \"IFACE_%v\"", iface)
	EnableNginx := sockets.GET_INFO_INT("EnableNginx")
	if EnableNginx == 0 {
		return GbCommands

	}

	EnableNginxFW := sockets.GET_INFO_INT("EnableNginxFW")
	Ports := nginxIfacePorts(iface)
	if EnableNginxFW == 0 {
		return byInterfaceReverseProxy(GbCommands, iface, Ports)
	}

	if len(Ports) == 0 {
		return GbCommands
	}
	grpi := "-m set --match-set nginxfww src"
	iptables := futils.FindProgram("iptables")
	multi := fmt.Sprintf("--match multiport --dports %v", joinPorts(Ports))
	GbCommands = append(GbCommands, fmt.Sprintf("%v -t filter -A in_%v -p tcp %v %v %v -j NGNIX_FW_DROP_IN", iptables, iface, multi, grpi, comment))
	return byInterfaceReverseProxy(GbCommands, iface, Ports)

}
func joinPorts(ports []int) string {
	// Create a slice to hold the string representations of the ports
	var strPorts []string

	// Iterate over the slice of integers and convert each to a string
	for _, port := range ports {
		strPorts = append(strPorts, strconv.Itoa(port))
	}

	// Join the slice of strings with a comma
	return strings.Join(strPorts, ",")
}
func nginxIfacePorts(iface string) []int {
	var ports []int
	db, err := SqliteConns.NginxConnectRO()

	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return ports
	}

	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	rows, err := db.Query(`SELECT port FROM stream_ports WHERE interface=?`, iface)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		_ = db.Close()
		return ports
	}

	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	mPort := make(map[int]int)
	for rows.Next() {
		var sPort int
		err := rows.Scan(&sPort)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		if sPort == 0 {
			continue
		}
		mPort[sPort] = sPort
	}

	for xport, _ := range mPort {
		ports = append(ports, xport)
	}
	return ports
}
func ipRuleForInet(GbCommands []string, iface string) []string {
	EnableFireholIPSets := sockets.GET_INFO_INT("EnableFireholIPSets")
	rules := Rules.LoadRules(iface)
	iptables := futils.FindProgram("iptables")
	TfilterA := fmt.Sprintf("%v -t filter -A", iptables)
	mratelim := "-m ratelimit --ratelimit-set"
	for _, rule := range rules {
		RuleAccepted := false
		FINAL := ""
		xprefix := TfilterA
		isNat := false

		log.Info().Msgf("%v Load Rule [%v]: Interface:%v TYPE:[%v]", futils.GetCalleRuntime(), rule.RuleName, iface, rule.Accepttype)

		if rule.Accepttype == "DROP" {
			RuleAccepted = true
			rule.LogContract = "-m conntrack --ctstate NEW,ESTABLISHED"
			FINAL = "-m conntrack --ctstate NEW,ESTABLISHED -j SMART_REJECT"
		}

		if rule.XTratelimit == 1 {
			RuleAccepted = true
			rule.Accepttype = "DROP"
			rule.LogContract = fmt.Sprintf("%v rule%d --ratelimit-mode %v", mratelim, rule.ID, rule.XTratelimitDir)
			FINAL = fmt.Sprintf("%v rule%d --ratelimit-mode %v -j DROP", mratelim, rule.ID, rule.XTratelimitDir)
		}
		if rule.Accepttype == "ACCEPT" {
			RuleAccepted = true
			FINAL = "-j ACCEPT"
		}
		if rule.MOD == "IPFEED" {
			RuleAccepted = true
			if EnableFireholIPSets == 0 {
				continue
			}
			FINAL = fmt.Sprintf("%v -j SMART_REJECT", rule.LogContract)
			rule.Accepttype = "DROP"
			rule.IsClient = 0
		}
		if rule.Accepttype == "TPROXY" {
			RuleAccepted = true
			isNat = true
			rule.IsClient = 0
			xprefix, FINAL, GbCommands = Rules.ExtractFirewallRuleTProxy(rule, GbCommands)
		}
		if rule.Accepttype == "MIRROR" {
			RuleAccepted = true
			isNat = true
			xprefix, FINAL, GbCommands = Rules.ExtractFirewallRuleTEE(rule, GbCommands)
			if len(FINAL) == 0 {
				continue
			}
		}
		if rule.Accepttype == "NEXTHOPE" {
			RuleAccepted = true
			isNat = true
			xprefix, FINAL, GbCommands = Rules.ExtractFirewallRuleNextHope(rule, GbCommands)
			if len(FINAL) == 0 {
				continue
			}
		}

		if strings.HasPrefix(rule.Iface, "MASQ:") {
			RuleAccepted = true
			isNat = true
			rule.IsClient = 0
			rule.Accepttype = "MASQUERADE"
			xprefix, FINAL, GbCommands = Rules.ExtractFirewallRuleMasQuerade(rule, GbCommands)
		}

		matches := RegexNATInterface.FindStringSubmatch(rule.Iface)
		if matches != nil {
			RuleAccepted = true
			log.Debug().Msgf("%v --------------- NAT ---------------", futils.GetCalleRuntime())
			isNat = true
			rule.IsClient = 0
			rule.NatID = futils.StrToInt(matches[2])
			xprefix, FINAL, rule = Rules.ExtractFirewallRuleNat(rule)
			log.Debug().Msgf("%v Interface: %v *NAT* Prefix: %v", futils.GetCalleRuntime(), iface, xprefix)
		}

		if !RuleAccepted {
			log.Warn().Msgf("%v [%v]: Interface:%v TYPE:[%v] INCOMPATIBLE [SKIP!]", futils.GetCalleRuntime(), rule.RuleName, iface, rule.Accepttype)
			continue
		}

		log.Debug().Msgf("%v --------------- ExtractFireWallPorts(%v,%d) ---------------", futils.GetCalleRuntime(), rule.Service, rule.ID)
		services := Rules.ExtractFireWallPorts(rule.Service, rule.ServicesContainer)
		StampInterface := rule.Iface
		if StampInterface == "" {
			StampInterface = "ALL"
		}

		FINAL = fmt.Sprintf("-m comment --comment \"IFACE_%v\" -m comment --comment \"RULE.%d\" %v", StampInterface, rule.ID, FINAL)
		rule.LogContract = fmt.Sprintf("%v -m comment --comment \"LOG.%d\" %v", rule.LogContract, rule.ID, ruleLogs(fmt.Sprintf("%v_%d", rule.Accepttype, rule.ID)))

		var zPrefix []string
		zPrefix = append(zPrefix, xprefix)
		if rule.IsClient == 1 {
			zPrefix = append(zPrefix, fmt.Sprintf("out_%v", StampInterface))
		} else {
			zPrefix = append(zPrefix, fmt.Sprintf("in_%v", StampInterface))
		}
		if isNat {
			zPrefix = []string{xprefix}
		}
		if rule.TimeEnabled == 1 {
			Ttime := Rules.ExtractFirewallRuleTime(rule)
			if len(Ttime) > 3 {
				zPrefix = append(zPrefix, Ttime)
			}
		}
		nDPI := Rules.ExtractFirewallRulenDPI(rule)
		if len(nDPI) > 3 {
			zPrefix = append(zPrefix, nDPI)
		}
		//var OUT []string
		var RULES []string
		prefix := strings.Join(zPrefix, " ")
		if len(services) > 0 {
			for _, partRulle := range services {
				RULES = append(RULES, fmt.Sprintf("%v %v", prefix, partRulle))

			}
		} else {
			RULES = append(RULES, prefix)
		}

		var MIDDLE []string
		sources := acls.BuildRuleSourcesDest(rule, 0)
		Destinations := acls.BuildRuleSourcesDest(rule, 1)

		if len(sources) > 0 && len(Destinations) > 0 {
			for _, source := range sources {
				for _, destination := range Destinations {
					MIDDLE = append(MIDDLE, source.ExRule+" "+destination.ExRule)
				}
			}
		}

		if len(sources) > 0 && len(Destinations) == 0 {
			for _, source := range sources {
				MIDDLE = append(MIDDLE, source.ExRule)
			}
		}
		if len(Destinations) > 0 && len(sources) == 0 {
			for _, destination := range Destinations {
				MIDDLE = append(MIDDLE, destination.ExRule)
			}
		}

		log.Debug().Msgf("%v %d Rules + %d Objects", futils.GetCalleRuntime(), len(RULES), len(MIDDLE))
		for _, MainRule := range RULES {
			MainRule = strings.TrimSpace(MainRule)
			if len(MIDDLE) > 0 {
				for _, middle := range MIDDLE {
					GbCommands = append(GbCommands, fmt.Sprintf("%v %v %v", MainRule, middle, FINAL))
				}
			} else {
				GbCommands = append(GbCommands, fmt.Sprintf("%v %v", MainRule, FINAL))
			}
		}

	}

	return GbCommands

}

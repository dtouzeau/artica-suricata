package afirewall

import (
	"SqliteConns"
	"TuneKernel"
	"afirewall/aFirewallTools"
	"csqlite"
	"database/sql"
	"fmt"
	"futils"
	"ipclass"
	"notifs"
	"os/user"
	"regexp"
	"sockets"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

var proxytransparentPattern1 = regexp.MustCompile(`^:(.+?)\s+-\s+\[`)
var proxytransparentPattern2 = regexp.MustCompile(`^([0-9]+):\s+from all fwmark.*?lookup\s+([0-9]+)`)

type SquidTransparentPorts struct {
	ID                int    `json:"ID"`
	Proxyport         int    `json:"Port"`
	DestPort          int    `json:"DestPort"`
	OtherPorts        string `json:"OtherPorts"`
	UseSSL            int    `json:"UseSSL"`
	Interface         string `json:"Interface"`
	DestPortsCompiled string `json:"DestPortsCompiled"`
	DNAT              int    `json:"DNAT"`
}

func SquidTransparentClean() bool {
	aFirewallTools.CleanRulesByString([]string{"ArticaSquidTransparent"})
	CleanIpRules()
	return true
}
func GetCurrentGroups() map[string]bool {
	grp := make(map[string]bool)
	Lines := GetIptablesArray()
	for _, line := range Lines {
		Group := futils.RegexGroup1(proxytransparentPattern1, line)
		if len(Group) < 3 {
			continue
		}
		grp[Group] = true
	}

	return grp
}

func GetSquidTransparentPorts(Tproxy int) []SquidTransparentPorts {

	db, err := SqliteConns.ProxyConnectRO()
	SquidSSLUrgency := sockets.GET_INFO_INT("SquidSSLUrgency")

	var res []SquidTransparentPorts
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return res
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	rows, err := db.Query(`SELECT ID,localport,port,others_ports,sslcertificate,nic,dnat FROM transparent_ports WHERE enabled=1 AND TProxy=? AND hiddenID=0`, Tproxy)

	if err != nil {
		log.Error().Msgf("%v Query error %v", futils.GetCalleRuntime(), err.Error())
		return res
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		var rec SquidTransparentPorts
		var OtherPorts sql.NullString
		var sslcertificate sql.NullString
		var nic sql.NullString
		err := rows.Scan(&rec.ID, &rec.Proxyport, &rec.DestPort, &OtherPorts, &sslcertificate, &nic, &rec.DNAT)
		if err != nil {
			log.Error().Msgf("%v Scan row error %v", futils.GetCalleRuntime(), err.Error())
			_ = rows.Close()
			_ = db.Close()
			return res
		}

		if len(sslcertificate.String) > 3 {
			if SquidSSLUrgency == 1 {
				continue
			}
			rec.UseSSL = 1
		}
		rec.Interface = futils.Trim(nic.String)
		rec.OtherPorts = OtherPorts.String
		res = append(res, rec)
	}
	return res
}
func getSquidID() int {
	u, err := user.Lookup("squid")
	if err != nil {
		log.Warn().Msg(fmt.Sprintf("Error: user.Lookup(squid) %v", err))
		return 0
	}
	return futils.StrToInt(u.Uid)
}
func SquidTransparentExcludeSources(squid SquidTransparentPorts) []string {

	var res []string
	iptables := futils.FindProgram("iptables")
	comment := "-m comment --comment \"ArticaSquidTransparent\""
	var dports string
	Prefix := fmt.Sprintf("%v -t nat -I PREROUTING ", iptables)
	if len(squid.Interface) > 2 {
		Prefix = fmt.Sprintf("%v -t nat -I PREROUTING -i %v", iptables, squid.Interface)
	}

	if strings.Contains(squid.DestPortsCompiled, ",") {
		dports = fmt.Sprintf(" --match multiport --dports %v", squid.DestPortsCompiled)
	} else {
		dports = fmt.Sprintf(" --dport %v", squid.DestPortsCompiled)
	}

	db, err := ConnectDBProxy()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return res
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	csqlite.ConfigureDBPool(db)
	csqlite.FieldExistCreateINT(db, "transparent_ports", "hiddenID")
	rows, err := db.Query(`SELECT pattern FROM proxy_ports_wbl WHERE include=0 AND portid=?`, squid.ID)

	if err != nil {
		log.Error().Msg(fmt.Sprintf("afirewall.SquidTransparentExcludeSources Query error %v", err.Error()))
		return res
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)
	for rows.Next() {
		var fpat sql.NullString

		err := rows.Scan(&fpat)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("afirewall.TransparentPorts Scan row error %v", err.Error()))
			_ = rows.Close()
			_ = db.Close()
			return res
		}
		pattern := fpat.String
		if len(pattern) < 3 {
			continue
		}

		rule := fmt.Sprintf("%v -s %v -p tcp -m tcp %v -j ACCEPT %v", Prefix, pattern, dports, comment)
		res = append(res, rule)

	}
	return res
}
func SquidTransparentExcludeDestination(squid SquidTransparentPorts) []string {

	var res []string
	iptables := futils.FindProgram("iptables")
	comment := "-m comment --comment \"ArticaSquidTransparent\""
	var dports string
	Prefix := fmt.Sprintf("%v -t nat -I PREROUTING ", iptables)
	if len(squid.Interface) > 2 {
		Prefix = fmt.Sprintf("%v -t nat -I PREROUTING -i %v", iptables, squid.Interface)
	}

	if strings.Contains(squid.DestPortsCompiled, ",") {
		dports = fmt.Sprintf(" --match multiport --dports %v", squid.DestPortsCompiled)
	} else {
		dports = fmt.Sprintf(" --dport %v", squid.DestPortsCompiled)
	}
	RFC := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

	db, err := ConnectDBProxy()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return res
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	csqlite.FieldExistCreateINT(db, "transparent_ports", "hiddenID")
	rows, err := db.Query(`SELECT pattern FROM proxy_ports_wbl WHERE include=1 AND portid=?`, squid.ID)

	if err != nil {
		log.Error().Msgf("%v Query error %v", futils.GetCalleRuntime(), err.Error())
		return res
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)
	for rows.Next() {
		var fpat sql.NullString

		err := rows.Scan(&fpat)
		if err != nil {
			log.Error().Msgf("%v Scan row error %v", futils.GetCalleRuntime(), err.Error())
			_ = rows.Close()
			_ = db.Close()
			return res
		}
		pattern := fpat.String
		if len(pattern) < 3 {
			continue
		}

		rule := fmt.Sprintf("%v -d %v -p tcp -m tcp %v -j ACCEPT %v", Prefix, pattern, dports, comment)
		res = append(res, rule)

	}
	log.Debug().Msgf("%v: Rules Number %d", futils.GetCalleRuntime(), len(res))
	if len(res) == 0 {
		for _, pattern := range RFC {
			rule := fmt.Sprintf("%v -d %v -p tcp -m tcp %v -j ACCEPT %v", Prefix, pattern, dports, comment)
			res = append(res, rule)
		}

	}
	log.Debug().Msgf("%v: Rules Number %d", futils.GetCalleRuntime(), len(res))
	return res
}
func SquidTransparentBuild() {
	SQUIDEnable := sockets.GET_INFO_INT("SQUIDEnable")
	if SQUIDEnable == 0 {
		notifs.BuildProgress(110, "Feature is disabled", "squid.transparent.build")
		SquidTransparentClean()
		return
	}

	notifs.BuildProgress(15, "{configuring}", "squid.transparent.build")
	iptables := futils.FindProgram("iptables")
	comment := "-m comment --comment \"ArticaSquidTransparent\""
	SquidPorts := GetSquidTransparentPorts(0)
	notifs.BuildProgress(15, "{cleaning}", "squid.transparent.build")
	SquidTransparentClean()
	if len(SquidPorts) == 0 {
		notifs.BuildProgress(50, "{building}", "squid.transparent.build")
		SquidTProxyBuild()
		notifs.BuildProgress(100, "{done}", "squid.transparent.build")
		return
	}
	notifs.BuildProgress(50, "{building}", "squid.transparent.build")
	SquidID := getSquidID()

	var WHITES []string
	var RULES []string
	for _, squid := range SquidPorts {
		var DestinationsPorts string
		var dports string
		var squidr string
		if squid.Proxyport == 0 {
			continue
		}
		log.Debug().Msg(fmt.Sprintf("Port ID %d Ports=%v,%v", squid.ID, squid.DestPort, squid.OtherPorts))
		DestinationsPorts = futils.IntToString(squid.DestPort)
		if len(squid.OtherPorts) > 3 {
			log.Debug().Msg(fmt.Sprintf("Port ID %d ->CleanPortListVirgule(%d,%v)", squid.ID, squid.DestPort, squid.OtherPorts))
			DestinationsPorts = CleanPortListVirgule(fmt.Sprintf("%d,%v", squid.DestPort, squid.OtherPorts))
		}
		log.Debug().Msg(fmt.Sprintf("Port ID %d Desintation ports:%v", squid.ID, DestinationsPorts))
		Prefix := fmt.Sprintf("%v -t nat -I PREROUTING -p tcp ! -d 127.0.0.1", iptables)
		if len(squid.Interface) > 2 {
			Prefix = fmt.Sprintf("%v -t nat -I PREROUTING -i %v -p tcp ! -d 127.0.0.1", iptables, squid.Interface)
		}
		if strings.Contains(DestinationsPorts, ",") {
			dports = fmt.Sprintf(" --match multiport --dports %v", DestinationsPorts)
		} else {
			dports = fmt.Sprintf(" --dport %v", DestinationsPorts)
		}
		squid.DestPortsCompiled = DestinationsPorts
		if SquidID > 0 {
			squidr = fmt.Sprintf("-m owner --uid-owner %d", SquidID)
			WHITES = append(WHITES, fmt.Sprintf("%v -t nat -I OUTPUT -p tcp %v %v -j ACCEPT %v", iptables, dports, squidr, comment))
		}
		InterfaceIP := ""
		frule := ""
		if len(squid.Interface) > 0 {
			if squid.Interface == "lo" {
				InterfaceIP = "127.0.0.1"
			} else {
				InterfaceIP = ipclass.InterfaceToIPv4(squid.Interface)
			}
		}
		if !ipclass.IsIPAddress(InterfaceIP) {
			frule = fmt.Sprintf("%v%v -j REDIRECT --to-port %d %v", Prefix, dports, squid.Proxyport, comment)
		} else {
			frule = fmt.Sprintf("%v%v -j DNAT --to-destination %v:%d %v", Prefix, dports, InterfaceIP, squid.Proxyport, comment)
		}
		if squid.DNAT == 1 {
			if squid.Interface == "" {
				squid.Interface = "lo"
			}
			DestIP := ipclass.InterfaceToIPv4(squid.Interface)
			frule = fmt.Sprintf("%v%v --j DNAT --to-destination %v:%d %v", Prefix, dports, DestIP, squid.Proxyport, comment)

		}

		RULES = append(RULES, frule)
		wf := SquidTransparentExcludeSources(squid)
		wd := SquidTransparentExcludeDestination(squid)
		log.Debug().Msg(fmt.Sprintf("afirewall.SquidTransparentBuild white destinations: %d", len(wd)))
		if len(wf) > 0 {
			for _, rrule := range wf {
				log.Debug().Msg(fmt.Sprintf("afirewall.SquidTransparentBuild add [%v]", rrule))
				WHITES = append(WHITES, rrule)
			}
		}
		if len(wd) > 0 {
			for _, rrule := range wd {
				log.Debug().Msg(fmt.Sprintf("afirewall.SquidTransparentBuild add [%v]", rrule))
				WHITES = append(WHITES, rrule)
			}
		}
	}

	for _, Rule := range WHITES {
		RULES = append(RULES, Rule)
	}

	for _, Rule := range RULES {
		log.Debug().Msg(Rule)
		err, content := futils.ExecuteShell(Rule)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%v error %v %v for line [%v]", futils.GetCalleRuntime(), err.Error(), content, Rule))
		}
	}
	notifs.BuildProgress(90, "{building}", "squid.transparent.build")
	SquidTProxyBuild()
	notifs.BuildProgress(100, "{done}", "squid.transparent.build")
}
func CleanPortListVirgule(sf string) string {

	ports := strings.Split(sf, ",")

	Comp := make(map[int]bool)
	for _, port := range ports {

		fport := futils.StrToInt(port)
		if fport == 0 {
			continue
		}
		Comp[fport] = true
	}

	var final []string
	for xPort, _ := range Comp {
		final = append(final, futils.IntToString(xPort))

	}
	return strings.Join(final, ",")
}
func SquidTProxyBuild() {

	SQUIDEnable := sockets.GET_INFO_INT("SQUIDEnable")
	if SQUIDEnable == 0 {
		///SquidTransparentClean()
		return
	}

	SquidPorts := GetSquidTransparentPorts(1)
	//SquidTransparentClean()
	if len(SquidPorts) == 0 {
		return
	}

	ip := futils.FindProgram("ip")
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v rule add fwmark 1 lookup proxy", ip))
	//ip_route_interfaces := ip_route_interfaces()
	MANGLE := "/usr/sbin/iptables -t mangle"
	Comment := "-m comment --comment \"ArticaSquidTransparent\""

	SquidID := getSquidID()

	var WHITES []string
	CurGroups := GetCurrentGroups()

	for _, squid := range SquidPorts {
		var DestinationsPorts string
		var dports string
		var inic, idev string

		TableID := 200 + squid.ID
		if squid.Proxyport == 0 {
			continue
		}
		log.Debug().Msg(fmt.Sprintf("TProxy: Port ID %d Ports=%v,%v", squid.ID, squid.DestPort, squid.OtherPorts))

		if len(squid.Interface) > 2 {
			inic = fmt.Sprintf(" -i %v", squid.Interface)
			idev = fmt.Sprintf(" dev %v", squid.Interface)
		}
		DestinationsPorts = futils.IntToString(squid.DestPort)
		if len(squid.OtherPorts) > 3 {
			log.Debug().Msg(fmt.Sprintf("Port ID %d ->CleanPortListVirgule(%d,%v)", squid.ID, squid.DestPort, squid.OtherPorts))
			DestinationsPorts = CleanPortListVirgule(fmt.Sprintf("%d,%v", squid.DestPort, squid.OtherPorts))
		}
		if strings.Contains(DestinationsPorts, ",") {
			dports = fmt.Sprintf(" --match multiport --dports %v", DestinationsPorts)
		} else {
			dports = fmt.Sprintf(" --dport %v", DestinationsPorts)
		}

		FinalTpxy := fmt.Sprintf("-j TPROXY --tproxy-mark %d --on-port %d", squid.ID, squid.Proxyport)
		GroupName := fmt.Sprintf("in_tproxy.%v", squid.ID)

		_, ok := CurGroups[GroupName]
		if !ok {
			fmt.Println(fmt.Sprintf("Creating chain '%v' in table 'mangle'", GroupName))
			cmd := fmt.Sprintf("%v -N %v %v", MANGLE, GroupName, Comment)
			err, out := futils.ExecuteShell(cmd)
			if err != nil {
				log.Error().Msg(fmt.Sprintf("%v error %v %v", cmd, err.Error(), out))
			}
		}
		_, ok = CurGroups[fmt.Sprintf("%v.divert", GroupName)]
		if !ok {
			fmt.Println(fmt.Sprintf("Creating chain '%v.divert' under '%v' in table 'mangle'", GroupName, GroupName))
			cmd := fmt.Sprintf("%v -N %v.divert %v", MANGLE, GroupName, Comment)
			log.Debug().Msg(cmd)
			err, out := futils.ExecuteShell(cmd)
			if err != nil {
				if !strings.Contains(out, "Chain already exists") {
					log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
				}
			}
		}

		cmd := fmt.Sprintf("%v -I %v%v -p tcp %v %v", MANGLE, GroupName, inic, Comment, FinalTpxy)
		log.Debug().Msg(cmd)
		err, out := futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
		}

		cmd = fmt.Sprintf("%v -I %v%v -p tcp %v -j LOG --log-prefix \"FIREHOL:TRANSPARENT MARK %d\" --log-level 6", MANGLE, GroupName, inic, Comment, squid.ID)
		log.Debug().Msg(cmd)
		err, out = futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
		}

		cmd = fmt.Sprintf("%v -I %v.divert %v -j ACCEPT", MANGLE, GroupName, Comment)
		log.Debug().Msg(cmd)
		err, out = futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
		}

		cmd = fmt.Sprintf("%v -I %v.divert %v -j MARK --set-mark %d", MANGLE, GroupName, Comment, squid.ID)
		log.Debug().Msg(cmd)
		err, out = futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
		}
		cmd = fmt.Sprintf("%v -I %v.divert -p tcp %v -j LOG --log-prefix \"FIREHOL:TRANSPARENT MARK %d port %d\" --log-level 6", MANGLE, GroupName, Comment, squid.ID, squid.Proxyport)
		log.Debug().Msg(cmd)
		err, out = futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
		}
		cmd = fmt.Sprintf("%v -I %v%v -p tcp -m socket %v -j in_tproxy.%d.divert", MANGLE, GroupName, inic, Comment, squid.ID)
		log.Debug().Msg(cmd)
		err, out = futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
		}

		cmd = fmt.Sprintf("%v -I PREROUTING%v -p tcp %v %v -j %v", MANGLE, inic, dports, Comment, GroupName)
		log.Debug().Msg(cmd)
		err, out = futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
		}

		cmd = fmt.Sprintf("%v -f inet rule del lookup %v", ip, TableID)
		log.Debug().Msg(cmd)
		err, out = futils.ExecuteShell(cmd)

		cmd = fmt.Sprintf("%v -f inet route flush table %v", ip, TableID)
		log.Debug().Msg(cmd)
		err, out = futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
		}

		cmd = fmt.Sprintf("%v -f inet rule add from all fwmark %d%v lookup %v", ip, squid.ID, idev, TableID)
		log.Debug().Msg(cmd)
		err, out = futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
		}
		//$sh[]="$ip -f inet route add local 0.0.0.0/0 dev lo table $TableID $silent";
		cmd = fmt.Sprintf("%v -f inet route add local default dev lo scope host table %v", ip, TableID)
		log.Debug().Msg(cmd)
		err, out = futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
		}

		RlSrc := SquidTProxyExcludeSources(squid)
		if len(RlSrc) > 0 {
			for _, rr := range RlSrc {
				WHITES = append(WHITES, rr)
			}
		}
		RlSrc = SquidTProxyExcludeDestinations(squid)
		if len(RlSrc) > 0 {
			for _, rr := range RlSrc {
				WHITES = append(WHITES, rr)
			}
		}

	}
	if SquidID > 0 {
		WHITES = append(WHITES, fmt.Sprintf("%v -I PREROUTING -m mark --mark 1 %v -j RETURN", MANGLE, Comment))
		squidr := fmt.Sprintf("-m owner --uid-owner %d", SquidID)
		WHITES = append(WHITES, fmt.Sprintf("%v -I OUTPUT %v %v -j MARK --set-mark 1", MANGLE, squidr, Comment))
	}

	for _, cmd := range WHITES {
		log.Debug().Msg(cmd)
		err, out := futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %v %v", cmd, err.Error(), out))
		}
	}

	TuneKernel.TuneKernel()

}
func SquidTProxyExcludeSources(squid SquidTransparentPorts) []string {

	var res []string
	MANGLE := "/usr/sbin/iptables -t mangle"
	Comment := "-m comment --comment \"ArticaSquidTransparent\""

	db, err := ConnectDBProxy()
	if err != nil {
		log.Error().Msg(fmt.Sprintf("afirewall.SquidTransparentExcludeSources %v", err.Error()))
		return res
	}
	defer db.Close()
	csqlite.FieldExistCreateINT(db, "transparent_ports", "hiddenID")
	rows, err := db.Query(`SELECT pattern FROM proxy_ports_wbl WHERE include=0 AND portid=?`, squid.ID)

	if err != nil {
		log.Error().Msg(fmt.Sprintf("afirewall.SquidTransparentExcludeSources Query error %v", err.Error()))
		return res
	}
	defer rows.Close()
	for rows.Next() {
		var fpat sql.NullString

		pattern := fpat.String
		if len(pattern) < 3 {
			continue
		}

		rule := fmt.Sprintf("%v -I in_tproxy.%d -s %v %v -j RETURN", MANGLE, squid.ID, pattern, Comment)
		res = append(res, rule)

	}
	return res
}
func SquidTProxyExcludeDestinations(squid SquidTransparentPorts) []string {

	var res []string
	MANGLE := "/usr/sbin/iptables -t mangle"
	Comment := "-m comment --comment \"ArticaSquidTransparent\""

	db, err := ConnectDBProxy()
	if err != nil {
		log.Error().Msg(fmt.Sprintf("afirewall.SquidTProxyExcludeDestinations %v", err.Error()))
		return res
	}
	defer db.Close()
	csqlite.FieldExistCreateINT(db, "transparent_ports", "hiddenID")
	rows, err := db.Query(`SELECT pattern FROM proxy_ports_wbl WHERE include=1 AND portid=?`, squid.ID)

	if err != nil {
		log.Error().Msg(fmt.Sprintf("afirewall.SquidTProxyExcludeDestinations Query error %v", err.Error()))
		return res
	}
	defer rows.Close()
	for rows.Next() {
		var fpat sql.NullString

		pattern := fpat.String
		if len(pattern) < 3 {
			continue
		}

		rule := fmt.Sprintf("%v -I in_tproxy.%d -d %v %v -j RETURN", MANGLE, squid.ID, pattern, Comment)
		res = append(res, rule)

	}
	RFC := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if len(res) == 0 {
		for _, pattern := range RFC {
			rule := fmt.Sprintf("%v -I in_tproxy.%d -d %v %v -j RETURN", MANGLE, squid.ID, pattern, Comment)
			res = append(res, rule)
		}

	}

	return res
}

func CleanIpRules() {

	ip := futils.FindProgram("ip")
	_, out := futils.ExecuteShell(fmt.Sprintf("%v rule", ip))
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line := futils.Trim(line)
		rule, table := futils.RegexGroup2(proxytransparentPattern2, line)
		fRule := futils.StrToInt(rule)
		if fRule > 0 {
			err, _ := futils.ExecuteShell(fmt.Sprintf("%v rule del prio %d", ip, fRule))
			if err != nil {
				log.Error().Msg(fmt.Sprintf("rule del prio error %v", err.Error()))
			}
			cmd := fmt.Sprintf("%v -f inet route flush table %v", ip, table)
			log.Debug().Msg(fmt.Sprintf("CleanIpRules %v", cmd))
			err, _ = futils.ExecuteShell(cmd)
			if err != nil {
				log.Error().Msg(fmt.Sprintf("-f inet route flush table %v", err.Error()))
			}
		} else {
			log.Debug().Msg(fmt.Sprintf("[%v] No matches", line))
		}
	}

}

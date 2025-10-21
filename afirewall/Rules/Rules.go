package Rules

import (
	"SqliteConns"
	"database/sql"
	"fmt"
	"futils"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"ipclass"
	"regexp"
	"sockets"
	"strconv"
	"strings"
)

type AclsRules struct {
	DataPath  string
	IPsetName string
	ExRule    string
}

type IptablesRules struct {
	ID                int    `json:"ID"`
	RuleName          string `json:"RuleName"`
	ForwardTo         string `json:"forwardTo"`
	ForwardToPort     int    `json:"forwardToPort"`
	Iface             string `json:"iface"`
	NatID             int
	IsClient          int    `json:"isClient"`
	Service           string `json:"service"`
	ServicesContainer string `json:"services_container"`
	TimeEnabled       int    `json:"time_enabled"`
	Jlog              int    `json:"logging"`
	Accepttype        string `json:"accept_type"`
	LogContract       string `json:"log_Contract"`
	MOD               string `json:"mod"`
	XTratelimit       int    `json:"xt_ratelimit"`
	XTratelimitDir    string `json:"xt_ratelimit_dir"`
	TimeRestriction   string `json:"time_restriction"`
}

func ExtractFirewallRulenDPI(rule IptablesRules) string {
	EnablenDPI := sockets.GET_INFO_INT("EnablenDPI")
	if EnablenDPI == 0 {
		return ""
	}
	xt_ndpi := fmt.Sprintf("/lib/modules/%v/extra/xt_ndpi.ko", futils.KernelVersion())
	log.Debug().Msgf("%v Kernel version %v [%v]", futils.GetCalleRuntime(), futils.KernelVersion(), xt_ndpi)
	if !futils.FileExists(xt_ndpi) {
		return ""
	}

	db, err := SqliteConns.FirewallConnectRO()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return ""
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	rows, err := db.Query(`SELECT ndpiname FROM firehol_ndpi WHERE ruleid=?`, rule.ID)
	if err != nil {
		log.Error().Msgf("%v:%v", futils.GetCalleRuntime(), err.Error())
		return ""
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	MM := make(map[string]string)
	for rows.Next() {
		var ndpiname sql.NullString
		err := rows.Scan(&ndpiname)
		if err != nil {
			log.Error().Msgf("%v: Error while scanning row %v", futils.GetCalleRuntime(), err.Error())
			_ = rows.Close()
			return ""
		}
		if len(ndpiname.String) < 3 {
			continue
		}
		MM[ndpiname.String] = ndpiname.String
	}
	if len(MM) == 0 {
		return ""
	}

	var TT []string
	for ndpi, _ := range MM {
		TT = append(TT, ndpi)
	}
	if len(TT) == 0 {
		return ""
	}
	return "-m ndpi --proto " + strings.Join(TT, ",")
}
func ExtractFirewallRuleTime(rule IptablesRules) string {

	if len(rule.TimeRestriction) < 3 {
		return ""
	}
	arrayDays := map[int]string{
		1: "monday",
		2: "tuesday",
		3: "wednesday",
		4: "thursday",
		5: "friday",
		6: "saturday",
		7: "sunday",
	}
	TTIME := futils.UnserializeMap1(rule.TimeRestriction)
	var dds []int
	var f []string
	for num := range arrayDays {
		if val, ok := TTIME[fmt.Sprintf("D%d", num)]; ok && futils.StrToInt(val) == 1 {
			dds = append(dds, num)
		}
	}
	if len(dds) > 0 {
		f = append(f, fmt.Sprintf("--weekdays %v", joinPorts(dds)))
	}
	timePattern := regexp.MustCompile(`^[0-9]+:[0-9]+`)
	if timePattern.MatchString(TTIME["ftime"]) && timePattern.MatchString(TTIME["ttime"]) {
		f = append(f, fmt.Sprintf("--timestart %s --timestop %s", TTIME["ftime"], TTIME["ttime"]))
	}
	if len(f) == 0 {
		return ""
	}
	return fmt.Sprintf("-m time %v", strings.Join(f, " "))
}
func ExtractFirewallRuleNat(rule IptablesRules) (string, string, IptablesRules) {

	NatINf := pnatParams(rule.NatID)
	if NatINf.Enabled == 0 {
		return "", "", rule
	}
	xprefix := ""
	FINAL := ""
	Iface := NatINf.Iface
	iptables := futils.FindProgram("iptables")
	Destination := NatINf.Destination
	if len(Destination) < 4 {
		log.Error().Msgf("%v Unable to build NAT rule ID:%d ( destination [%v] invalid)", futils.GetCalleRuntime(), rule.NatID, Destination)
		return "", "", rule
	}
	if NatINf.NAT_TYPE == 0 {
		rule.Accepttype = "NAT"
		xprefix = fmt.Sprintf("%v -t nat -A PREROUTING", iptables)
		if len(Iface) > 1 {
			xprefix = fmt.Sprintf("%v -t nat -A PREROUTING -i %v", iptables, Iface)
		}
		FINAL = fmt.Sprintf("-m conntrack --ctstate NEW -j DNAT --to-destination %v", Destination)
	}
	if NatINf.NAT_TYPE == 1 {
		Group := fmt.Sprintf("SNAT2%d", rule.NatID)
		xprefix = fmt.Sprintf("%v -t nat -A POSTROUTING", iptables)
		if len(Iface) > 1 {
			xprefix = fmt.Sprintf("%v -t nat -A POSTROUTING -o %v", iptables, Iface)
		}
		if rule.Accepttype == "ACCEPT" {
			FINAL = fmt.Sprintf("-m conntrack --ctstate NEW -j %v", Group)
		} else {
			FINAL = "-m conntrack --ctstate NEW -j RETURN"
		}
	}
	if NatINf.NAT_TYPE == 2 {
		xprefix = fmt.Sprintf("%v -t nat -A PREROUTING", iptables)
		if len(Iface) > 1 {
			xprefix = fmt.Sprintf("%v -t nat -A PREROUTING -i %v", iptables, Iface)
		}
		FINAL = fmt.Sprintf("-m conntrack --ctstate NEW -j REDIRECT --to-destination %v", Destination)
	}
	if NatINf.NAT_TYPE == 3 {
		xprefix = fmt.Sprintf("%v -t mangle -A PREROUTING", iptables)
		if len(Iface) > 1 {
			xprefix = fmt.Sprintf("%v -t mangle -A PREROUTING -i %v", iptables, Iface)
		}
		MARKID := 200 + rule.NatID
		FINAL = fmt.Sprintf("-j MARK --set-mark %d", MARKID)
	}

	return xprefix, FINAL, rule
}
func ExtractFirewallRuleTEE(rule IptablesRules, GbCommands []string) (string, string, []string) {
	iptables := futils.FindProgram("iptables")
	if !ipclass.IsIPAddress(rule.ForwardTo) {
		return "", "", GbCommands
	}
	FINAL := fmt.Sprintf("-j TEE --gateway %v", rule.ForwardTo)
	xprefix := fmt.Sprintf("%v -t mangle -A PREROUTING", iptables)
	log.Info().Msgf("%v rule.%d Outgoing=%d", futils.GetCalleRuntime(), rule.ID, rule.IsClient)
	if rule.IsClient == 1 {
		xprefix = fmt.Sprintf("%v -t mangle -A POSTROUTING", iptables)
	}
	return xprefix, FINAL, GbCommands
}
func ExtractFirewallRuleMasQuerade(rule IptablesRules, GbCommands []string) (string, string, []string) {
	ID := futils.StrToInt(strings.ReplaceAll(rule.Iface, "MASQ:", ""))
	Enabled, RuleInterface := masquerade2Interface(ID)

	if (Enabled) == 0 {
		return "", "", GbCommands
	}
	iptables := futils.FindProgram("iptables")
	xprefix := fmt.Sprintf("%v -t nat -A POSTROUTING", iptables)
	if len(RuleInterface) > 2 {
		xprefix = fmt.Sprintf("%v -t nat -A POSTROUTING -o %v", iptables, RuleInterface)
	}
	FINAL := "-m conntrack --ctstate NEW -j MASQUERADE"
	return xprefix, FINAL, GbCommands

}
func ExtractFirewallRuleTProxy(rule IptablesRules, GbCommands []string) (string, string, []string) {
	TMAng := "-t mangle"
	MARK := ""
	TABLEMARK := ""
	iptables := futils.FindProgram("iptables")
	ipbin := futils.FindProgram("ip")
	EnableipV6 := sockets.GET_INFO_INT("EnableipV6")
	if rule.ID < 10 {
		MARK = fmt.Sprintf("50%d", rule.ID)
		TABLEMARK = fmt.Sprintf("150%d", rule.ID)
	} else {
		MARK = fmt.Sprintf("5%d", rule.ID)
		TABLEMARK = fmt.Sprintf("15%d", rule.ID)
	}
	if rule.ForwardToPort == 0 {
		rule.ForwardToPort = 8080
	}
	comment := fmt.Sprintf("-m comment --comment \"IFACE_%v\"", rule.Iface)
	//address := fmt.Sprintf("%v:%d", rule.ForwardTo, rule.ForwardToPort)
	if !ipclass.IsIPAddress(rule.ForwardTo) {
		return "", "", GbCommands
	}
	GbCommands = append(GbCommands, fmt.Sprintf("%v -f inet rule del lookup %v", ipbin, TABLEMARK))
	GbCommands = append(GbCommands, fmt.Sprintf("%v -f inet route flush table %v", ipbin, TABLEMARK))
	GbCommands = append(GbCommands, fmt.Sprintf("%v -f inet rule add from all fwmark %v lookup %v", ipbin, MARK, TABLEMARK))
	if rule.Iface != "ALL" {
		GbCommands = append(GbCommands, fmt.Sprintf("%v -f inet route add default via %v dev %v table %v", ipbin, rule.ForwardTo, rule.Iface, TABLEMARK))
	} else {
		GbCommands = append(GbCommands, fmt.Sprintf("%v -f inet route add default via %v table %v", ipbin, rule.ForwardTo, TABLEMARK))
	}
	if EnableipV6 == 1 {
		GbCommands = append(GbCommands, fmt.Sprintf("%v -f inet6 rule del lookup %v", ipbin, TABLEMARK))
		GbCommands = append(GbCommands, fmt.Sprintf("%v -f inet6 route flush table %v", ipbin, TABLEMARK))
		GbCommands = append(GbCommands, fmt.Sprintf("%v -f inet6 rule add from all fwmark %v lookup %v", ipbin, MARK, TABLEMARK))
		GbCommands = append(GbCommands, fmt.Sprintf("%v -f inet6 route add default via %v table %v", ipbin, rule.ForwardTo, TABLEMARK))
	}

	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -N in_tproxy.%d %v", iptables, TMAng, rule.ID, comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A in_tproxy.%d -p tcp -m tos --tos 0x20 -j RETURN %v", iptables, TMAng, rule.ID, comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A in_tproxy.%d -s %v -j RETURN %v", iptables, TMAng, rule.ID, rule.ForwardTo, comment))
	GbCommands = append(GbCommands, fmt.Sprintf("%v %v -A in_tproxy.%d -p tcp -m tos --tos 0x0 -j MARK --set-mark %v %v", iptables, TMAng, rule.ID, MARK, comment))

	xprefix := fmt.Sprintf("%v %v -A PREROUTING", iptables, TMAng)
	if rule.Iface != "ALL" {
		xprefix = fmt.Sprintf("%v -i %v", xprefix, rule.Iface)
	}
	FINAL := fmt.Sprintf("-j in_tproxy.%d", rule.ID)
	return xprefix, FINAL, GbCommands

}
func ExtractFireWallPorts(ServiceName string, ServicesContainer string) []string {

	var FINAL_RULES []string
	var services []string
	var trule []string

	if ServiceName == "RustDesk" {
		ptcps := []int{21115, 21116, 21117, 21118, 21119}
		trule = append(trule, "-p tcp -m multiport --destination-ports "+joinPorts(ptcps))
		trule = append(trule, "-p udp --dport 21116")
		return trule
	}
	db, err := ConnectDB()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return FINAL_RULES
	}
	defer db.Close()

	if len(ServiceName) > 2 {
		rows, err := db.Query(`SELECT enabled,server_port FROM firehol_services_def WHERE service=?`, ServiceName)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			_ = db.Close()
			return FINAL_RULES
		}
		defer rows.Close()
		for rows.Next() {
			var enabled int
			var server_port string
			err := rows.Scan(&enabled, &server_port)
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
				continue
			}
			if enabled == 0 {
				continue
			}
			tb := strings.Split(server_port, " ")
			for _, zzport := range tb {
				if len(zzport) == 0 {
					continue
				}
				services = append(services, zzport)
			}

		}
	}
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), ServicesContainer)
	if len(ServicesContainer) > 0 {
		ServiceContainersDbase := futils.Base64Decode(ServicesContainer)
		log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), ServiceContainersDbase)
		ServiceContainers := futils.UnserializeMap1(ServiceContainersDbase)
		for ServName, _ := range ServiceContainers {
			ServName = strings.TrimSpace(ServName)
			log.Debug().Msgf("%v Service:=[%v]", futils.GetCalleRuntime(), ServName)
			if ServName == "" {
				continue
			}
			var enabled int
			var server_port sql.NullString
			err := db.QueryRow(`SELECT enabled,server_port FROM firehol_services_def WHERE service=?`, ServName).Scan(&enabled, &server_port)
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
				continue
			}
			log.Debug().Msgf("%v Service:=[Enabled:%d/%v]", futils.GetCalleRuntime(), enabled, server_port)
			if enabled == 0 {
				continue
			}
			tb := strings.Split(server_port.String, " ")
			if len(tb) > 0 {
				for _, zzport := range tb {
					if len(zzport) == 0 {
						continue
					}
					services = append(services, zzport)
				}
			} else {
				services = append(services, server_port.String)
			}

		}
	}
	log.Debug().Msgf("%v %d Services to parse", futils.GetCalleRuntime(), len(services))
	if len(services) == 0 {
		return FINAL_RULES
	}
	MyMaps := ExtractFireWallPortsServices(services)
	for proto, dPorts := range MyMaps {
		var trules []string
		if proto != "any" {
			log.Debug().Msgf("%v PROTOCOL: %v", futils.GetCalleRuntime(), proto)
			trule = append(trules, fmt.Sprintf("-p %v", proto))
		}
		if proto == "icmp" {
			FINAL_RULES = append(FINAL_RULES, strings.Join(trule, " "))
			continue
		}
		if len(dPorts) > 1 {
			trule = append(trule, "-m multiport --destination-ports")
		} else {
			trule = append(trule, "--dport")
		}
		var Xport []string
		for pNumber, _ := range dPorts {
			if futils.StrToInt(pNumber) == 0 {
				continue
			}
			Xport = append(Xport, pNumber)
		}
		if len(Xport) == 0 {
			continue
		}
		trule = append(trule, strings.Join(Xport, ","))
		FINAL_RULES = append(FINAL_RULES, strings.Join(trule, " "))
	}
	return FINAL_RULES
}
func ExtractFireWallPortsServices(services []string) map[string]map[string]bool {
	mainMap := make(map[string]map[string]bool)
	for _, line := range services {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		re := regexp.MustCompile(`^(.+?)/(.+)`)
		matches := re.FindStringSubmatch(line)
		if matches == nil {
			log.Error().Msgf("%v %s did not match", futils.GetCalleRuntime(), line)
			continue
		}
		proto := strings.ToLower(matches[1])
		ports := strings.ToLower(strings.TrimSpace(matches[2]))

		if _, err := strconv.Atoi(proto); err == nil {
			proto, ports = ports, proto
		}
		ports = strings.ReplaceAll(ports, "any", "1:65535")

		if mainMap[proto] == nil {
			mainMap[proto] = make(map[string]bool)
		}
		mainMap[proto][ports] = true
	}
	return mainMap
}
func LoadRules(iface string) []IptablesRules {
	var res []IptablesRules
	db, err := SqliteConns.FirewallConnectRO()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return res
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	rows, err := db.Query(`SELECT ID, ForwardTo, isClient, service, enablet, jlog, accepttype, MOD, 
       xt_ratelimit, xt_ratelimit_dir, ForwardToPort, time_restriction,rulename,services_container FROM iptables_main WHERE eth=? AND enabled=1 ORDER BY zOrder`, iface)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		_ = db.Close()
		return res
	}
	FireHoleLogAllEvents := sockets.GET_INFO_INT("FireHoleLogAllEvents")
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	for rows.Next() {
		var record IptablesRules
		record.Iface = iface
		var TimeEnabled, IsClient sql.NullString
		var ForwardTo, rulename, ServicesContainer, Service, Accepttype, MOD, XTratelimitDir, ForwardToPort, timeRestriction sql.NullString
		err := rows.Scan(
			&record.ID,          // 1. ID
			&ForwardTo,          // 2. ForwardTo
			&IsClient,           // 3. isClient
			&Service,            // 4. service
			&TimeEnabled,        // 5. enablet
			&record.Jlog,        // 6. jlog
			&Accepttype,         // 7. accepttype
			&MOD,                // 8. MOD
			&record.XTratelimit, // 9. xt_ratelimit
			&XTratelimitDir,     // 10. xt_ratelimit_dir
			&ForwardToPort,      // 11. ForwardToPort
			&timeRestriction,    // 12. time_restriction
			&rulename,
			&ServicesContainer, // 14 services_container
		)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		record.IsClient = futils.StrToInt(IsClient.String)
		record.ForwardTo = ForwardTo.String
		record.Service = Service.String
		record.Accepttype = Accepttype.String
		record.MOD = MOD.String
		record.XTratelimitDir = XTratelimitDir.String
		record.ForwardToPort = futils.StrToInt(ForwardTo.String)
		record.TimeRestriction = timeRestriction.String
		record.TimeEnabled = futils.StrToInt(TimeEnabled.String)
		record.ServicesContainer = ServicesContainer.String
		record.RuleName = rulename.String

		log.Debug().Msgf("%v Loading Rule [%v] ID:%d", futils.GetCalleRuntime(), record.RuleName, record.ID)
		if FireHoleLogAllEvents == 1 {
			record.Jlog = 1
		}
		res = append(res, record)
	}

	return res
}
func ConnectDB() (*sql.DB, error) {
	databaseFile := "/home/artica/SQLITE/firewall.db"
	futils.CreateDir("/home/artica/SQLITE")
	db, err := sql.Open("sqlite3", databaseFile)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil, err
	}
	return db, nil
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

type PNATinfos struct {
	JLog        int    `json:"JLog"`
	Enabled     int    `json:"Enabled"`
	NAT_TYPE    int    `json:"NAT_TYPE"`
	Dstaddr     string `json:"dstaddr"`
	Dstaddrport int    `json:"dstaddrport"`
	Iface       string `json:"iface"`
	Destination string `json:"destination"`
}

func pnatParams(ID int) PNATinfos {
	var Inf PNATinfos
	db, err := ConnectDB()
	if err != nil {
		log.Error().Msgf("%v Error connecting DB %v", futils.GetCalleRuntime(), err)
		return Inf
	}
	defer db.Close()
	var dstaddr sql.NullString
	db.QueryRow(`SELECT nic,jlog,enabled,NAT_TYPE,dstaddr,dstaddrport FROM pnic_nat WHERE ID=?`, ID).Scan(
		&Inf.Iface, &Inf.JLog, &Inf.Enabled, &Inf.NAT_TYPE, &dstaddr, &Inf.Dstaddrport)
	Inf.Dstaddr = dstaddr.String
	log.Debug().Msgf("%v NAT:%d Destination: %v:%v", futils.GetCalleRuntime(), ID, Inf.Dstaddr, Inf.Dstaddrport)
	if !ipclass.IsIPAddress(Inf.Dstaddr) {
		log.Debug().Msgf("%v NAT:%d Destination: %v:%v -> NOT AN IP ADDRESS", futils.GetCalleRuntime(), ID, Inf.Dstaddr, Inf.Dstaddrport)
		Inf.Dstaddr = futils.GethostbyIP(Inf.Dstaddr)
	}
	if ipclass.IsIPAddress(Inf.Dstaddr) {
		Inf.Destination = fmt.Sprintf("%v:%v", Inf.Dstaddr, Inf.Dstaddrport)
	}
	return Inf
}
func masquerade2Interface(ID int) (int, string) {
	db, err := ConnectDB()
	if err != nil {
		log.Error().Msgf("%v Error connecting DB %v", futils.GetCalleRuntime(), err)
		return 0, ""
	}
	defer db.Close()
	var Iface sql.NullString
	var enabled int
	db.QueryRow(`SELECT enabled,nic FROM firehol_masquerade WHERE ID=?`, ID).Scan(&enabled, &Iface)
	return enabled, Iface.String
}

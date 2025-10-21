package afirewall

import (
	"SqliteConns"
	"afirewall/IPSetClass"
	"afirewall/aFirewallTools"
	"database/sql"
	"fmt"
	"futils"
	"ipclass"
	"notifs"
	"regexp"
	"sockets"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

var routersPatternFind1 = regexp.MustCompile(`ROUTER\.[0-9]+`)
var RxTrustedNets = regexp.MustCompile(`TRUSTED\.NETS`)

type IptablesMasquerades struct {
	ID       int      `json:"ID"`
	NicFrom  string   `json:"NicFrom"`
	NicTo    string   `json:"NicTo"`
	RuleName string   `json:"RuleName"`
	Sources  []string `json:"Sources"`
}

type IPtablesRouters struct {
	ID              int    `json:"ID"`
	NicFrom         string `json:"NicFrom"`
	NicTo           string `json:"NicTo"`
	Masquerade      int    `json:"Masquerade"`
	RouterName      string `json:"RouterName"`
	RouterGroupName string `json:"RouterGroupName"`
	RouterIN        string `json:"RouterIN"`
	JLOG            int    `json:"JLOG"`
	DenyDHCP        int    `json:"DenyDHCP"`
	OnlyMASQ        int    `json:"OnlyMASQ"`
	NoFirewall      int    `json:"NoFirewall"`
	Policy          int    `json:"Policy"`
}
type IptablesMetricsRecords struct {
	Exists bool `json:"exists"`
	Pkts   int  `json:"pkts"`
	Bytes  int  `json:"bytes"`
}

type IptablesMetrics struct {
	Family map[string]map[int]IptablesMetricsRecords
}

var routersPattern1 = regexp.MustCompile(`LOG.*?/.*?LOG\.([0-9]+)`)
var routersPattern2 = regexp.MustCompile(`^([0-9]+)\s+([0-9]+).*?/.*?ROUTER\.([0-9]+)\s+`)
var routersPattern3 = regexp.MustCompile(`^([0-9]+)\s+([0-9]+).*?/.*?RULE\.CROWDSEC\s+`)
var routersPattern4 = regexp.MustCompile(`^([0-9]+)\s+([0-9]+).*?/.*?TRUSTED\.NETS`)
var routersPattern5 = regexp.MustCompile(`^([0-9]+)\s+([0-9]+)\s+in_ALL\s+all`)
var routersPattern6 = regexp.MustCompile(`^([0-9]+)\s+([0-9]+)\s+out_ALL\s+all`)
var MasqPattern7 = regexp.MustCompile(`^([0-9]+)\s+([0-9]+).*?/.*?MASQR\.([0-9]+)\s+`)
var PatternProxIN = regexp.MustCompile(`^([0-9]+)\s+([0-9]+).*?/.*?PROXYRULES_IN`)
var PatternProxOUT = regexp.MustCompile(`^([0-9]+)\s+([0-9]+).*?/.*?PROXYRULES_OUT`)
var NFQueueWhite = regexp.MustCompile(`^([0-9]+)\s+([0-9]+).*?NFQUEUE_WHITELIST`)
var NFQueueBlack = regexp.MustCompile(`^([0-9]+)\s+([0-9]+).*?NFQUEUE_BLACKLIST`)

// var NFQueueCache = regexp.MustCompile(`^([0-9]+)\s+([0-9]+).*?NFQUEUE_CACHE`)
var NFQueueFinal = regexp.MustCompile(`^([0-9]+)\s+([0-9]+).*?NFQUEUE_FINAL`)

func IPTablesStatus() IptablesMetrics {

	var stats IptablesMetrics

	stats.Family = make(map[string]map[int]IptablesMetricsRecords)
	stats.Family["LOG"] = make(map[int]IptablesMetricsRecords)
	stats.Family["ROUTER"] = make(map[int]IptablesMetricsRecords)
	stats.Family["CROWDSEC"] = make(map[int]IptablesMetricsRecords)
	stats.Family["TRUSTEDNETS"] = make(map[int]IptablesMetricsRecords)
	stats.Family["INALL"] = make(map[int]IptablesMetricsRecords)
	stats.Family["OUTALL"] = make(map[int]IptablesMetricsRecords)
	stats.Family["PROXYRULES_IN"] = make(map[int]IptablesMetricsRecords)
	stats.Family["PROXYRULES_OUT"] = make(map[int]IptablesMetricsRecords)
	stats.Family["PROXYRULES_IN"][0] = IptablesMetricsRecords{}
	stats.Family["PROXYRULES_OUT"][0] = IptablesMetricsRecords{}

	stats.Family["NFQUEUE_WHITELIST"] = make(map[int]IptablesMetricsRecords)
	stats.Family["NFQUEUE_WHITELIST"][0] = IptablesMetricsRecords{}
	stats.Family["NFQUEUE_BLACKLIST"] = make(map[int]IptablesMetricsRecords)
	stats.Family["NFQUEUE_BLACKLIST"][0] = IptablesMetricsRecords{}
	iptables := futils.FindProgram("iptables")

	var Main []string
	err, out := futils.ExecuteShell(fmt.Sprintf("%v -nvL -x", iptables))
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: %v", err.Error(), out))
		return stats
	}
	Main = append(Main, out)
	err, out = futils.ExecuteShell(fmt.Sprintf("%v -t mangle -nvL -x", iptables))
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: %v", err.Error(), out))
		return stats
	}
	Main = append(Main, out)
	err, out = futils.ExecuteShell(fmt.Sprintf("%v -t nat -nvL -x", iptables))
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: %v", err.Error(), out))
		return stats
	}
	Main = append(Main, out)

	tb := strings.Split(strings.Join(Main, "\n"), "\n")

	for _, line := range tb {
		var Pkts string
		var Bytes string
		var ROUTERID int
		var s IptablesMetricsRecords
		line = futils.Trim(line)
		if len(line) == 0 {
			continue
		}
		if strings.Contains(line, "pkts      bytes target     prot opt in     out") {
			continue
		}
		if strings.Contains(line, "Chain INPUT (") {
			continue
		}
		if strings.Contains(line, "Chain FORWARD (") {
			continue
		}
		if strings.Contains(line, "Chain OUTPUT (") {
			continue
		}
		if strings.Contains(line, "Chain PREROUTING (") {
			continue
		}
		if strings.Contains(line, "Chain POSTROUTING (") {
			continue
		}
		if strings.Contains(line, " references)") {
			continue
		}

		Rule := futils.RegexGroup1(routersPattern1, line)
		if len(Rule) > 0 {
			s.Exists = true
			stats.Family["LOG"][futils.StrToInt(Rule)] = s
			continue
		}

		Pkts, Bytes = futils.RegexGroup2(NFQueueWhite, line)
		if len(Pkts) > 0 {
			s.Exists = true
			s.Pkts = futils.StrToInt(Pkts)
			s.Bytes = futils.StrToInt(Bytes)
			t := stats.Family["NFQUEUE_WHITELIST"][0]
			s.Bytes = t.Bytes + s.Bytes
			s.Pkts = t.Pkts + t.Pkts
			stats.Family["NFQUEUE_WHITELIST"][0] = s
			continue
		}
		Pkts, Bytes = futils.RegexGroup2(NFQueueFinal, line)
		if len(Pkts) > 0 {
			s.Exists = true
			Pkts := futils.StrToInt(Pkts)
			Bytes := futils.StrToInt(Bytes)
			t := stats.Family["NFQUEUE_WHITELIST"][0]
			t.Bytes = t.Bytes + Bytes
			t.Pkts = t.Pkts + Pkts
			stats.Family["NFQUEUE_WHITELIST"][0] = t
			continue
		}
		Pkts, Bytes = futils.RegexGroup2(NFQueueBlack, line)
		if len(Pkts) > 0 {
			s.Exists = true
			s.Pkts = futils.StrToInt(Pkts)
			s.Bytes = futils.StrToInt(Bytes)
			stats.Family["NFQUEUE_BLACKLIST"][0] = s
			continue
		}

		Pkts, Bytes = futils.RegexGroup2(routersPattern4, line)
		if len(Pkts) > 0 {
			s.Exists = true
			s.Pkts = futils.StrToInt(Pkts)
			s.Bytes = futils.StrToInt(Bytes)
			stats.Family["TRUSTEDNETS"][0] = s
			continue
		}
		Pkts, Bytes = futils.RegexGroup2(routersPattern5, line)
		if len(Pkts) > 0 {
			s.Exists = true
			s.Pkts = futils.StrToInt(Pkts)
			s.Bytes = futils.StrToInt(Bytes)
			stats.Family["INALL"][0] = s
			continue
		}
		Pkts, Bytes = futils.RegexGroup2(routersPattern6, line)
		if len(Pkts) > 0 {
			s.Exists = true
			s.Pkts = futils.StrToInt(Pkts)
			s.Bytes = futils.StrToInt(Bytes)
			stats.Family["OUTALL"][0] = s
			continue
		}

		Pkts, Bytes, Rule = futils.RegexGroup3(MasqPattern7, line)
		if len(Rule) > 0 {
			ROUTERID = futils.StrToInt(Rule)
			if !stats.Family["ROUTER"][ROUTERID].Exists {
				s.Exists = true
				s.Pkts = futils.StrToInt(Pkts)
				s.Bytes = futils.StrToInt(Bytes)
				stats.Family["ROUTER"][ROUTERID] = s
				continue
			}
			Org := stats.Family["ROUTER"][ROUTERID]
			s.Exists = true
			s.Pkts = s.Pkts + Org.Pkts
			s.Bytes = s.Bytes + Org.Bytes
			stats.Family["ROUTER"][ROUTERID] = s
			continue
		}

		Pkts, Bytes, Rule = futils.RegexGroup3(routersPattern2, line)
		if len(Rule) > 0 {
			ROUTERID = futils.StrToInt(Rule)
			if !stats.Family["ROUTER"][ROUTERID].Exists {
				s.Exists = true
				s.Pkts = futils.StrToInt(Pkts)
				s.Bytes = futils.StrToInt(Bytes)
				stats.Family["ROUTER"][ROUTERID] = s
				continue
			}

			Org := stats.Family["ROUTER"][ROUTERID]
			s.Exists = true
			s.Pkts = s.Pkts + Org.Pkts
			s.Bytes = s.Bytes + Org.Bytes
			stats.Family["ROUTER"][ROUTERID] = s
			continue
		}

		Pkts, Bytes = futils.RegexGroup2(routersPattern3, line)
		if len(Pkts) > 0 {
			s.Exists = true
			s.Pkts = futils.StrToInt(Pkts)
			s.Bytes = futils.StrToInt(Bytes)
			stats.Family["CROWDSEC"][0] = s
			continue
		}
		Pkts, Bytes = futils.RegexGroup2(PatternProxIN, line)
		if len(Pkts) > 0 {
			s.Exists = true
			zINtOLd := stats.Family["PROXYRULES_IN"][0].Pkts
			ZbytesOLd := stats.Family["PROXYRULES_IN"][0].Bytes
			s.Pkts = futils.StrToInt(Pkts) + zINtOLd
			s.Bytes = futils.StrToInt(Bytes) + ZbytesOLd
			stats.Family["PROXYRULES_IN"][0] = s
			continue
		}
		Pkts, Bytes = futils.RegexGroup2(PatternProxOUT, line)
		if len(Pkts) > 0 {
			s.Exists = true
			zINtOLd := stats.Family["PROXYRULES_OUT"][0].Pkts
			ZbytesOLd := stats.Family["PROXYRULES_OUT"][0].Bytes
			s.Pkts = futils.StrToInt(Pkts) + zINtOLd
			s.Bytes = futils.StrToInt(Bytes) + ZbytesOLd
			stats.Family["PROXYRULES_OUT"][0] = s
			continue
		}
		log.Debug().Msg(fmt.Sprintf("NOT DETECTED [%v]", line))

	}

	return stats

}
func SmartReject() {

	Lines := aFirewallTools.CurrentRules()
	A := false
	B := false
	C := false
	var NewF []string
	for _, line := range Lines {
		line = futils.Trim(line)
		if len(line) == 0 {
			continue
		}
		if strings.Contains(line, "SMART_REJECT -") {
			A = true
		}
		if strings.Contains(line, "SMART_REJECT -p tcp") {
			B = true
		}
		if strings.Contains(line, "SMART_REJECT -j REJECT") {
			C = true
		}
		if strings.Contains(line, "SMART_REJECT") {
			continue
		}
		NewF = append(NewF, line)
	}
	if A == true {
		if B == true {
			if C == true {
				log.Debug().Msgf("%v SMART REJECT Already set", futils.GetCalleRuntime())
				return
			}
		}
	}
	_ = aFirewallTools.IPTablesRestore(strings.Join(NewF, "\n"))
	iptables := futils.FindProgram("iptables")
	err, out := futils.ExecuteShell(fmt.Sprintf("%v -t filter -N SMART_REJECT", iptables))
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: %v", futils.GetCalleRuntime(), out))
	}
	err, out = futils.ExecuteShell(fmt.Sprintf("%v -A SMART_REJECT -p tcp -j REJECT --reject-with tcp-reset", iptables))
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: %v", futils.GetCalleRuntime(), out))
	}
	err, out = futils.ExecuteShell(fmt.Sprintf("%v -A SMART_REJECT -j REJECT --reject-with icmp-port-unreachable", iptables))
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: %v", futils.GetCalleRuntime(), out))
	}
}

func RoutersBuild(Simulate bool) error {
	c := 0
	notifs.BuildProgress(10, "{cleaning} {rules}", "routers.build.progress")
	FireHolEnable := sockets.GET_INFO_INT("FireHolEnable")
	Routers := RoutersGet()

	var Cleaning []string
	Cleaning = append(Cleaning, "MASQR.")
	Cleaning = append(Cleaning, "ROUTER.")
	Cleaning = append(Cleaning, "FORWARD_")
	Cleaning = append(Cleaning, "ROUTERSMAIN")
	Cleaning = append(Cleaning, "FORWARD -m set --match-set trustednet dst")
	log.Info().Msgf("%v %d router(s) to process", futils.GetCalleRuntime(), len(Routers))
	for _, router := range Routers {
		log.Debug().Msgf("%v Cleaning '%v'", futils.GetCalleRuntime(), router.RouterIN)
		Cleaning = append(Cleaning, router.RouterIN)
	}
	aFirewallTools.CleanRulesByString(Cleaning)
	iptables := futils.FindProgram("iptables")
	FireHoleLogAllEvents := sockets.GET_INFO_INT("FireHoleLogAllEvents")
	ConntrackNew := "-m conntrack --ctstate NEW"
	//dctstateNew := "-m conntrack --ctstate NEW,ESTABLISHED"
	ctstate := "-m state --state RELATED,ESTABLISHED"
	tfilterA := fmt.Sprintf("%v -t filter -A", iptables)
	SmartReject()
	var f []string
	log.Debug().Msgf("%v Building routers", futils.GetCalleRuntime())
	notifs.BuildProgress(50, "{building}", "routers.build.progress")
	for _, router := range Routers {
		if FireHoleLogAllEvents == 1 {
			router.JLOG = 1
		}
		Action := "-j ACCEPT"
		IN := router.RouterIN
		FwLog := fmt.Sprintf("FORWARD_%v", router.ID)
		Comment := fmt.Sprintf("-m comment --comment \"%v\" -m comment --comment \"ROUTERSMAIN\"", router.RouterName)
		command := fmt.Sprintf("%v -t filter -N %v %v -m comment --comment \"%v\"", iptables, IN, Comment, futils.GetCalleRuntime())
		f = append(f, command)

		if router.Policy == 1 {
			Action = "-j SMART_REJECT"
		}

		f = append(f, fmt.Sprintf("%v FORWARD -i %v -o %v %v -j %v", tfilterA, router.NicFrom, router.NicTo, Comment, IN))

		if router.Masquerade == 1 {

			if router.JLOG == 1 {
				MasqName := fmt.Sprintf("MASQUERADE_%d", router.ID)
				f = append(f, fmt.Sprintf("%v -t nat -I POSTROUTING -o %v %v %v %v", iptables, router.NicTo, ConntrackNew, Comment, ruleLogs(MasqName)))
			}
			f = append(f, fmt.Sprintf("%v -t nat -I POSTROUTING -o %v %v %v -j MASQUERADE", iptables, router.NicTo, ConntrackNew, Comment))

		}

		if router.DenyDHCP == 1 {
			if router.JLOG == 1 {
				FDENY := fmt.Sprintf("FDENY_%d", router.ID)
				f = append(f, fmt.Sprintf("%v %v -p udp --sport 68 --dport 67 %v %v", tfilterA, IN, Comment, ruleLogs(FDENY)))
				f = append(f, fmt.Sprintf("%v %v -p udp --sport 67 --dst 255.255.255.255 %v %v", tfilterA, IN, Comment, ruleLogs(FDENY)))
				f = append(f, fmt.Sprintf("%v %v -p udp --dport 67:68 %v %v", tfilterA, IN, Comment, ruleLogs(FDENY)))
			}
			f = append(f, fmt.Sprintf("%v %v -p udp --sport 68 --dport 67 %v -j DROP", tfilterA, IN, Comment))
			f = append(f, fmt.Sprintf("%v %v -p udp --sport 67 --dst 255.255.255.255 %v -j DROP", tfilterA, IN, Comment))
			f = append(f, fmt.Sprintf("%v %v -p udp --dport 67:68 %v  -j DROP", tfilterA, IN, Comment))

			if router.JLOG == 1 {
				FDENY := fmt.Sprintf("FDENY_%d", router.ID)
				f = append(f, fmt.Sprintf("%v -I FORWARD 1 -i %v -o %v -p udp -m multiport --dports 67,68 %v %v", iptables, router.NicFrom, router.NicTo, Comment, ruleLogs(FDENY)))
			}
			//Add Specific DHCP if exists
			f = append(f, fmt.Sprintf("%v -I FORWARD -i %v -o %v -p udp -m multiport --dports 67,68 %v -j DROP", iptables, router.NicFrom, router.NicTo, Comment))

		}
		if router.NoFirewall == 0 {
			if router.JLOG == 1 {
				f = append(f, fmt.Sprintf("%v %v %v %v", tfilterA, IN, Comment, ruleLogs(FwLog)))
			}
			log.Debug().Msgf("%v Router: %d Firewall=%d", futils.GetCalleRuntime(), router.ID, router.NoFirewall)

			if FireHolEnable == 1 {
				FwRules := ipRuleForInet([]string{}, fmt.Sprintf("%v2%v", router.NicFrom, router.NicTo))
				for _, line := range FwRules {

					f = append(f, fmt.Sprintf("%v -m comment --comment \"%v\"", line, futils.GetCalleRuntime()))
				}
			}

			f = append(f, fmt.Sprintf("%v %v %v %v %v", tfilterA, IN, ctstate, Comment, Action))
			f = append(f, fmt.Sprintf("%v %v %v %v", tfilterA, IN, Comment, Action))
		}

		c++
	}
	var ErrArr []string
	log.Debug().Msgf("%v %d builded rules", futils.GetCalleRuntime(), c)
	if c > 0 {
		notifs.BuildProgress(70, "{building}", "routers.build.progress")
		//f = futils.ReverseStringArray(f)
		_ = futils.FilePutContents("/proc/sys/net/ipv4/ip_forward", "1")
		for _, cmd := range f {
			if Simulate {
				fmt.Println(cmd)
				continue
			}
			err, out := futils.ExecuteShell(cmd)
			if err != nil {
				log.Error().Msg(fmt.Sprintf("%v [%v] %v: %v", futils.GetCalleRuntime(), cmd, err.Error(), out))
				ErrArr = append(ErrArr, fmt.Sprintf("%v: %v", err.Error(), out))
			}
		}

	}

	if FireHolEnable == 1 {
		log.Debug().Msgf("%v Checking trustednets", futils.GetCalleRuntime())
		if !IsGroupN("trustednets") {
			log.Warn().Msgf("%v Group trustednets doesn't exists -> Create it", futils.GetCalleRuntime())
			TrustedAddRules()
		}

		Comment := fmt.Sprintf("-m comment --comment \"%v\" -m comment --comment \"ROUTERSMAIN\"", "ROUTER.0")
		cmd := fmt.Sprintf("%v FORWARD %v -m set --match-set trustednet dst -j trustednets", tfilterA, Comment)
		err, out := futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), cmd)
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), out)
		}
	}
	if len(ErrArr) > 0 {
		notifs.BuildProgress(75, "{building}", "routers.build.progress")
		SquidTransparentBuild()
		notifs.BuildProgress(80, "{building}", "routers.build.progress")
		log.Debug().Msgf("%v -->BuildMasqueradeRules()", futils.GetCalleRuntime())
		BuildMasqueradeRules()
		notifs.BuildProgress(85, "{building}", "routers.build.progress")
		MasqueradeBuild()
		notifs.BuildProgress(110, "{building} {failed}", "routers.build.progress")
		return fmt.Errorf(strings.Join(ErrArr, "<br>"))
	}
	notifs.BuildProgress(75, "{building}", "routers.build.progress")
	SquidTransparentBuild()
	notifs.BuildProgress(80, "{building} {success}", "routers.build.progress")
	log.Debug().Msgf("%v -->BuildMasqueradeRules()", futils.GetCalleRuntime())
	BuildMasqueradeRules()
	notifs.BuildProgress(85, "{building} {success}", "routers.build.progress")
	MasqueradeBuild()
	notifs.BuildProgress(100, "{building} {success}", "routers.build.progress")
	BuildMirroredInterfaces()
	return nil
}
func RoutersClean() bool {

	Lines := GetIptablesArray()
	Changes := false
	var NewLines []string
	for _, line := range Lines {

		if futils.RegexFind(routersPatternFind1, line) {
			Changes = true
			continue
		}
		NewLines = append(NewLines, line)
	}

	if !Changes {
		return false
	}
	_ = aFirewallTools.IPTablesRestore(strings.Join(NewLines, "\n"))
	return true
}
func BuildMasqueradeRules() {
	iptablesBin := futils.FindProgram("iptables")
	log.Debug().Msgf("%v finding iptables rules", futils.GetCalleRuntime())
	Rules := masqueradRules()
	if len(Rules) == 0 {
		log.Debug().Msgf("%v No rule, SKIP", futils.GetCalleRuntime())
		return
	}
	for _, rule := range Rules {
		MarNumber := 8000 + rule.ID
		var f []string
		MARKLOG := fmt.Sprintf("-m comment --comment \"MASQR.%d\"", rule.ID)
		f = append(f, iptablesBin)
		f = append(f, "-t mangle -A PREROUTING")
		f = append(f, fmt.Sprintf("-i %v", rule.NicFrom))

		if len(rule.Sources) > 0 {
			IPsetName := fmt.Sprintf("MasqSrc%d", rule.ID)
			err := IPSetClass.CreateIPSet(IPsetName, rule.Sources)
			if err != nil {
				log.Error().Msgf("%v Error creating Masquerade rules: %v", futils.GetCalleRuntime(), err)
				continue
			}
			f = append(f, fmt.Sprintf("-m set --match-set %v src", IPsetName))
		}
		f = append(f, MARKLOG)
		f = append(f, fmt.Sprintf("-j MARK --set-mark %d", MarNumber))
		cmdline := strings.Join(f, " ")
		log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), cmdline)
		err, out := futils.ExecuteShell(cmdline)
		if err != nil {
			log.Error().Msgf("%v %v [%v]", futils.GetCalleRuntime(), cmdline, out)
			continue
		}
		cmdline = fmt.Sprintf("%v -t nat -A POSTROUTING -o %v %v -m mark --mark %d -j MASQUERADE", iptablesBin, rule.NicTo, MARKLOG, MarNumber)
		log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), cmdline)
		err, out = futils.ExecuteShell(cmdline)
		if err != nil {
			log.Error().Msgf("%v %v [%v]", futils.GetCalleRuntime(), cmdline, out)
			continue
		}
	}
}
func masqueradRules() []IptablesMasquerades {
	var Rules []IptablesMasquerades
	db, err := SqliteConns.FirewallConnectRO()
	if err != nil {
		log.Error().Msgf("%v db err %v", futils.GetCalleRuntime(), err.Error())
		return Rules
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	rows, err := db.Query(`SELECT ID,nic_from,nic_to,rulename FROM pnic_bridges WHERE enabled=1 AND OnlyMASQ=1`)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: %v", futils.GetCalleRuntime(), err.Error()))
		return Rules
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		var rec IptablesMasquerades
		var RuleName sql.NullString
		err := rows.Scan(&rec.ID, &rec.NicFrom, &rec.NicTo, &RuleName)
		log.Debug().Msgf("%v %d %v --> %v", futils.GetCalleRuntime(), rec.ID, rec.NicFrom, rec.NicTo)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%v: %v", futils.GetCalleRuntime(), err.Error()))
			return Rules
		}
		rec.RuleName = RuleName.String
		rec.Sources = masqueradRulesSrc(db, rec.ID)
		Rules = append(Rules, rec)
	}
	return Rules
}
func masqueradRulesSrc(db *sql.DB, ruleid int) []string {
	rows, err := db.Query(`SELECT networks FROM pnic_bridges_src WHERE enabled=1 AND pnicid=?`, ruleid)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: %v", futils.GetCalleRuntime(), err.Error()))
		return []string{}
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var f []string
	for rows.Next() {
		var sNet sql.NullString
		err := rows.Scan(&sNet)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%v: %v", futils.GetCalleRuntime(), err.Error()))
			return []string{}
		}
		if !ipclass.IsValidIPorCDIRorRange(sNet.String) {
			continue
		}
		f = append(f, sNet.String)
	}
	return f

}

func RoutersGet() []IPtablesRouters {
	var Routers []IPtablesRouters
	db, err := SqliteConns.FirewallConnectRO()
	if err != nil {
		log.Error().Msgf("%v db err %v", futils.GetCalleRuntime(), err.Error())
		return Routers
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	rows, err := db.Query(`SELECT ID,nic_from,nic_to,masquerading,jlog,DenyDHCP,NoFirewall,policy,OnlyMASQ FROM pnic_bridges WHERE enabled=1`)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: %v", futils.GetCalleRuntime(), err.Error()))
		return Routers
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		var rec IPtablesRouters
		var DenyDHCP sql.NullString
		var OnlyMASQ sql.NullString
		err := rows.Scan(&rec.ID, &rec.NicFrom, &rec.NicTo, &rec.Masquerade, &rec.JLOG, &DenyDHCP, &rec.NoFirewall, &rec.Policy, &OnlyMASQ)
		if err != nil {
			log.Error().Msgf("%v Error while scanning row %v", futils.GetCalleRuntime(), err.Error())
			_ = rows.Close()
			return Routers
		}
		if futils.StrToInt(OnlyMASQ.String) == 1 {
			log.Info().Msgf("%v sklip router %d Only MASQ defined", futils.GetCalleRuntime(), rec.ID)
		}
		rec.OnlyMASQ = futils.StrToInt(OnlyMASQ.String)
		rec.DenyDHCP = futils.StrToInt(DenyDHCP.String)
		rec.RouterName = fmt.Sprintf("ROUTER.%d", rec.ID)
		rec.RouterGroupName = fmt.Sprintf("%v2%v", rec.NicFrom, rec.NicTo)
		rec.RouterIN = fmt.Sprintf("in_%v", rec.RouterGroupName)
		Routers = append(Routers, rec)
	}
	return Routers
}

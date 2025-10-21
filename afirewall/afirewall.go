package afirewall

import (
	"SqliteConns"
	"afirewall/aFirewallTools"
	"database/sql"
	"fmt"
	"futils"
	"sockets"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

type IfConfigs struct {
	RPFilter          int
	AcceptRedirects   int
	LogMartians       int
	AcceptSourceRoute int
	Forwarding        int
	MCForwarding      int
	SendRedirects     int
	SysCtlEnable      int
	Proxyarp          int
	forwarding        int
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

func ConnectDBProxy() (*sql.DB, error) {
	databaseFile := "/home/artica/SQLITE/proxy.db"
	futils.CreateDir("/home/artica/SQLITE")
	db, err := sql.Open("sqlite3", databaseFile)
	if err != nil {
		log.Error().Msg(err.Error())
		return nil, err
	}
	return db, nil
}

func CreateNginxfwwIPSet() {
	if IpSetExists("nginxfww") {
		return
	}
	ipsetBin := futils.FindProgram("ipset")
	cmd := fmt.Sprintf("%v create nginxfww hash:ip,port family inet hashsize 16384 timeout 0 maxelem 1000000", ipsetBin)
	err, out := futils.ExecuteShell(cmd)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), out)
	}
}
func IsCrowdSecEnabled() int64 {
	EnableCrowdSec := sockets.GET_INFO_INT("EnableCrowdSec")
	if EnableCrowdSec == 0 {
		return 0
	}
	EnableArticaNFQueue := sockets.GET_INFO_INT("EnableArticaNFQueue")
	if EnableArticaNFQueue == 1 {
		return 0
	}
	ArticaPSnifferDaemon := sockets.GET_INFO_INT("ArticaPSnifferDaemon")
	EnableCrowdsecFirewallBouncer := sockets.GET_INFO_INT("EnableCrowdsecFirewallBouncer")
	if ArticaPSnifferDaemon == 1 {
		EnableCrowdsecFirewallBouncer = 1
	}
	return EnableCrowdsecFirewallBouncer
}
func CreateCrowdSecIpSets() {
	if IsCrowdSecEnabled() == 0 {
		return
	}
	ipset := futils.FindProgram("ipset")

	if len(ipset) < 3 {
		log.Error().Msgf(" %v : ipset no such binary", futils.GetCalleRuntime())
		return

	}

	cmd := fmt.Sprintf("%v create crowdsec-blacklists hash:ip timeout 0 maxelem 1000000", ipset)
	err, out := futils.ExecuteShell(cmd)
	if err != nil {
		if !strings.Contains(out, "the same name already exists") {
			log.Error().Msg(fmt.Sprintf("%v : crowdsec-blacklists %v %v", futils.GetCalleRuntime(), err.Error(), out))
		}

	}

	cmd = fmt.Sprintf("%v create crowdsec6-blacklists hash:ip timeout 0 maxelem 1000000", ipset)
	err, out = futils.ExecuteShell(cmd)
	if err != nil {
		if !strings.Contains(out, "the same name already exists") {
			log.Error().Msg(fmt.Sprintf("%v : crowdsec-blacklists %v %v", futils.GetCalleRuntime(), err.Error(), out))
		}
	}

}
func IpSetObjects() map[string]bool {

	smap := make(map[string]bool)
	ipset := futils.FindProgram("ipset")
	if len(ipset) < 3 {
		log.Error().Msgf("%v : ipset no such binary", futils.GetCalleRuntime())
		return smap

	}
	cmd := fmt.Sprintf("%v list -n", ipset)
	err, out := futils.ExecuteShell(cmd)
	if err != nil {
		log.Error().Msgf("%v ipset %v %v", futils.GetCalleRuntime(), err.Error(), out)
		return smap
	}
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line := futils.Trim(strings.ToLower(line))
		if len(line) < 2 {
			continue
		}
		smap[line] = true
	}
	return smap
}
func IPtablesMainGenericExists(Key string) bool {
	iptablesTemp, _ := aFirewallTools.GetCurrentIPTablesRules()
	tb := strings.Split(iptablesTemp, "\n")
	for _, line := range tb {
		if strings.Contains(line, Key) {
			return true
		}
	}
	return false
}
func IPtablesGroupExists(GroupName string) bool {
	iptablesTemp := GetIptablesArray()
	Pattern := fmt.Sprintf(":%v", strings.ToLower(GroupName))
	for _, line := range iptablesTemp {
		if strings.Contains(strings.ToLower(line), Pattern) {
			return true
		}
	}
	return false
}
func ruleLogs(prefix string) string {
	var f []string
	f = append(f, "-m limit --limit 1/s --limit-burst 5")
	f = append(f, "-j LOG --log-level 6")
	f = append(f, fmt.Sprintf("--log-prefix=\"FIREHOL: %v: \"", prefix))
	return strings.Join(f, " ")

}
func IPtablesCreateGroup(GroupName string, Comment string) error {
	cx := fmt.Sprintf("-m comment --comment \"%v\"", Comment)
	iptables := futils.FindProgram("iptables")
	cmd := fmt.Sprintf("%v -N %v %v", iptables, GroupName, cx)
	err, data := futils.ExecuteShell(cmd)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v : %v %v", futils.GetCalleRuntime(), err, data))
	}
	return nil
}
func InterfacesConfigs() map[string]IfConfigs {
	results := make(map[string]IfConfigs)
	db, err := SqliteConns.InterfacesConnectRO()
	if err != nil {
		log.Error().Msg(fmt.Sprintf("SysctlSquidPorts() db err %v", err.Error()))
		return results
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	rows, errQuery1 := db.Query(`SELECT Interface,SysCtlEnable,RPFilter,AcceptRedirects,LogMartians,AcceptSourceRoute,forwarding,MCForwarding,SendRedirects,proxyarp FROM nics`)
	if errQuery1 != nil {
		log.Error().Msgf("%v Error querying nics table %s", futils.GetCalleRuntime(), errQuery1)
		return results
	}

	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var Interface string
	for rows.Next() {
		var Conf IfConfigs
		_ = rows.Scan(&Interface, Conf.SysCtlEnable, Conf.RPFilter, Conf.AcceptRedirects, Conf.LogMartians, Conf.AcceptSourceRoute, Conf.Forwarding, Conf.MCForwarding, Conf.SendRedirects, Conf.Proxyarp)
		results[Interface] = Conf

	}
	_ = db.Close()
	return results

}
func MustGateway() bool {
	Routers := RoutersGet()
	if len(Routers) > 0 {
		return true
	}
	return false
}
func Flush() {

	iptables := futils.FindProgram("iptables")
	iptablesRestore := futils.FindProgram("iptables-restore")
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -F INPUT", iptables))
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -P INPUT ACCEPT", iptables))
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -F OUTPUT", iptables))
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -P OUTPUT ACCEPT", iptables))
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -F FORWARD", iptables))
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -P FORWARD ACCEPT", iptables))
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -t nat -F PREROUTING", iptables))
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -t nat -F", iptables))
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -t mangle -F", iptables))
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -F", iptables))
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -X", iptables))
	var conf []string
	conf = append(conf, "# Empty the entire filter table")
	conf = append(conf, "*mangle")
	conf = append(conf, ":PREROUTING ACCEPT [0:0]")
	conf = append(conf, ":INPUT ACCEPT [0:0]")
	conf = append(conf, ":FORWARD ACCEPT [0:0]")
	conf = append(conf, ":OUTPUT ACCEPT [0:0]")
	conf = append(conf, ":POSTROUTING ACCEPT [0:0]")
	conf = append(conf, "::DIVERT - [0:0]")
	conf = append(conf, "COMMIT")
	conf = append(conf, "*nat")
	conf = append(conf, ":PREROUTING ACCEPT [0:0]")
	conf = append(conf, ":INPUT ACCEPT [0:0]")
	conf = append(conf, ":POSTROUTING ACCEPT [0:0]")
	conf = append(conf, ":OUTPUT ACCEPT [0:0]")
	conf = append(conf, "COMMIT")
	conf = append(conf, "*filter")
	conf = append(conf, ":INPUT ACCEPT [0:0]")
	conf = append(conf, ":FORWARD ACCEPT [0:0]")
	conf = append(conf, ":OUTPUT ACCEPT [0:0]")
	conf = append(conf, "COMMIT")
	conf = append(conf, "")

	TMPFILE := futils.TempFileName()
	_ = futils.FilePutContents(TMPFILE, strings.Join(conf, "\n"))
	log.Warn().Msgf("%v Flushing iptables configuration", futils.GetCalleRuntime())
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v < %v", iptablesRestore, TMPFILE))
	futils.DeleteFile(TMPFILE)

}

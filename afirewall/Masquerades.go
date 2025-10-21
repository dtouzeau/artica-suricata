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

func MasqueradeClean() bool {
	Lines := GetIptablesArray()
	Changes := false
	var NewLines []string
	for _, line := range Lines {
		if strings.Contains(line, `MASQUERADE.`) {
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
func MasqueradeCleanInterface(InterfaceName string) bool {
	Lines := GetIptablesArray()
	Changes := false
	substr := fmt.Sprintf("MASQUERADE.%v", InterfaceName)
	var NewLines []string
	for _, line := range Lines {
		if strings.Contains(line, substr) {
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
func MasqueradeBuildInterface(InterfaceName string) {
	MasqueradeCleanInterface(InterfaceName)
	iptables := futils.FindProgram("iptables")
	comment := fmt.Sprintf("-m comment --comment \"MASQUERADE.%v\"", InterfaceName)

	rule := fmt.Sprintf("%v -t nat -I POSTROUTING -o %v -j MASQUERADE %v", iptables, InterfaceName, comment)
	err, content := futils.ExecuteShell(rule)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("afirewall.MasqueradeBuild error %v %v for line [%v]", err.Error(), content, rule))
	}
}
func MasqueradeVlans() {
	EnableVLANs := sockets.GET_INFO_INT("EnableVLANs")
	if EnableVLANs == 0 {
		return
	}
	db, err := SqliteConns.InterfacesConnectRO()
	if err != nil {
		log.Error().Msgf("%v: Error Connecting to DB %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	rows, err := db.Query(`SELECT ID FROM nics_vlan WHERE enabled=1 AND masquerade=1`)

	if err != nil {
		log.Error().Msgf("%v Query error %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ID int
		err := rows.Scan(&ID)
		if err != nil {
			log.Error().Msgf("%v Scan row error %v", futils.GetCalleRuntime(), err.Error())
			_ = rows.Close()
			_ = db.Close()
			return
		}
		Eth := fmt.Sprintf("vlan%d", ID)
		MasqueradeBuildInterface(Eth)
	}
}

func MasqueradeBuild() {

	db, err := SqliteConns.InterfacesConnectRO()
	MasqueradeClean()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	rows, err := db.Query(`SELECT Interface FROM nics WHERE enabled=1 and firewall_masquerade=1`)

	if err != nil {
		log.Error().Msgf("%v Query error %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	iptables := futils.FindProgram("iptables")

	for rows.Next() {
		var Interface string

		err := rows.Scan(&Interface)
		if err != nil {
			log.Error().Msgf("%v Scan row error %v", futils.GetCalleRuntime(), err.Error())
			_ = rows.Close()
			_ = db.Close()
			return
		}
		if len(Interface) < 2 {
			continue
		}
		comment := fmt.Sprintf("-m comment --comment \"MASQUERADE.%v\"", Interface)

		rule := fmt.Sprintf("%v -t nat -I POSTROUTING -o %v -j MASQUERADE %v", iptables, Interface, comment)
		err, content := futils.ExecuteShell(rule)
		if err != nil {
			log.Error().Msgf("%v error %v %v for line [%v]", futils.GetCalleRuntime(), err.Error(), content, rule)
		}

	}
	_ = rows.Close()

	EnableVLANs := sockets.GET_INFO_INT("EnableVLANs")
	if EnableVLANs == 1 {
		rows, err = db.Query(`SELECT ID FROM nics_vlan WHERE enabled=1 and masquerade=1`)
		if err != nil {
			log.Error().Msgf("%v Query error %v on nics_vlan", futils.GetCalleRuntime(), err.Error())
			return
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {

			}
		}(rows)

		for rows.Next() {
			var ID int
			err := rows.Scan(&ID)
			if err != nil {
				log.Error().Msgf("%v Scan row error %v", futils.GetCalleRuntime(), err.Error())
				_ = rows.Close()
				_ = db.Close()
				return
			}

			Interface := fmt.Sprintf("vlan%d", ID)
			comment := fmt.Sprintf("-m comment --comment \"MASQUERADE.%v\"", Interface)
			rule := fmt.Sprintf("%v -t nat -I POSTROUTING -o %v -j MASQUERADE %v", iptables, Interface, comment)
			err, content := futils.ExecuteShell(rule)
			if err != nil {
				log.Error().Msgf("%v error %v %v for line [%v]", futils.GetCalleRuntime(), err.Error(), content, rule)
			}
		}
	}
	_ = db.Close()
	return
}

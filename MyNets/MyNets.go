package MyNets

import (
	"SqliteConns"
	"database/sql"
	"futils"
	"strings"

	"github.com/rs/zerolog/log"
)

func LocalNets() map[string]bool {
	zNet := make(map[string]bool)
	db, err := SqliteConns.InterfacesConnectRO()
	if err != nil {
		log.Error().Msgf("%v: Error Connecting to DB %v", futils.GetCalleRuntime(), err.Error())
		return zNet
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	Query := "SELECT ipaddr FROM networks_infos WHERE enabled=1"
	rows, err := db.Query(Query)
	if err != nil {
		log.Error().Msgf("%v:%v %v", futils.GetCalleRuntime(), Query, err.Error())
		_ = db.Close()
		return zNet
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		var ipaddr string
		err := rows.Scan(&ipaddr)
		if err != nil {
			log.Error().Msgf("%v: Error while scanning row %v", futils.GetCalleRuntime(), err.Error())
			_ = rows.Close()
			_ = db.Close()
			return zNet
		}

		pattern := ipaddr
		pattern = strings.ReplaceAll(pattern, "/255.255.255.0", "/24")
		if pattern == "0.0.0.0/0.0.0.0" {
			continue
		}
		zNet[pattern] = true

	}
	return zNet
}
func TrustedNets() map[string]bool {
	zNet := make(map[string]bool)
	db, err := SqliteConns.InterfacesConnectRO()
	if err != nil {
		log.Error().Msgf("%v: Error Connecting to DB %v", futils.GetCalleRuntime(), err.Error())
		return zNet
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	Query := "SELECT ipaddr FROM networks_infos WHERE trusted=1 AND enabled=1"
	rows, err := db.Query(Query)
	if err != nil {
		log.Error().Msgf("%v:%v %v", futils.GetCalleRuntime(), Query, err.Error())
		_ = db.Close()
		return zNet
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		var ipaddr string
		err := rows.Scan(&ipaddr)
		if err != nil {
			log.Error().Msgf("%v: Error while scanning row %v", futils.GetCalleRuntime(), err.Error())
			_ = rows.Close()
			_ = db.Close()
			return zNet
		}

		pattern := ipaddr
		pattern = strings.ReplaceAll(pattern, "/255.255.255.0", "/24")

		if pattern == "0.0.0.0/0.0.0.0" {
			continue
		}
		zNet[pattern] = true

	}
	if len(zNet) == 0 {
		zNet["10.0.0.0/8"] = true
		zNet["172.16.0.0/12"] = true
		zNet["192.168.0.0/16"] = true
	}

	return zNet
}

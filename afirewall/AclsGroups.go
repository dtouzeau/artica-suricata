package afirewall

import (
	"SqliteConns"
	"database/sql"
	"fmt"
	"futils"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

func AddIPSetGroup(ipsetname string, ipaddress string) {

	db, err := SqliteConns.AclsConnectRW()

	if err != nil {
		log.Error().Msgf("%v Error connecting DB %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	zpset := strings.Split(ipsetname, "-")
	if len(zpset) < 2 {
		log.Error().Msgf("%v Error ipsetname [%v] is invalid", futils.GetCalleRuntime(), ipsetname)
		return
	}
	currentDate := time.Now()
	zdate := currentDate.Format("2006-01-02 15:04:05")
	RuleID := zpset[1]
	Groupid := zpset[2]
	description := fmt.Sprintf("Added by Web API for rule id:%v", RuleID)

	var ID int
	db.QueryRow(`SELECT ID FROM webfilters_sqitems WHERE gpid=? AND pattern=?`, Groupid, ipaddress).Scan(&ID)
	if ID > 0 {
		err = IpSetAdd(ipsetname, ipaddress)
		if err != nil {
			log.Error().Msgf("%v Error inserting new item in IPSet: %v", futils.GetCalleRuntime(), err.Error())
		}
		return
	}

	_, err = db.Exec(`INSERT INTO webfilters_sqitems (gpid,pattern,enabled,zdate,description) VALUES (?,?,?,?,?)`, Groupid, ipaddress, 1, zdate, description)
	if err != nil {
		log.Error().Msgf("%v Error inserting new item in SQLite: %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	err = IpSetAdd(ipsetname, ipaddress)
	if err != nil {
		log.Error().Msgf("%v Error inserting new item %v in IPSet [%v]: %v", futils.GetCalleRuntime(), ipaddress, ipsetname, err.Error())
	}

}

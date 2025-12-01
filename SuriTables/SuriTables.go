package SuriTables

import (
	"Classifications"
	"apostgres"
	"database/sql"
	"fmt"
	"futils"
	"notifs"
	"sockets"
	"strings"

	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
)

func Check() {
	DisablePostGres := sockets.GET_INFO_INT("DisablePostGres")
	if DisablePostGres == 1 {
		return
	}
	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}

	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	tables := apostgres.ListTablesMem(db)
	if !tables["suricata_classifications"] {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS suricata_classifications (ID SERIAL NOT NULL PRIMARY KEY, uduniq varchar(50) NOT NULL UNIQUE, shortname varchar(50) NOT NULL,description VARCHAR(128) NOT NULL,priority smallint NOT NULL)`)
		if err != nil {
			if strings.Contains(err.Error(), ".6432: connect: no such file or directory") {
				log.Error().Msgf("%v Issue on PgBouncer, disable it", err.Error())
				sockets.SET_INFO_INT("PgBouncerEnabled", 0)
				return
			}
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		sockets.DeleteTemp("PostgresTables")
	}
	if !tables["suricata_events"] {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS suricata_events (zDate timestamp,src_ip inet,dst_ip inet,dst_port INT NOT NULL,proto varchar(10) NOT NULL,severity smallint NOT NULL,signature BIGINT,proxyname VARCHAR(128),xcount BIGINT)`)
		if err != nil {
			if strings.Contains(err.Error(), "more connections allowed (max_client_conn)") {
				notifs.SquidAdminMysql(1, "Stop REST-API service no more connections allowed (max_client_conn)", "", futils.GetCalleRuntime(), 794)
				notifs.TosyslogGen(fmt.Sprintf("%v %v --> Stopping REST API", futils.GetCalleRuntime(), err.Error()), "postgres")

			}
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		sockets.DeleteTemp("PostgresTables")
	}
	if !tables["suricata_tmp"] {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS suricata_tmp (signature BIGINT PRIMARY KEY,description varchar(128),classtype varchar(35),source_file VARCHAR(40) )`)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
	}
	if !tables["suricata_categories"] {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS suricata_categories (classtype varchar(35),source_file VARCHAR(40),enabled BIGINT NOT NULL DEFAULT 0,available BIGINT NOT NULL DEFAULT 0,PRIMARY KEY (classtype,source_file) )`)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
	}

	if !tables["suricata_sig"] {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS suricata_sig (signature BIGINT PRIMARY KEY,description varchar(128),enabled smallint NOT NULL DEFAULT 1,firewall smallint NOT NULL DEFAULT 0,notify smallint NOT NULL DEFAULT 0 )`)
		if err != nil {
			if strings.Contains(err.Error(), "more connections allowed (max_client_conn)") {
				notifs.SquidAdminMysql(1, "Stop REST-API service no more connections allowed (max_client_conn)", "", futils.GetCalleRuntime(), 794)
				notifs.TosyslogGen(fmt.Sprintf("%v %v --> Stopping REST API", futils.GetCalleRuntime(), err.Error()), "postgres")

			}
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		sockets.DeleteTemp("PostgresTables")
	}
	if !tables["suricata_rules_conf"] {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS suricata_rules_conf (sid BIGINT PRIMARY KEY,enabled smallint NOT NULL DEFAULT 0,firewall smallint NOT NULL DEFAULT 0,notify smallint NOT NULL DEFAULT 0 )`)
		if err != nil {
			if strings.Contains(err.Error(), "more connections allowed (max_client_conn)") {
				notifs.SquidAdminMysql(1, "Stop REST-API service no more connections allowed (max_client_conn)", "", futils.GetCalleRuntime(), 794)
				notifs.TosyslogGen(fmt.Sprintf("%v %v --> Stopping REST API", futils.GetCalleRuntime(), err.Error()), "postgres")

			}
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		sockets.DeleteTemp("PostgresTables")
	}

	if !tables["suricatajson"] {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS suricatajson( time_received VARCHAR(64), ipver VARCHAR(4),
	srcip VARCHAR(40), dstip VARCHAR(40), protocol INTEGER, sp INTEGER, dp INTEGER,
		http_uri TEXT, http_host TEXT, http_referer TEXT, filename TEXT, magic TEXT, state VARCHAR(32),
		md5 VARCHAR(32), stored VARCHAR(32), size BIGINT,proxyname VARCHAR(128))`)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		sockets.DeleteTemp("PostgresTables")
	}
	if !tables["suricata_firewall"] {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS suricata_firewall (ID SERIAL NOT NULL PRIMARY KEY, uduniq varchar(50) NOT NULL UNIQUE, zdate timestamp, signature BIGINT, src_ip inet, dst_port smallint NOT NULL, proto varchar(10) NOT NULL, xauto smallint NOT NULL DEFAULT 0, proxyname varchar(128) )`)
		if err != nil {
			if strings.Contains(err.Error(), "more connections allowed (max_client_conn)") {
				notifs.SquidAdminMysql(1, "Stop REST-API service no more connections allowed (max_client_conn)", "", futils.GetCalleRuntime(), 794)
				notifs.TosyslogGen(fmt.Sprintf("%v %v --> Stopping REST API", futils.GetCalleRuntime(), err.Error()), "postgres")
			}
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		sockets.DeleteTemp("PostgresTables")
	}

	if apostgres.IsDBClosed(db) {
		log.Warn().Msgf("%v DB closed, reconnect", futils.GetCalleRuntime())
		db, err = apostgres.SQLConnect()
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return
		}
		defer func(db *sql.DB) {
			_ = db.Close()
		}(db)
		if apostgres.IsDBClosed(db) {
			log.Warn().Msgf("%v DB closed again.. reconnect", futils.GetCalleRuntime())
			db, err = apostgres.SQLConnect()
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
				return
			}

		}
	}

	apostgres.CreateIndex(db, "suricata_firewall", "ikey", []string{"uduniq", "signature", "src_ip", "proxyname", "zdate", "xauto"})
	apostgres.CreateIndex(db, "suricata_classifications", "ikey", []string{"uduniq", "shortname", "priority"})
	apostgres.CreateIndex(db, "suricatajson", "PROXYNAMEi", []string{"proxyname"})
	apostgres.CreateIndex(db, "suricatajson", "keyi", []string{"time_received", "ipver", "srcip", "dstip", "state"})

	apostgres.CreateFieldInt(db, "suricata_sig", "firewall")
	apostgres.CreateFieldInt(db, "suricata_sig", "notify")
	apostgres.CreateIndex(db, "suricata_sig", "enabled", []string{"firewall", "notify", "enabled"})
	apostgres.CreateIndex(db, "suricata_events", "idx_suricata_events_signature", []string{"signature"})
	apostgres.CreateIndex(db, "suricata_events", "PROXYNAMEi", []string{"proxyname"})
	apostgres.CreateIndex(db, "suricata_events", "keyi", []string{"zDate", "src_ip", "dst_ip", "severity", "signature", "xcount"})
	go Classifications.Parse()
}

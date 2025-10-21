package afirewall

import (
	"SqliteConns"
	"crypto/md5"
	"csqlite"
	"database/sql"
	"fmt"
	"futils"
	"time"

	"github.com/leeqvip/gophp"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

func CheckTables() {

	db, err := SqliteConns.FirewallConnectRW()
	if err != nil {
		log.Error().Msgf("%v Failed to open database: %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()

	}(db)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS firehol_services_def (service text PRIMARY KEY,server_port TEXT,client_port TEXT,enabled INTEGER,helper TEXT )`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS pnic_nat (ID INTEGER PRIMARY KEY AUTOINCREMENT,zMD5 TEXT UNIQUE,NAT_TYPE INTEGER,dstport INTEGER NOT NULL,dstaddr TEXT NOT NULL,srcaddr TEXT NOT NULL,dstaddrport INTEGER NOT NULL,dstaddrTarget TEXT,proto VARCHAR(10),nic TEXT NULL,jlog INTEGER NOT NULL DEFAULT 0,enabled INTEGER DEFAULT 1)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS firehol_masquerade (ID INTEGER PRIMARY KEY AUTOINCREMENT,nic TEXT UNIQUE,include_src TEXT,exclude_dst TEXT,enabled INTEGER NOT NULL DEFAULT 1)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS firehol_itself(ID INTEGER PRIMARY KEY AUTOINCREMENT,md5 TEXT UNIQUE,comment TEXT,pattern TEXT,official INTEGER NOT NULL DEFAULT 0,port TEXT)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS traffic_shaping (ID INTEGER PRIMARY KEY AUTOINCREMENT,pattern TEXT,stmp TEXT,enabled INTEGER NOT NULL DEFAULT 0,ruleid INTEGER NOT NULL DEFAULT 0,`limit` INTEGER NOT NULL DEFAULT 10000000,limit_unit TEXT NOT NULL DEFAULT 'bit')")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS  firehol_ndpi  (ID  INTEGER PRIMARY KEY AUTOINCREMENT,ruleid  INTEGER,ndpiname  TEXT )`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS  link_balance  (ID  INTEGER PRIMARY KEY AUTOINCREMENT,Interface  NOT NULL UNIQUE,checkaddr  TEXT,checkytype  TEXT,mark  INTEGER UNIQUE,weight  INTEGER,probability  INTEGER NOT NULL DEFAULT 50,enabled  INTEGER NOT NULL DEFAULT 1)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}

	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS stmp ON traffic_shaping (stmp)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS ruleid ON traffic_shaping (ruleid)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS pattern ON traffic_shaping (pattern)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS Keypattern ON firehol_itself (pattern)`)

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS iptables_main (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    zOrder INTEGER NOT NULL DEFAULT 1,
    rulename TEXT NOT NULL DEFAULT 'NEW RULE',
    MOD TEXT NOT NULL DEFAULT '',
    eth TEXT NOT NULL DEFAULT '',
    proto TEXT NOT NULL DEFAULT 'tcp',
    MARK INTEGER NOT NULL DEFAULT 0,
    MARK_BALANCE INTEGER NOT NULL DEFAULT 0,
    QOS INTEGER NOT NULL DEFAULT 0,
    destport_group INTEGER NOT NULL DEFAULT 0,
    source_group INTEGER NOT NULL,
    dest_group INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    enablet INTEGER NOT NULL DEFAULT 0,
    jlog INTEGER NOT NULL DEFAULT 0,
    time_restriction TEXT NOT NULL DEFAULT '',
    service TEXT NOT NULL DEFAULT '',
    application TEXT NOT NULL DEFAULT '',
    services_container TEXT NOT NULL DEFAULT '',
    OverideNet INTEGER NOT NULL DEFAULT 0,
    masquerade INTEGER NOT NULL DEFAULT 0,
    isClient INTEGER NOT NULL DEFAULT 0,
    accepttype TEXT NOT NULL DEFAULT 'ACCEPT',
    ForwardTo TEXT NOT NULL DEFAULT '',
    ForwardToPort INTEGER NOT NULL DEFAULT 0,
    ForwardNIC TEXT NOT NULL DEFAULT '',
    L7Mark INTEGER NOT NULL DEFAULT 0);`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS firehol_itself(ID INTEGER PRIMARY KEY AUTOINCREMENT,md5 TEXT UNIQUE,comment TEXT,pattern TEXT,official INTEGER NOT NULL DEFAULT 0,port TEXT)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	csqlite.FieldExistCreateINT(db, "pnic_nat", "jlog")
	csqlite.FieldExistCreateTEXT(db, "pnic_nat", "rulename")
	csqlite.FieldExistCreateINT(db, "iptables_main", "MARK_BALANCE")
	csqlite.FieldExistCreateINT(db, "iptables_main", "ForwardToPort")
	csqlite.FieldExistCreateINT(db, "iptables_main", "xt_ratelimit")
	csqlite.FieldExistCreateTEXTVal(db, "iptables_main", "xt_ratelimit_dir", "src")

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS firehol_routers_exclude (ID INTEGER PRIMARY KEY AUTOINCREMENT,routerid INTEGER,service TEXT,pattern TEXT,destination  INT)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS firehol_client_services (ID INTEGER PRIMARY KEY AUTOINCREMENT,zmd5 TEXT UNIQUE,interface TEXT,service VARCHAR( 20 ),enabled INTEGER,allow_type INTEGER)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS iptables_bridge (ID INTEGER PRIMARY KEY AUTOINCREMENT,nics_virtuals_id INTEGER,nic_inbound TEXT,nic_linked TEXT NOT NULL,zmd5 TEXT UNIQUE)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS pnic_bridges (ID INTEGER PRIMARY KEY AUTOINCREMENT,zMD5 TEXT UNIQUE,nic_from TEXT ,nic_to TEXT ,enabled INTEGER DEFAULT 1,DenyDHCP INTEGER DEFAULT 0,NoFirewall INTEGER NOT NULL DEFAULT 0,jlog INTEGER NOT NULL DEFAULT 0,masquerading INTEGER ,masquerading_invert INTEGER ,STP INTEGER DEFAULT 1, DenyCountries INTEGER,OnlyMASQ INTEGER NOT NULL DEFAULT 0 )`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS pnic_bridges_src (ID INTEGER PRIMARY KEY AUTOINCREMENT,pnicid INTEGER NOT NULL,networks TEXT ,enabled INTEGER DEFAULT 1 )`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS firehol_services (ID INTEGER PRIMARY KEY AUTOINCREMENT,zmd5 TEXT UNIQUE,interface TEXT,service VARCHAR( 20 ),enabled INTEGER,allow_type INTEGER)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS `3proxy_services` ( ID INTEGER PRIMARY KEY AUTOINCREMENT, servicename TEXT NOT NULL DEFAULT 'New service', zorder INTEGER NOT NULL DEFAULT 0, service_type INTEGER, enabled INTEGER NOT NULL DEFAULT 1, maxconn INTEGER NOT NULL DEFAULT 100, redsocks INTEGER NOT NULL DEFAULT 0, redsocks_port INTEGER, redsocks_type INTEGER, options TEXT, listen_port INTEGER, listen_interface TEXT, outgoing_interface TEXT, transparentmethod INTEGER, transparentin TEXT, transparentout TEXT, transparentport TEXT, excludetransparentin TEXT, excludetransparentout TEXT, transparent INTEGER NOT NULL DEFAULT 0)")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS redsocks( ID INTEGER PRIMARY KEY AUTOINCREMENT, servicename TEXT, redsocks_interface TEXT, redsocks_port INTEGER, redsocks_family TEXT, target_type TEXT, zorder INTEGER NOT NULL DEFAULT 0,enabled INTEGER NOT NULL DEFAULT 1, target_port INTEGER, target_ip INTEGER, transparentmethod INTEGER, transparentin TEXT, transparentout TEXT, transparentport TEXT, excludetransparentin TEXT, excludetransparentout TEXT)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS `3proxy_acls_rules` ( ID INTEGER PRIMARY KEY AUTOINCREMENT,rulename TEXT NOT NULL DEFAULT 'New rule', allowdeny INTEGER NOT NULL DEFAULT 0, zorder INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1, bandlimin INTEGER NOT NULL DEFAULT 1, bandlimout INTEGER NOT NULL DEFAULT 1, connlim TEXT, countout  TEXT, countin TEXT, serviceid INTEGER, userlist TEXT, sourcelist TEXT, targetlist TEXT, targetportlist TEXT, commandlist TEXT, weekdaylist TEXT, timeperiodlist TEXT)")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS `3proxy_acls_parent` (ID INTEGER PRIMARY KEY AUTOINCREMENT,ruleid INTEGER, enabled INTEGER, serviceid INTEGER, weight INTEGER, parent_type text, ipaddr text, port INTEGER, username text, password text)")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS `3proxy_acls_templates`( ID INTEGER PRIMARY KEY,explain TEXT, title TEXT, content TEXT)")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
	}

	csqlite.FieldExistCreateINT(db, "3proxy_services", "zorder")
	csqlite.FieldExistCreateINT(db, "3proxy_services", "enabled")
	csqlite.FieldExistCreateINT(db, "3proxy_services", "redsocks")
	csqlite.FieldExistCreateINT(db, "3proxy_services", "redsocks_port")
	csqlite.FieldExistCreateINT(db, "3proxy_services", "redsocks_type")
	csqlite.FieldExistCreateINTDefManual(db, "3proxy_services", "maxconn", 100)

	csqlite.FieldExistCreateTEXT(db, "3proxy_services", "options")
	csqlite.FieldExistCreateTEXT(db, "3proxy_services", "servicename")

	csqlite.FieldExistCreateINT(db, "3proxy_acls_rules", "enabled")
	csqlite.FieldExistCreateINT(db, "3proxy_acls_rules", "bandlimin")
	csqlite.FieldExistCreateINT(db, "3proxy_acls_rules", "bandlimout")
	csqlite.FieldExistCreateINT(db, "3proxy_acls_rules", "connlim")

	csqlite.FieldExistCreateTEXT(db, "3proxy_acls_rules", "countout")
	csqlite.FieldExistCreateTEXT(db, "3proxy_acls_rules", "countin")

	csqlite.FieldExistCreateINT(db, "pnic_bridges", "NoFirewall")
	csqlite.FieldExistCreateINT(db, "pnic_bridges", "jlog")
	csqlite.FieldExistCreateINT(db, "pnic_bridges", "policy")
	csqlite.FieldExistCreateTEXT(db, "pnic_bridges", "rulename")
	csqlite.FieldExistCreateTEXT(db, "pnic_bridges", "OnlyMASQ")

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM firehol_services_def").Scan(&count)
	if err != nil {
		log.Error().Msgf("%v Failed to count rows %v", futils.GetCalleRuntime(), err)
		return
	}
	if count > 50 {
		return
	}

	PortArray := DecodeDefaultServices()

	tx, err := db.Begin()
	if err != nil {
		log.Error().Msgf("%v Failed to begin transaction %v", futils.GetCalleRuntime(), err)
		return
	}

	stmt, err := tx.Prepare("INSERT INTO firehol_services_def (service, server_port, client_port, helper, enabled) VALUES (?, ?, ?, ?, 1)")
	if err != nil {
		log.Error().Msgf("%v Failed to prepare statement %v", futils.GetCalleRuntime(), err)
		return
	}
	defer stmt.Close()

	for service, xarray1 := range PortArray {
		serverPort := xarray1["server"]["ports"]
		clientPort := xarray1["server"]["ports"]
		Helper := ""
		_, err = stmt.Exec(service, serverPort, clientPort, Helper)
		if err != nil {
			log.Error().Msgf("%v Failed to execute statement %v", futils.GetCalleRuntime(), err)
			return
		}
	}

	err = tx.Commit()
	if err != nil {
		log.Error().Msgf("%v Failed to commit transaction %v", futils.GetCalleRuntime(), err)
		return
	}

	err = db.QueryRow("SELECT COUNT(*) FROM firehol_itself").Scan(&count)
	if err != nil {
		log.Error().Msgf("%v Failed to count rows %v", futils.GetCalleRuntime(), err)
		return
	}

	if count == 0 {
		list := []string{"188.165.242.213", "37.187.156.120", "217.70.180.132", "85.236.154.77", "192.30.252.0/22", "185.199.108.0/22", "140.82.112.0/20", "13.114.40.48/32", "13.229.188.59/32", "13.234.176.102/32", "13.234.210.38/32", "13.236.229.21/32", "13.237.44.5/32", "13.250.177.223/32", "15.164.81.167/32", "18.194.104.89/32", "18.195.85.27/32", "18.228.52.138/32", "18.228.67.229/32", "18.231.5.6/32", "35.159.8.160/32", "52.192.72.89/32", "52.64.108.95/32", "52.69.186.44/32", "52.74.223.119/32", "52.78.231.108/32", "151.101.120.0/24", "204.12.217.18", "151.101.122.49", "13.225.233.101", "104.24.106.100", "104.24.110.112", "104.27.156.131", "104.27.116.104", "193.49.48.249", "149.28.239.174", "88.221.83.0/24", "35.231.145.0/24", "147.135.249.253", "23.200.87.0/24", "23.62.99.0/24", "151.101.2.49", "204.51.94.155", "176.9.54.44", "107.22.171.143", "216.245.214.30", "104.27.157.131", "185.225.251.41", "23.62.99.56", "104.123.50.0/24", "217.212.252.70"}
		ports := []int{80, 21, 443}
		date := time.Now().Format("2006-01-02 15:04:05")

		var tt []string
		for _, pattern := range list {
			for _, port := range ports {
				portStr := fmt.Sprintf("tcp:%d", port)
				md5Sum := fmt.Sprintf("%x", md5.Sum([]byte(pattern+portStr)))
				comment := fmt.Sprintf("[%s] Default by Artica Tech", date)
				tt = append(tt, fmt.Sprintf("('%s','%s',1,'%s','%s')", md5Sum, pattern, portStr, comment))
			}
		}
		if len(tt) > 0 {
			query := fmt.Sprintf("INSERT OR IGNORE INTO firehol_itself (md5,pattern,official,port,comment) VALUES %s", tt)
			_, err := db.Exec(query)
			if err != nil {
				log.Printf("Failed to insert values: %v\n", err)
			}
		}
	}

}
func DecodeDefaultServices() map[string]map[string]map[string]string {
	PortArray := make(map[string]map[string]map[string]string)
	dataFilePath := "/usr/share/artica-postfix/ressources/databases/firehol.services.db"
	data := futils.Base64Decode(futils.FileGetContents(dataFilePath))

	phpData, err := gophp.Unserialize([]byte(data))
	if err != nil {
		log.Error().Msgf("%v unserialize failed %v", futils.GetCalleRuntime(), err.Error())
		return PortArray
	}

	xarray, _ := phpData.(map[string]interface{})

	for MainService, xarray1 := range xarray {
		PortArray[MainService] = make(map[string]map[string]string)
		xarray2, _ := xarray1.(map[string]interface{})
		for ServiceType, xarray3 := range xarray2 {
			PortArray[MainService][ServiceType] = make(map[string]string)
			xarray4, _ := xarray3.(map[string]interface{})
			for Key, val := range xarray4 {
				PortArray[MainService][ServiceType][Key] = val.(string)
			}
		}
	}
	return PortArray

}

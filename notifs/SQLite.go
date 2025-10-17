package notifs

import (
	"csqlite"
	"database/sql"
	"fmt"
	"futils"
	"regexp"
	"sockets"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

var RegexMatchAD = regexp.MustCompile(`(?i)(Active directory|NTLM|KERBEROS)`)

func CheckDatabases() {
	err, db := SQLiteConnectNotifs()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		log.Error().Msgf("%v Failed to set WAL mode: %v", futils.GetCalleRuntime(), err)
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS squid_admin_mysql ( ID INTEGER PRIMARY KEY AUTOINCREMENT,zDate INTEGER,content TEXT NULL,subject TEXT,function TEXT NULL,filename TEXT NULL,line INTEGER,severity INTEGER,TASKID INTEGER,removeafter INTEGER NOT NULL DEFAULT 0,sended INTEGER NOT NULL DEFAULT 0)`)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS ntlm_admin_mysql (ID INTEGER PRIMARY KEY AUTOINCREMENT,zDate int,content text,subject text,function text,filename text,line int,severity int,TASKID int)`)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS auth_events (ID INTEGER PRIMARY KEY AUTOINCREMENT,ipaddr TEXT NOT NULL,hostnameTEXT NOT NULL,Country TEXT NOT NULL,success INTEGER NOT NULL DEFAULT '1',uid TEXT NOT NULL,zDate TEXT NOT NULL)`)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS btmp_records (id INTEGER PRIMARY KEY AUTOINCREMENT,zmd5 TEXT NOT NULL UNIQUE ,user TEXT,terminal TEXT,host TEXT,timestamp TEXT,seen INTEGER NOT NULL DEFAULT 0);`)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS sql_errors (ID INTEGER PRIMARY KEY AUTOINCREMENT,zdate INTEGER NOT NULL,subject TEXT NOT NULL,error TEXT NOT NULL,sql TEXT NOT NULL,database TEXT NOT NULL,debug TEXT NOT NULL)`)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}

	csqlite.FieldExistCreateTEXT(db, "auth_events", "hostname")
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS sent ON squid_admin_mysql (sended,removeafter)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS sent ON squid_admin_mysql (sended,removeafter)`)

	_, _ = db.Exec(`CREATE INDEX auth_events_ipaddr ON auth_events (ipaddr);`)
	_, _ = db.Exec(`CREATE INDEX auth_events_hostname ON auth_events (hostname);`)
	_, _ = db.Exec(`CREATE INDEX auth_events_Country ON auth_events (Country);`)

	csqlite.FieldExistCreateTEXT(db, "squid_admin_mysql", "attached_file")
	csqlite.FieldExistCreateTEXT(db, "squid_admin_mysql", "filecontent")
	csqlite.FieldExistCreateTEXT(db, "squid_admin_mysql", "recipients")
	csqlite.FieldExistCreateINT(db, "squid_admin_mysql", "sended")
	csqlite.FieldExistCreateINT(db, "squid_admin_mysql", "removeafter")

	futils.Chmod("/home/artica/SQLITE/system_events.db", 0644)
	futils.ChownFile("/home/artica/SQLITE/system_events.db", "www-data", "www-data")

}

func checkSQLErrors(db *sql.DB) {

	Directory := "/usr/share/artica-postfix/ressources/logs/sql_errors"
	futils.CreateDir(Directory)
	futils.ChownFolder(Directory, "www-data", "www-data")

	files := futils.DirectoryScan(Directory)
	for _, file := range files {
		TmpPath := fmt.Sprintf("%v/%v", Directory, file)
		_, err := db.Exec(futils.FileGetContents(TmpPath))
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
		}
		futils.DeleteFile(TmpPath)

	}
}

func ScanDir() {

	if futils.IsSystemOverloaded() {
		return
	}

	err, db := SQLiteConnectNotifs()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}

	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	checkSQLErrors(db)
	ArticaLogDir := sockets.GET_INFO_STR("ArticaLogDir")
	if len(ArticaLogDir) == 0 {
		ArticaLogDir = "/var/log/artica-postfix"
	}

	Directory := fmt.Sprintf("%v/squid_admin_mysql", ArticaLogDir)
	futils.CreateDir(Directory)

	ALREADY := make(map[string]bool)
	Files := futils.DirectoryScan(Directory)
	for _, filename := range Files {

		FullPath := fmt.Sprintf("%v/%v", Directory, filename)
		ftime := futils.FileTime(FullPath)
		if ftime > 240 {
			futils.DeleteFile(FullPath)
			continue
		}

		Data := futils.FileGetContents(FullPath)
		if len(Data) == 0 {
			futils.DeleteFile(FullPath)
			continue
		}
		array := futils.UnserializeMap1(Data)
		if len(array) < 2 {
			futils.DeleteFile(FullPath)
			continue
		}

		if !futils.IfKeyExistsStr("severity", array) {
			futils.DeleteFile(FullPath)
			continue
		}
		if !futils.IfKeyExistsStr("subject", array) {
			futils.DeleteFile(FullPath)
			continue
		}

		file := array["file"]

		zdate := strings.Replace(array["zdate"], "'", "", -1)
		zdateTime, err := time.Parse("2006-01-02 15:04:05", zdate)
		if err != nil {
			log.Error().Msgf("%v Failed to parse date: %v", futils.GetCalleRuntime(), err)
			TosyslogGen(array["subject"], file)
			futils.DeleteFile(FullPath)
			continue
		}
		zdatemin := zdateTime.Format("2006-01-02 15:04:00")
		function := array["function"]
		line := array["line"]
		severity := array["severity"]
		subject := strings.Replace(array["subject"], "'", "`", -1)
		content := strings.Replace(array["text"], "'", "`", -1)

		smd5 := futils.Md5String(fmt.Sprintf("%s%s%s%s%s", line, file, severity, zdatemin, array["subject"]))
		if ALREADY[smd5] {
			futils.DeleteFile(FullPath)
			continue
		}
		ALREADY[smd5] = true

		if futils.RegexFind(RegexMatchAD, subject) {
			_, err := db.Exec(`INSERT OR IGNORE INTO ntlm_admin_mysql (zDate, content, subject, function, filename, line, severity) VALUES (?, ?, ?, ?, ?, ?, ?)`, zdate, content, subject, function, file, line, severity)
			if err != nil {
				log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
			}
		}

		ArticaNotifsMaxTime := sockets.GET_INFO_INT("ArticaNotifsMaxTime")
		if ArticaNotifsMaxTime == 0 {
			ArticaNotifsMaxTime = 7
		}
		removeafter := time.Now().AddDate(0, 0, int(ArticaNotifsMaxTime)).Unix()

		_, err = db.Exec(`INSERT OR IGNORE INTO squid_admin_mysql (zDate, content, subject, function, filename, line, severity, removeafter) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, zdate, content, subject, function, file, line, severity, removeafter)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
			TosyslogGen(fmt.Sprintf("%v SQL Error %v", futils.GetCalleRuntime(), err.Error()), "articarest")
			continue
		}
		TosyslogGen(array["subject"], file)
		futils.DeleteFile(FullPath)

	}

}

func CleanTables() {

	err, db := SQLiteConnectNotifs()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	SystemEventsRetentionTime := sockets.GET_INFO_INT("SystemEventsRetentionTime")

	if SystemEventsRetentionTime == 0 {
		SystemEventsRetentionTime = 7
	}
	if SystemEventsRetentionTime < 2 {
		SystemEventsRetentionTime = 2
	}
	daysToSubtract := int(SystemEventsRetentionTime)
	currentTime := time.Now()
	timeMinusDays := currentTime.AddDate(0, 0, -daysToSubtract)
	formattedTime := timeMinusDays.Format("2006-01-02 15:04:05")

	ztime := futils.StrToTimeMinusDays(int(SystemEventsRetentionTime))
	if ztime == 0 {
		log.Error().Msgf("%v ztime is zero ???", futils.GetCalleRuntime())
		return
	}

	_, err = db.Exec(`DELETE FROM squid_admin_mysql WHERE zDate < ?`, ztime)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}
	_, err = db.Exec(`DELETE FROM sql_errors WHERE zDate < ?`, ztime)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}
	_, err = db.Exec(`DELETE FROM webconsole_events WHERE zDate < ?`, ztime)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}
	_, err = db.Exec(`DELETE FROM auth_events WHERE zDate < ?`, formattedTime)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}
	_, err = db.Exec(`VACUUM`)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}
}

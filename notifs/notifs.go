package notifs

import (
	"SqliteConns"
	"articasys"
	"compressor"
	"crypto/md5"
	"database/sql"
	"fmt"
	"futils"
	"httpclient"
	"io"
	"ipclass"
	"log/syslog"
	"os"
	"runtime"
	"sockets"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/journal"
	"github.com/leeqvip/gophp"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/host"
)

const ProgressDir = "/usr/share/artica-postfix/ressources/logs/web"

func GetFunctionName() string {
	pc, _, _, ok := runtime.Caller(2)
	if !ok {
		return "unknown"
	}

	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "unknown"
	}

	return fn.Name()
}

func WebconsoleEvents(severity int, subject string, text string) {

	err, db := SQLiteConnectNotifs()
	if err != nil {
		log.Error().Msg(fmt.Sprintf("notifs.WebconsoleEvents %v", err.Error()))
		return
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	Query := `CREATE TABLE IF NOT EXISTS webconsole_events ( ID INTEGER PRIMARY KEY AUTOINCREMENT, zDate INTEGER,
		content TEXT NULL, subject TEXT, severity INTEGER,removeafter INTEGER NOT NULL DEFAULT 0, sended INTEGER NOT NULL DEFAULT 0)`

	_, err = db.Exec(Query)

	if err != nil {
		log.Error().Msg(fmt.Sprintf("notifs.WebconsoleEvents CREATE TABLE: %v", err.Error()))
		_ = db.Close()
		return
	}

	currentTime := strconv.Itoa(int(time.Now().Unix()))
	ArticaNotifsMaxTime := sockets.GET_INFO_INT("ArticaNotifsMaxTime")
	if ArticaNotifsMaxTime == 0 {
		ArticaNotifsMaxTime = 7
	}
	removeafter := CurDateAddDay(int(ArticaNotifsMaxTime))

	_, err = db.Exec(`INSERT OR IGNORE INTO webconsole_events (zDate,content,subject,severity,removeafter) VALUES (?,?,?,?,?)`, currentTime, text, subject, severity, removeafter)

	if err != nil {
		log.Error().Msgf("%>v CREATE TABLE: %v", futils.GetCalleRuntime(), err.Error())
		_ = db.Close()
		return
	}

}

func AdminTrack(Text string) {
	db, err := sql.Open("sqlite3", "/home/artica/SQLITE/admins.db")
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
		return
	}
	zTime := futils.TimeStampToString()
	_, err = db.Exec(`INSERT INTO admintracks (time,ipaddr,username,operation) VALUES (?,'0.0.0.0','WebAPI',?)`, zTime, Text)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}
	TosyslogGen(fmt.Sprintf("[WebAPI] [0.0.0.0] %v", Text), "ArticaTrackAdmins")
}

func TosyslogGen(text string, processname string) bool {

	if processname == "network" {
		Journal(text, futils.GetCalleRuntime(), "network")
	}

	if processname == "hacluster-client" {
		var MyIP string
		HaClusterClientInterface := sockets.GET_INFO_STR("HaClusterClientInterface")
		if len(HaClusterClientInterface) == 0 {
			HaClusterClientInterface = ipclass.DefaultInterface()
		}
		if len(HaClusterClientInterface) > 1 {
			MyIP = ipclass.InterfaceToIPv4(HaClusterClientInterface)
		}
		if len(MyIP) > 3 {
			text = fmt.Sprintf("(%v) %v", MyIP, text)
		}
	}

	syslogger, err := syslog.New(syslog.LOG_INFO, processname)
	if err != nil {
		return false
	}
	log.Debug().Msg(text)
	_ = syslogger.Notice(text)
	_ = syslogger.Close()
	return true
}
func MonitSyslog(Action string, MonitName string, ServiceName string) {
	w, err := syslog.New(syslog.LOG_INFO, "monit")
	if err != nil {
		return
	}
	defer func() {
		closeErr := w.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	Msg := fmt.Sprintf("'%v' %v: %v", MonitName, Action, ServiceName)
	_ = w.Info(Msg)
	_ = w.Close()
}

func SquAdminMySQLPurge() {
	err, db := SQLiteConnectNotifs()
	if err != nil {
		return
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	_, err = db.Exec("DELETE FROM squid_admin_mysql")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}
}
func getUptimeReadable() (string, error) {
	// Get the system uptime in seconds
	uptimeSeconds, err := host.Uptime()
	if err != nil {
		return "", fmt.Errorf("failed to get uptime: %v", err)
	}

	// Convert seconds into days, hours, and minutes
	uptime := int(uptimeSeconds)
	days := uptime / (24 * 3600)
	uptime %= 24 * 3600
	hours := uptime / 3600
	uptime %= 3600
	minutes := uptime / 60

	// Format the output
	result := ""
	if days > 0 {
		result += fmt.Sprintf("%d days, ", days)
	}
	if hours > 0 || days > 0 {
		result += fmt.Sprintf("%d hours, ", hours)
	}
	result += fmt.Sprintf("%d minutes", minutes)

	return result, nil
}
func ActiveDirectoryReport(severity int, subject string, function string) {
	const ReportPath = "/usr/share/artica-postfix/ressources/logs/ConnectionReport.log"
	err, db := SQLiteConnectNotifs()
	if err != nil {
		squidAdminMysqlQueue(0, "Connect SQL failed", err.Error(), futils.GetCalleRuntime(), 172)
		return
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	currentTime := strconv.Itoa(int(time.Now().Unix()))
	Report := futils.FileGetContents(ReportPath)
	_, err = db.Exec(`INSERT OR IGNORE INTO ntlm_admin_mysql (zDate,content,subject,function,severity) VALUES (?,?,?,?,?)`, currentTime, Report, subject, function, severity)

	if err != nil {
		if strings.Contains(err.Error(), "disk image is malformed") {
			log.Error().Msgf("%v Error updating records: %v, database was removed", futils.GetCalleRuntime(), err)
			futils.DeleteFile("/home/artica/SQLITE/system_events.db")
			CheckDatabases()
			return
		}
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	futils.DeleteFile(ReportPath)

}
func UpdateEvent(line string, function string) {
	filename := "/var/log/artica.updater.log"
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)

	sdate := time.Now().Format("2006-01-02 15:04:05")
	pid := os.Getpid()
	_, _ = f.WriteString(fmt.Sprintf("%v [%d] articarest: %v: %v\n", sdate, pid, function, line))
}
func PeerEvent(evdate string, ztime string, line string) {
	filename := "/var/log/squid/peers.log"
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)
	if len(evdate) == 0 {
		evdate = time.Now().Format("2006/01/02 15:04:05")
	} else {
		evdate = evdate + " " + ztime
	}
	_, _ = f.WriteString(fmt.Sprintf("%v %v\n", evdate, line))
}
func CategoriesEvents(line string, function string) {
	filename := "/var/log/categories.updater.log"
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)

	sdate := time.Now().Format("2006-01-02 15:04:05")
	pid := os.Getpid()
	_, _ = f.WriteString(fmt.Sprintf("%v [%d] articarest: %v: %v\n", sdate, pid, function, line))

}
func StatsComDebug(line string, function string) {
	filename := "/var/log/statscom-debug.log"
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)

	sdate := time.Now().Format("2006-01-02 15:04:05")
	pid := os.Getpid()
	_, _ = f.WriteString(fmt.Sprintf("%v [%d] articarest: %v: %v\n", sdate, pid, function, line))

}
func minutesSinceBoot() int {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0
	}

	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}

	return int(seconds / 60)
}

func IsProductionTime() bool {
	now := time.Now()
	startTimeStr := sockets.GET_INFO_STR("ProductionTimeStart")
	if len(startTimeStr) < 3 {
		startTimeStr = "06:00"
	}

	endTimeStr := sockets.GET_INFO_STR("ProductionTimeEnd")
	if len(endTimeStr) < 3 {
		endTimeStr = "22:00"
	}
	if startTimeStr == "00:00" && endTimeStr == "00:00" {
		return true
	}
	startTime, err := time.Parse("15:04", startTimeStr)
	if err != nil {
		return true
	}
	endTime, err := time.Parse("15:04", endTimeStr)
	if err != nil {
		return true
	}
	start := time.Date(now.Year(), now.Month(), now.Day(), startTime.Hour(), startTime.Minute(), 0, 0, now.Location())
	end := time.Date(now.Year(), now.Month(), now.Day(), endTime.Hour(), endTime.Minute(), 0, 0, now.Location())

	if now.Equal(start) || (now.After(start) && now.Before(end)) {
		return true
	}
	return false
}

func SquidAdminMysql(severity int, subject string, text string, function string, line int) bool {
	MinutesSince := minutesSinceBoot()
	if MinutesSince < 3 {
		severity = 2
	}

	if severity == 0 {
		if !IsProductionTime() {
			severity = 2
		}

		HaClusterClient := sockets.GET_INFO_INT("HaClusterClient")
		if HaClusterClient == 1 {
			TosyslogGen(fmt.Sprintf("[ERROR]: %v", subject), "hacluster-client")
		}
	}

	err, db := SQLiteConnectNotifs()
	if err != nil {
		squidAdminMysqlQueue(severity, subject, text, function, line)
		return false
	}

	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	if len(function) == 0 {
		function = GetFunctionName()
	}

	Hostname, _ := os.Hostname()
	Cpus := articasys.CpuNumber()
	Mem := articasys.TotalMemorymb()
	Kernel := articasys.KernelVersion()
	Interfaces := articasys.InterfacesReport()
	CurtTime := futils.CurrentTimeStr()
	Uptime, _ := getUptimeReadable()

	var Ztext []string

	Ztext = append(Ztext, text)
	Ztext = append(Ztext, "-------------------------------------")
	Ztext = append(Ztext, fmt.Sprintf("function: %v", function))
	Ztext = append(Ztext, fmt.Sprintf("Server Load: %v (5min)", articasys.LoadAvg5min()))
	Ztext = append(Ztext, fmt.Sprintf("Uptime: %v since (%d minutes)", Uptime, MinutesSince))
	Ztext = append(Ztext, fmt.Sprintf("Time: %v", CurtTime))
	Ztext = append(Ztext, fmt.Sprintf("Server: %v", Hostname))
	Ztext = append(Ztext, fmt.Sprintf("Hardware: %d CPU(s) %vMB of memory", Cpus, Mem))
	Ztext = append(Ztext, fmt.Sprintf("Kernel: %v", Kernel))
	Ztext = append(Ztext, fmt.Sprintf("Interfaces: %v", Interfaces))
	text = strings.Join(Ztext, "\n")

	currentTime := strconv.Itoa(int(time.Now().Unix()))
	ArticaNotifsMaxTime := sockets.GET_INFO_INT("ArticaNotifsMaxTime")
	if ArticaNotifsMaxTime == 0 {
		ArticaNotifsMaxTime = 7
	}
	removeafter := CurDateAddDay(int(ArticaNotifsMaxTime))

	_, err = db.Exec(`INSERT OR IGNORE INTO squid_admin_mysql
	(zDate,content,subject,function,filename,line,severity,removeafter) VALUES (?,?,?,?,?,?,?,?)`, currentTime, text, subject, function, function, line, severity, removeafter)

	if err != nil {
		squidAdminMysqlQueue(severity, subject, text, function, line)
		return false
	}
	if severity == 0 || severity == 1 {
		_, _ = httpclient.RestAPIUnixGet("/system/notifications/send")
	}

	return true
}
func SQLiteConnectNotifs() (error, *sql.DB) {
	dbpath := "/home/artica/SQLITE/system_events.db"
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return err, nil
	}
	return nil, db

}
func CurDateAddDay(daysToAdd int) string {
	currentTime := time.Now()
	if daysToAdd == 0 {
		daysToAdd = 5
	}
	newTime := currentTime.AddDate(0, 0, daysToAdd)
	return newTime.Format("2006-01-02 15:04:05")
}
func BuildProgress(prc int, text string, fname string) bool {
	futils.CreateDir(ProgressDir)
	var Files []string
	if strings.Contains(fname, ",") {
		Files = strings.Split(fname, ",")
	} else {
		Files = append(Files, fname)
	}
	for _, BaseName := range Files {
		array := make(map[string]string)
		array["POURC"] = fmt.Sprintf("%d", prc)
		array["TEXT"] = text
		Path := fmt.Sprintf("%v/%v", ProgressDir, BaseName)
		serialized, _ := gophp.Serialize(array)
		serializedText := fmt.Sprintf("%s", serialized)
		err := futils.FilePutContents(Path, serializedText)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		futils.Chmod(Path, 0644)
		futils.ChownFile(Path, "www-data", "www-data")
	}
	return true
}
func Journal(text string, function string, SYSLOG_IDENTIFIER string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	if !journal.Enabled() {
		log.Printf("%v  %v\n", function, text)
		return
	}
	err := journal.Send(
		fmt.Sprintf("[%v] %v", function, text),
		journal.PriInfo,
		map[string]string{
			"SYSLOG_IDENTIFIER": SYSLOG_IDENTIFIER,
		},
	)
	if err != nil {
		log.Printf("%v  %v\n", function, text)
		return
	}
}

func BuildLog(text string, fname string) bool {
	futils.CreateDir(ProgressDir)
	Path := fmt.Sprintf("%v/%v", ProgressDir, fname)
	_ = futils.FilePutContents(Path, text)
	futils.Chmod(Path, 0644)
	futils.ChownFile(Path, "www-data", "www-data")
	return true
}
func PHPLog(message string) {
	// Open the log file for appending, create if it doesn't exist
	file, err := os.OpenFile("/usr/share/artica-postfix/ressources/logs/php.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	currentTime := time.Now()
	location := currentTime.Location()

	logEntry := fmt.Sprintf("[%s %s] [%d] [ARTICAREST] %v\n", currentTime.Format("02-Jan-2006 15:04:05"), location, os.Getpid(), message)
	if _, err := file.WriteString(logEntry); err != nil {
		log.Error().Msgf("failed to write to log file: %v", err)
	}
}

func BuildLogFile(fname string, content string) {
	futils.CreateDir(ProgressDir)
	Path := fmt.Sprintf("%v/%v", ProgressDir, fname)
	_ = futils.FilePutContents(Path, content)
	futils.Chmod(Path, 0644)
	futils.ChownFile(Path, "www-data", "www-data")
}

func squidAdminMysqlQueue(severity int, subject string, text string, function string, line int) bool {
	maindir := "/var/log/artica-postfix/squid_admin_mysql"

	strSeverity := strconv.Itoa(severity)
	strLine := strconv.Itoa(line)
	if _, err := os.Stat(maindir); os.IsNotExist(err) {
		return false
	}
	array := make(map[string]string)
	objTime := time.Now()
	array["zdate"] = objTime.Format("2006-01-02 15:04:05")
	array["subject"] = subject
	array["text"] = text
	array["severity"] = strSeverity
	array["function"] = function
	array["file"] = "articarest"
	array["line"] = strLine
	array["pid"] = "0"
	array["TASKID"] = "0"
	serialized, _ := gophp.Serialize(array)
	serializedText := fmt.Sprintf("%s", serialized)
	smd5 := Md5(serializedText)
	tfile := fmt.Sprintf("%s/%s.log", maindir, smd5)
	f, err := os.Create(tfile)
	if err != nil {
		log.Err(err).Msg("Error creating file:" + tfile)
		return false
	}
	_, err2 := f.WriteString(serializedText)

	if err2 != nil {
		log.Err(err).Msg("Error creating file:" + tfile)
		return false
	}
	return true
}
func Md5(str string) string {
	h := md5.New()
	_, _ = io.WriteString(h, str)
	return fmt.Sprintf("%x", h.Sum(nil))
}
func ClusterEvents(prio int, subject string, content string, line int) {
	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)

	if ok {
		file := futils.Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s[%v:%d]: ", file, fn.Name(), line)
	}
	log.Debug().Msg(fmt.Sprintf("%v %v", subject, content))
	HaClusterClient := sockets.GET_INFO_INT("HaClusterClient")
	PowerDNSEnableClusterSlave := sockets.GET_INFO_INT("PowerDNSEnableClusterSlave")
	sPrio := make(map[int]string)
	sPrio[0] = "[ERROR]"
	sPrio[1] = "[WARNING]"
	sPrio[2] = "[INFO]"

	if PowerDNSEnableClusterSlave == 1 {
		TosyslogGen(fmt.Sprintf("%v %v %v %v", TheCall, sPrio[prio], subject, content), "cluster-client")
	}

	if HaClusterClient == 1 {
		TosyslogGen(fmt.Sprintf("prio:%d %v %v", prio, subject, content), "hacluster-client")
		return
	}

	db, err := SqliteConns.ClusterEventsConnectRW()
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v Failed to connect DB %v", futils.GetCalleRuntime(), err.Error()))
		TosyslogGen(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), "Failed to connect DB"), "hacluster-client")
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	if prio == 2 {
		log.Info().Msg(subject)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS events ( ID INTEGER PRIMARY KEY AUTOINCREMENT,prio INTEGER NOT NULL DEFAULT 2, zdate INTEGER OT NULL DEFAULT 0, sent INTEGER NOT NULL DEFAULT 0, subject TEXT NOT NULL DEFAULT '', content TEXT NOT NULL DEFAULT '', info TEXT NOT NULL DEFAULT '')`)
	xtime := futils.TimeStampToString()
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}

	info := TheCall
	_, err = db.Exec(`INSERT INTO events (zdate,prio,sent,subject,content,info) VALUES(?,?,0,?,?,?)`, xtime, prio, subject, content, info)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), err.Error()))
	}
}
func CreateCpuMemReport() string {
	ps := futils.FindProgram("ps")
	sort := futils.FindProgram("sort")
	head := futils.FindProgram("head")
	topBin := futils.FindProgram("top")
	iotop := futils.FindProgram("iotop")
	TempDir := futils.TempFileName()
	futils.CreateDir(TempDir)

	Command := fmt.Sprintf("%s --no-heading -eo user,pid,pcpu,args | %s -grbk 3 | %s -50 >%v/topCPU.txt", ps, sort, head, TempDir)
	_, _ = futils.ExecuteShell(Command)

	Command = fmt.Sprintf("%s --no-heading -eo user,pid,pmem,args | %s -grbk 3 | %s -50 >%v/topMem.txt", ps, sort, head, TempDir)
	_, _ = futils.ExecuteShell(Command)

	Command = strings.Join([]string{ps, "auxww", ">" + TempDir + "/allprocesses.txt"}, " ")
	_, _ = futils.ExecuteShell(Command)
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -b -n 1 >%v/top.log", topBin, TempDir))
	if futils.FileExists(iotop) {
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v -o -a -b -q -t -n 20 >%v/iotop.log", iotop, TempDir))
	} else {
		_ = futils.FilePutContents(TempDir+"/iotop.not.found.txt", "Cannot export this metric")
	}
	_ = futils.CopyFile("/var/log/articarest.log", TempDir+"/articarest.log")

	return TempDir
}

func SaveIncident(subject string, directory string) bool {

	if minutesSinceBoot() < 3 {
		_ = futils.RmRF(directory)
		return true
	}

	db, err := SqliteConns.IncidentsConnectRW()
	if err != nil {
		log.Error().Msgf("%v failed to open database: %v", futils.GetCalleRuntime(), err)
		return false
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	createTableSQL := `CREATE TABLE IF NOT EXISTS perfs_queue (zDate INTEGER NOT NULL PRIMARY KEY,subject TEXT NOT NULL,file TEXT NOT NULL);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Error().Msgf("%v Failed to create table: %v", futils.GetCalleRuntime(), err)
		return false
	}
	tmpfilegz := futils.TempFileName() + ".tgz"

	var TheCall string
	created := time.Now().Format("2006-01-02 15:04:05")
	pc, file, line, ok := runtime.Caller(1)

	if ok {
		file := futils.Basename(file)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s[%v:%d]: ", file, fn.Name(), line)
	}
	_ = futils.FilePutContents(fmt.Sprintf("%v/WhyThisReport.txt", directory), subject+"\n"+TheCall+"\nDate:"+created)

	// Create tar.gz file
	err = compressor.CompressDirectoyStrip(directory, tmpfilegz, directory)
	if err != nil {
		log.Error().Msgf("%v Failed to create tar.gz: %v", futils.GetCalleRuntime(), err)
		return false
	}

	data, err := os.ReadFile(tmpfilegz)
	if err != nil {
		log.Error().Msgf("%v Failed to read tmpfilegz: %v", futils.GetCalleRuntime(), err)
		return false
	}

	encodedData := futils.Base64Encode(string(data))

	_ = futils.RmRF(directory)
	sourceTime := time.Now().Unix()
	futils.DeleteFile(tmpfilegz)
	insertSQL := `INSERT OR IGNORE INTO perfs_queue (zDate, subject, file) VALUES (?, ?, ?);`
	_, err = db.Exec(insertSQL, sourceTime, subject, encodedData)
	if err != nil {
		log.Error().Msgf("%v Failed to insert into table: %v", futils.GetCalleRuntime(), err)
		return false
	}

	return true
}

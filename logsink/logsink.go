package logsink

import (
	"CacheMem"
	"GlobalsValues"
	"articaunix"
	"crypto/md5"
	"csqlite"
	"database/sql"
	"errors"
	"fmt"
	"futils"
	"io"
	"log/syslog"
	"notifs"
	"regexp"
	"runtime"
	"sockets"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

var RestartMux sync.Mutex
var logsinkPatternError = regexp.MustCompile(`error during parsing file \/etc\/rsyslog.d\/(.+?),`)
var logsinkPattern1 = regexp.MustCompile(`rsyslogd\s+([0-9.]+)`)

const RestartLock = "/etc/artica-postfix/logsink.restart.lock"
const ServiceName = "Syslog service"
const SyslogConf = "/etc/rsyslog.d/rsylogd.conf"
const ArticaBinary = GlobalsValues.ArticaBinary
const InitdPath = "/etc/init.d/rsyslog"
const MonitFile = "/etc/monit/conf.d/APP_RSYSLOG.monitrc"
const PidPath = "/run/rsyslogd.pid"
const LastStop = "/etc/artica-postfix/STOPPED_APP_RSYSLOG"
const SystemdTargets = "/etc/systemd/system/multi-user.target.wants/rsyslog.service,/usr/lib/systemd/system/rsyslog.service,/var/lib/systemd/deb-systemd-helper-enabled/rsyslog.service.dsh-also,/var/lib/systemd/deb-systemd-helper-enabled/multi-user.target.wants/rsyslog.service,/etc/systemd/system/multi-user.target.wants/rsyslog.service,/usr/lib/systemd/system/rsyslog.service"
const ProgressF = "syslog.restart.progress"

type RemoteSyslogConf struct {
	ssl         int
	ID          int
	server      string
	proto       string
	port        int
	myhostname  string
	queueSize   int
	queueSizeMb int
	logtype     string
}
type LocalFileConf struct {
	DirCreateMode  string
	FileCreateMode string
	File           string
	Template       string
	IoBufferSize   int
	FlushOnTXEnd   bool
	AsyncWriting   bool
}

func BuildLocalFileSimple(Target string) string {
	conf := LocalFileConf{File: Target, AsyncWriting: true}
	return BuildLocalFilelog(conf)
}
func BuildToArticaRest(FamilyName string) string {
	var BackStatsCom []string
	BackStatsCom = append(BackStatsCom, fmt.Sprintf("\taction(name=\"%v\" type=\"omfwd\" queue.type=\"direct\"", FamilyName))
	BackStatsCom = append(BackStatsCom, "action.resumeRetryCount=\"-1\"")
	BackStatsCom = append(BackStatsCom, "action.reportSuspension=\"on\"")
	BackStatsCom = append(BackStatsCom, "target=\"127.0.0.1\" port=\"5516\" protocol=\"udp\")")
	return strings.Join(BackStatsCom, " ")
}
func Install() {
	Config := ServiceConfig()
	articaunix.EnableService(Config)
	BuildSystemd()
	buildSyslog()
}
func BuildLocalFilelog(Conf LocalFileConf) string {
	if len(Conf.DirCreateMode) == 0 {
		Conf.DirCreateMode = "0700"
	}
	if len(Conf.FileCreateMode) == 0 {
		Conf.FileCreateMode = "0700"
	}
	if Conf.IoBufferSize == 0 {
		Conf.IoBufferSize = 128
	}
	var f []string
	f = append(f, "\taction(type=\"omfile\"")
	f = append(f, fmt.Sprintf("dirCreateMode=\"%v\"", Conf.DirCreateMode))
	f = append(f, fmt.Sprintf("FileCreateMode=\"%v\"", Conf.FileCreateMode))
	f = append(f, fmt.Sprintf("File=\"%v\"", Conf.File))
	f = append(f, fmt.Sprintf("ioBufferSize=\"%vk\"", Conf.IoBufferSize))
	if len(Conf.Template) > 3 {
		f = append(f, fmt.Sprintf("template=\"%v\"", Conf.Template))
	}

	if Conf.FlushOnTXEnd {
		f = append(f, fmt.Sprintf("flushOnTXEnd=\"%v\"", "on"))
	} else {
		f = append(f, fmt.Sprintf("flushOnTXEnd=\"%v\"", "off"))
	}
	if Conf.AsyncWriting {
		f = append(f, fmt.Sprintf("asyncWriting=\"%v\"", "on"))
	} else {
		f = append(f, fmt.Sprintf("asyncWriting=\"%v\"", "off"))
	}

	f = append(f, fmt.Sprintf("queue.type=\"LinkedList\""))
	f = append(f, QueuesConfig())
	f = append(f, ")")
	return strings.Join(f, " ")
}

func ReconfigureSyslog() {
	_ = futils.CopyFile("/etc/rsyslog.conf", "/etc/rsyslog.back")
	notifs.BuildProgress(20, "{reconfiguring}", ProgressF)
	BuildRsyslogConf()
	notifs.BuildProgress(50, "{reconfiguring}", ProgressF)
	log.Warn().Msgf("%v Reconfiguring rsyslog service...", futils.GetCalleRuntime())
	err := CheckConfig()
	if err != nil {
		log.Error().Msgf("%v --> FAILED AFTER CheckConfig()", futils.GetCalleRuntime())
		_ = futils.CopyFile("/etc/rsyslog.conf", "/etc/rsyslog.err")
		_ = futils.CopyFile("/etc/rsyslog.back", "/etc/rsyslog.conf")
		notifs.BuildProgress(110, "{reconfiguring} {failed}", ProgressF)
		notifs.BuildLogFile("syslog.restart.log", err.Error())
		return
	}
	notifs.BuildProgress(70, "{reconfiguring} {stopping}", ProgressF)
	if !Stop() {
		notifs.BuildProgress(110, "{reconfiguring} {stopping} {failed}", ProgressF)
		log.Error().Msgf("%v Error stopping rsyslog service", futils.GetCalleRuntime())
	}
	notifs.BuildProgress(70, "{reconfiguring} {starting}", ProgressF)
	err = Start()
	if err != nil {
		notifs.BuildProgress(110, err.Error(), ProgressF)
		return
	}
	notifs.BuildProgress(100, "{success}", ProgressF)
}
func logSinkSchedules() {
	EnableSyslogLogSink := sockets.GET_INFO_INT("EnableSyslogLogSink")
	LogSynBackupEnable := sockets.GET_INFO_INT("LogSynBackupEnable")
	if EnableSyslogLogSink == 0 {
		LogSynBackupEnable = 0
	}
	cronFile := "/etc/cron.d/logsink-backup"

	if LogSynBackupEnable == 0 {
		if futils.FileExists(cronFile) {
			futils.DeleteFile(cronFile)
			go func() {
				err, _ := futils.ExecuteShell("/etc/init.d/cron restart")
				if err != nil {

				}
			}()
		}
		return
	}

	schedules := make(map[int64]string)
	schedules[1] = "0 */1 * * *"
	schedules[2] = "0 */2 * * *"
	schedules[4] = "0 */4 * * *"
	schedules[8] = "0 */8 * * *"
	schedules[9] = "1 0 * * *"
	schedules[24] = "0 1 * * *"
	schedules[25] = "0 2 * * *"
	schedules[26] = "0 3 * * *"
	schedules[27] = "0 4 * * *"
	LogSynBackupSchedule := sockets.GET_INFO_INT("LogSynBackupSchedule")
	futils.PopuplateCronMake("logsink-backup", schedules[LogSynBackupSchedule], "exec.backup.logsink.php")
}
func Stop() bool {
	duration := 1 * time.Second
	var conf articaunix.ServiceStartStopOptions
	conf.ServiceName = "Rsyslog Daemon"
	conf.MonitName = "APP_SYSLOG"
	MonitSyslog("Order to Stop service")
	pid := GetPid()

	if conf.Out {
		fmt.Println(fmt.Sprintf("%v Checking PID %v...", conf.ServiceName, pid))
	}
	if !futils.ProcessExists(pid) {
		MonitSyslog("Stopping service, Already stopped")
		if conf.Out {
			fmt.Println(fmt.Sprintf("%v Already stopped", conf.ServiceName))
		}
		articaunix.MonitSyslog("Stopping", true, conf)
		return true
	}
	MonitSyslog("Stopping service")

	if conf.Out {
		fmt.Println(fmt.Sprintf("%v killing PID %v...", conf.ServiceName, pid))
	}

	futils.StopProcess(pid)

	pid = GetPid()
	if !futils.ProcessExists(pid) {
		if conf.Out {
			fmt.Println(fmt.Sprintf("%v Stopped [Success]", conf.ServiceName))
		}

		articaunix.MonitSyslog("Stopping", true, conf)
		_ = futils.FilePutContents(LastStop, futils.TimeStampToString())
		return true
	}

	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetPid()
		if !futils.ProcessExists(pid) {
			articaunix.MonitSyslog("Stopping after SIGTERM", true, conf)
			return true
		}
		futils.StopProcess(pid)
	}

	pid = GetPid()
	if futils.ProcessExists(pid) {
		articaunix.MonitSyslog(fmt.Sprintf("Stopping %d using SIGKILL", pid), false, conf)
		futils.KillProcess(pid)
	}

	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid = GetPid()
		if !futils.ProcessExists(pid) {
			articaunix.MonitSyslog("Stopping after SIGKILL", true, conf)
			_ = futils.FilePutContents(LastStop, futils.TimeStampToString())
			return true
		}
		if pid > 0 {
			futils.KillProcess(pid)
		}
	}
	pid = GetPid()
	if !futils.ProcessExists(pid) {
		articaunix.MonitSyslog("Stopping", true, conf)
		_ = futils.FilePutContents(LastStop, futils.TimeStampToString())
		return true
	}
	articaunix.MonitSyslog("Stopping", false, conf)
	return false
}
func GetPid() int {

	pid := futils.GetPIDFromFile(PidPath)
	if futils.ProcessExists(pid) {
		return pid
	}
	return futils.PIDOFPattern("rsyslogd -n -i")
}
func CreateMonitService() {
	var f []string
	f = append(f, fmt.Sprintf("check process APP_RSYSLOG with pidfile %v", PidPath))
	f = append(f, fmt.Sprintf("\tstart program = \"%v -start-syslog\"", ArticaBinary))
	f = append(f, fmt.Sprintf("\tstop program = \"%v -stop-syslog\"", ArticaBinary))
	f = append(f, "")
	md51 := futils.MD5File(MonitFile)
	_ = futils.FilePutContents(MonitFile, strings.Join(f, "\n"))
	md52 := futils.MD5File(MonitFile)
	if md51 == md52 {
		return
	}
	// Import cycle not allowed
}
func Start() error {
	rsyslogd := futils.FindProgram("rsyslogd")
	cmd := fmt.Sprintf("%v -n -i /run/rsyslogd.pid", rsyslogd)
	duration := 1 * time.Second
	pid := GetPid()

	var conf articaunix.ServiceStartStopOptions
	conf.ServiceName = "Rsyslog Daemon"
	conf.MonitName = "APP_SYSLOG"
	futils.CreateDir("/var/spool/rsyslog")
	futils.CreateDir("/home/artica/syslog/spool/ArticaRestSSH")
	log.Warn().Msgf("%v Starting %v", futils.GetCalleRuntime(), ServiceName)
	if futils.ProcessExists(pid) {
		log.Debug().Msg(fmt.Sprintf("Starting %v Already executed pid [%v]...", conf.ServiceName, pid))
		articaunix.MonitSyslog("Already Executed", true, conf)
		return nil
	}
	out := ""

	if IsMovingDir() {
		MonitSyslog("logsink.IsMovingDir A Moved operation is currently in use.")
		return fmt.Errorf("logsink.IsMovingDir A Moved operation is currently in use")
	}
	log.Debug().Msg(fmt.Sprintf("Starting %v [%v]...", conf.ServiceName, cmd))
	articaunix.MonitSyslog(fmt.Sprintf("Starting %v", cmd), true, conf)
	BuildSystemd()
	logSinkSchedules()
	CreateMonitService()
	BuildRsyslogConf()

	if !futils.FileExists("/var/log/crowdsec-firewall-bouncer.log") {
		futils.TouchFile("/var/log/crowdsec-firewall-bouncer.log")
	}

	log.Debug().Msg(fmt.Sprintf("Starting %v Executing [%v]...", conf.ServiceName, cmd))
	notifs.TosyslogGen(fmt.Sprintf("%v Starting Syslog Daemon", futils.GetCalleRuntime()), "rsyslogd")

	err, out := futils.ExecuteDetach(cmd)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}

	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetPid()
		if futils.ProcessExists(pid) {
			if conf.Out {
				fmt.Println(fmt.Sprintf("Starting %v Success PID [%v]...", conf.ServiceName, pid))
			}
			articaunix.MonitSyslog("Starting", true, conf)
			log.Debug().Msg(fmt.Sprintf("Starting %v Success PID %v", conf.ServiceName, pid))
			return nil
		}
		log.Debug().Msg(fmt.Sprintf("Starting %v waiting %v/5", conf.ServiceName, i))
		if conf.Out {
			articaunix.MonitSyslog(fmt.Sprintf("Starting waiting %v/5", i), true, conf)
			fmt.Println(fmt.Sprintf("Starting %v Waiting %v/5...", conf.ServiceName, i))
		}
	}

	if conf.Out {
		log.Error().Msg(fmt.Sprintf("Starting %v Failed  %v", conf.ServiceName, out))
	}
	articaunix.MonitSyslog("Starting", false, conf)
	tmpstr := strings.Split(out, "\n")

	for _, line := range tmpstr {
		if conf.Out {
			fmt.Println(fmt.Sprintf("Starting %v [%v]", conf.ServiceName, line))
		}
		articaunix.MonitSyslog(line, false, conf)
	}
	notifs.SquidAdminMysql(0, fmt.Sprintf("{starting} {%v} {failed}", conf.MonitName), out, "logsink.start", 332)
	return errors.New(out)

}
func CheckConfig() error {

	rsyslogd := futils.FindProgram("rsyslogd")
	cmd := fmt.Sprintf("%v -f /etc/rsyslog.conf -N1", rsyslogd)
	err, res := futils.ExecuteShell(cmd)
	if err != nil {

		if strings.Contains(res, "larger than queue.size") {
			return nil
		}

		text := fmt.Sprintf("%v Reconfiguring rsyslog return false %v", futils.GetCalleRuntime(), err.Error())
		Syslog(text)
		log.Error().Msg(text)
		tb := strings.Split(res, "\n")
		for _, line := range tb {
			BadFile := futils.RegexGroup1(logsinkPatternError, line)
			if len(BadFile) > 3 {
				futils.DeleteFile(fmt.Sprintf("%v/%v", "/etc/rsyslog.d", BadFile))
				Syslog(fmt.Sprintf("%v Error, removing bad config file %v", futils.GetCalleRuntime(), BadFile))
				log.Warn().Msgf("%v Remove %v", futils.GetCalleRuntime(), BadFile)
				return CheckConfig()
			}

			log.Error().Msgf("%v [%v]", futils.GetCalleRuntime(), line)
			Syslog(line)
		}

		return fmt.Errorf("%v\n%v", err.Error(), res)
	}
	return nil
}
func Syslog(text string) {
	w, err := syslog.New(syslog.LOG_INFO, "rsyslog")
	if err != nil {
		return
	}

	defer func() {
		closeErr := w.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	_ = w.Info(text)
	_ = w.Close()

}
func createConfigCache() map[string]string {
	zm5 := make(map[string]string)
	zm5["/etc/rsyslog.conf"] = futils.MD5File("/etc/rsyslog.conf")
	files := futils.DirectoryScan("/etc/rsyslog.d")
	for _, file := range files {
		fpath := fmt.Sprintf("/etc/rsyslog.d/%v", file)
		zm5[fpath] = futils.MD5File(fpath)
	}
	return zm5
}
func checkIfConfigChanged() bool {

	Old := futils.GobFileGet("/etc/artica-postfix/Syslog.md5")
	newconf := createConfigCache()
	for path, md51 := range newconf {
		if Old[path] == md51 {
			log.Debug().Msgf("%v %v %v SKIP", futils.GetCalleRuntime(), path, md51)
			continue
		}
		log.Warn().Msgf("%v %v [changed/added]", futils.GetCalleRuntime(), path)
		futils.GobFileSave("/etc/artica-postfix/Syslog.md5", newconf)
		return true
	}
	for path, _ := range Old {
		if !futils.FileExists(path) {
			log.Warn().Msgf("%v %v [deleted]", futils.GetCalleRuntime(), path)
			futils.GobFileSave("/etc/artica-postfix/Syslog.md5", newconf)
			return true
		}
		log.Debug().Msgf("%v %v %v SKIP", futils.GetCalleRuntime(), path, "Exists")
	}

	return false
}
func QueuesConfig() string {

	return `queue.size="10000" queue.discardMark="9000" queue.highWaterMark="8000" queue.lowWaterMark="2000"`
}

func Restart() {
	RestartMux.Lock()
	defer RestartMux.Unlock()

	if futils.FileExists(RestartLock) {
		Min := futils.FileTimeMin(RestartLock)
		if Min < 5 {
			return
		}
	}
	futils.TouchFile(RestartLock)
	defer futils.DeleteFile(RestartLock)
	var TheCall string
	pc, file, line, ok := runtime.Caller(1)

	if ok {
		file := futils.Basename(file)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s[%v:%d]: ", file, fn.Name(), line)
	}

	log.Warn().Msgf("%v Restarting by [%v]", futils.GetCalleRuntime(), TheCall)

	Who := futils.GetCalleRuntimeAll() + "\nCaller:" + TheCall
	pid := GetPid()

	if !futils.ProcessExists(pid) {
		_ = Start()
		return
	}
	if !checkIfConfigChanged() {
		log.Debug().Msgf("%v config unchanged!", futils.GetCalleRuntime())
		return
	}

	PidTime := futils.GetProcessTimeMin(pid)

	MonitSyslog("Restarting")
	notifs.TosyslogGen(fmt.Sprintf("%v Restarting Syslog Daemon (running since %dmn)", futils.GetCalleRuntime(), PidTime), "rsyslogd")
	notifs.SquidAdminMysql(1, "Restarting Syslog Daemon service", Who, futils.GetCalleRuntime(), 387)
	log.Warn().Msgf("%v Restarting syslog daemon...", futils.GetCalleRuntime())
	if !Stop() {
		log.Warn().Msgf("%v Unable to stop syslog daemon...", futils.GetCalleRuntime())
		return
	}
	log.Warn().Msgf("%v Starting syslog daemon...", futils.GetCalleRuntime())
	err := Start()
	if err != nil {
		notifs.SquidAdminMysql(0, fmt.Sprintf("[{restart}]: Unable to start Syslog service with error %v", err.Error()), Who, futils.GetCalleRuntime(), 255)
	}
	log.Debug().Msgf("%v Starting syslog daemon done...", futils.GetCalleRuntime())
	go sleepAndTest()
}
func sleepAndTest() {
	duration := 2 * time.Second
	rsyslogd := futils.FindProgram("rsyslogd")
	cmd := fmt.Sprintf("%v -n -i /run/rsyslogd.pid", rsyslogd)
	err, _ := futils.ExecuteDetach(cmd)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}

	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetPid()
		if futils.ProcessExists(pid) {
			continue
		}

	}
}
func zmd5(str string) string {
	h := md5.New()
	_, _ = io.WriteString(h, str)
	return fmt.Sprintf("%x", h.Sum(nil))
}
func IsArticaConf() bool {
	tp := strings.Split(futils.FileGetContents("/etc/rsyslog.conf"), "\n")
	for _, line := range tp {
		if strings.Contains(line, "Written by Artica") {
			return true
		}
	}
	return false
}
func isArticaService() bool {
	tp := strings.Split(futils.FileGetContents("/etc/init.d/rsyslog"), "\n")
	for _, line := range tp {
		if strings.Contains(line, "Modified by: Artica") {
			return true
		}
	}
	return false
}
func GetVersion() string {
	DestBin := articaunix.FindProgram("rsyslogd")
	if !futils.FileExists(DestBin) {
		return "0.0.0"
	}

	val := CacheMem.GetStringFunc()
	if len(val) > 1 {
		return val
	}

	BinaryMD5 := sockets.GET_INFO_STR("RsyslogBinMD5")
	log.Debug().Msg(fmt.Sprintf("%v: RsyslogBinMD5: %v", futils.GetCalleRuntime(), BinaryMD5))
	CurrMD5 := futils.MD5File(DestBin)
	log.Debug().Msg(fmt.Sprintf("%v: CurrMD5: %v", futils.GetCalleRuntime(), CurrMD5))
	Version := sockets.GET_INFO_STR("APP_SYSLOGD_VERSION")
	log.Debug().Msg(fmt.Sprintf("%v: Cached Version: %v", futils.GetCalleRuntime(), Version))

	if BinaryMD5 == CurrMD5 {
		log.Debug().Msg(fmt.Sprintf("%v: Return Cached Version: %v", futils.GetCalleRuntime(), Version))
		if len(Version) > 2 {
			return Version
		}
	}

	_, content := futils.ExecuteShell(fmt.Sprintf("%v -v", DestBin))
	tb := strings.Split(content, "\n")

	for _, line := range tb {
		version := futils.RegexGroup1(logsinkPattern1, line)
		if len(version) > 2 {
			log.Debug().Msg(fmt.Sprintf("Found in [%v] --> %v", line, version))
			sockets.SET_INFO_STR("APP_SYSLOGD_VERSION", version)
			sockets.SET_INFO_STR("RsyslogBinMD5", CurrMD5)
			CacheMem.SetStringFunc(version)
			return version
		}
		log.Debug().Msgf("%v NOT Found in [%v] version=%s", futils.GetCalleRuntime(), line, version)
	}

	log.Debug().Msg(fmt.Sprintf("%v: Failed in [%v]", futils.GetCalleRuntime(), content))
	return "0.0.0"
}
func Status(Watchdog bool) string {

	if Watchdog {
		GetVersion()
		if !futils.FileExists("/etc/cron.d/syslog-task") {
			_, _ = futils.ExecutePHP("exec.syslog-engine.php --task")
		}

		if !IsArticaConf() {
			if BuildRsyslogConf() {
				Install()
				Restart()
			}
		}
		if !isArticaService() {
			Install()
		}
		if !futils.FileExists(SyslogConf) {
			buildSyslog()
		}

	}

	var ini articaunix.StatusIni
	var f []string
	opts := ServiceConfig()

	ini.ProductCodeName = opts.MonitName
	ini.Installed = 1
	ini.Pidpath = opts.Pidfile
	ini.MemoryBin = opts.SourceBin
	ini.AlwaysON = true
	ini.WatchdogMode = Watchdog
	ini.Debug = false
	ini.CheckSockets = opts.CheckSocket
	ini.StartCmdLine = opts.ExecStart
	ini.InitdPath = InitdPath
	ini.LastStop = LastStop
	f = append(f, articaunix.BuildIni(ini))
	return strings.Join(f, "\n")
}
func ServiceConfig() articaunix.ServiceOptions {
	var opts articaunix.ServiceOptions
	opts.DisableMonitConfig = true
	DestBin := articaunix.FindProgram("rsyslogd")
	opts.SourceBin = DestBin
	opts.CheckSocket = ""
	opts.ForcePidFile = false
	opts.ExecStart = fmt.Sprintf("%v -start-syslog", ArticaBinary)
	opts.ExecStop = fmt.Sprintf("%v -stop-syslog", ArticaBinary)
	opts.ExecReload = ""
	opts.InitdPath = InitdPath
	opts.Pidfile = PidPath
	opts.ServiceName = "Rsyslog Service"
	opts.ProcessPattern = DestBin
	opts.ProcessNoWait = true
	opts.TokenEnabled = ""
	opts.StartCmdLine = opts.ExecStart
	opts.SyslogConfPath = ""
	opts.MonitName = "APP_RSYSLOG"
	return opts
}
func BuildSystemd() {
	if futils.IsDirDirectory("/etc/systemd/system") {
		return
	}
	var f []string
	f = append(f, "[Unit]")
	f = append(f, fmt.Sprintf("After=network.target"))
	f = append(f, fmt.Sprintf(""))
	f = append(f, fmt.Sprintf("[Service]"))
	f = append(f, fmt.Sprintf("ExecStart=%v -start-syslog", ArticaBinary))
	f = append(f, fmt.Sprintf("\tExecStop=%v -stop-syslog", ArticaBinary))
	f = append(f, fmt.Sprintf("Restart=no"))
	f = append(f, fmt.Sprintf("Type=notify"))
	f = append(f, fmt.Sprintf(""))
	f = append(f, fmt.Sprintf("[Install]"))
	f = append(f, fmt.Sprintf("WantedBy=multi-user.target"))
	f = append(f, fmt.Sprintf("Alias=rsyslog.service"))
	f = append(f, fmt.Sprintf(""))
	SystemdContent := strings.Join(f, "\n")
	Targets := strings.Split(SystemdTargets, ",")
	for _, sPath := range Targets {
		_ = futils.FilePutContents(sPath, SystemdContent)
	}

}
func ConnectDB() (error, *sql.DB) {
	dbpath := "/home/artica/SQLITE/syslogrules.db"
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return err, nil
	}
	return nil, db
}
func PatchTables() {
	err, db := ConnectDB()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	csqlite.ConfigureDBPool(db)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS rules (ID INTEGER PRIMARY KEY AUTOINCREMENT,server TEXT NOT NULL,port INTEGER NOT NULL DEFAULT 514,proto TEXT NOT NULL DEFAULT 'udp',logtype TEXT NOT NULL DEFAULT 'proxy',myhostname TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1,INTEGER NOT NULL DEFAULT 0 )`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	csqlite.FieldExistCreateTEXT(db, "rules", "certificate")
	csqlite.FieldExistCreateTEXT(db, "rules", "public_key")
	csqlite.FieldExistCreateTEXT(db, "rules", "pkcs12")
	csqlite.FieldExistCreateTEXT(db, "rules", "ca_key")
	csqlite.FieldExistCreateTEXT(db, "rules", "myhostname")

}
func WizardRsyslog() {
	Rserv := futils.FileGetContents("/etc/artica-postfix/WIZARDRSYSLOGSRV")
	RPort := int64(futils.StrToInt(futils.FileGetContents("/etc/artica-postfix/WIZARDRSYSLOGPORT")))
	rproto := strings.ToLower(futils.Trim(futils.FileGetContents("/etc/artica-postfix/WIZARDRSYSLOGPROTO")))
	LogSinkClientTCP := int64(0)
	if rproto == "tcp" {
		LogSinkClientTCP = 1
	}
	if RPort == 0 {
		RPort = 514
	}
	log.Info().Msgf("%v %v:%d %v", futils.GetCalleRuntime(), rproto, RPort, LogSinkClientTCP)

	if len(Rserv) < 3 {
		futils.DeleteFile("/etc/artica-postfix/WIZARDRSYSLOGSRV")
		futils.DeleteFile("/etc/artica-postfix/WIZARDRSYSLOGPORT")
		futils.DeleteFile("/etc/artica-postfix/WIZARDRSYSLOGPROTO")
		sockets.SET_INFO_INT("LogSinkClient", 0)
		return
	}
	sockets.SET_INFO_INT("LogSinkClient", 1)
	sockets.SET_INFO_STR("LogSinClientServer", Rserv)
	sockets.SET_INFO_INT("LogSinkClientTCP", LogSinkClientTCP)
	sockets.SET_INFO_INT("LogSinkClientPort", RPort)

	futils.DeleteFile("/etc/artica-postfix/WIZARDRSYSLOGSRV")
	futils.DeleteFile("/etc/artica-postfix/WIZARDRSYSLOGPORT")
	futils.DeleteFile("/etc/artica-postfix/WIZARDRSYSLOGPROTO")
}
func BuildRemoteSyslogs(logtype string, uniqKey string) string {
	if len(logtype) == 0 {
		logtype = "squid"
	}
	if len(uniqKey) == 0 {
		uniqKey = zmd5(futils.TimeStampToString())
	}

	var f []string

	if logtype == "all" {
		LogSinkClient := sockets.GET_INFO_INT("LogSinkClient")
		if LogSinkClient == 1 {
			f = append(f, fmt.Sprintf("#\tLogSinkClient ACTIVE %v", futils.GetCalleRuntime()))
			var sConf RemoteSyslogConf
			sConf.ID = 0
			sConf.ssl = 0
			sConf.proto = "udp"
			sConf.port = int(sockets.GET_INFO_INT("LogSinkClientPort"))
			sConf.server = sockets.GET_INFO_STR("LogSinClientServer")
			LogSinkClientTCP := sockets.GET_INFO_INT("LogSinkClientTCP")
			if LogSinkClientTCP == 1 {
				sConf.proto = "tcp"
			}
			sConf.queueSize = int(sockets.GET_INFO_INT("LogSinkClientQueue"))
			sConf.queueSizeMb = int(sockets.GET_INFO_INT("LogSinkClientQueueSize"))
			f = append(f, buildRemote(sConf))
		}
	}

	futils.CreateDir("/home/artica/SQLITE")
	err, db := ConnectDB()
	if err != nil {
		log.Error().Msg(fmt.Sprintf("BuildRemoteSyslogs() %v", err.Error()))
		return strings.Join(f, "\n")
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	csqlite.ConfigureDBPool(db)
	Query := `CREATE TABLE IF NOT EXISTS rules (
	ID INTEGER PRIMARY KEY AUTOINCREMENT,
	server TEXT NOT NULL,
	port INTEGER NOT NULL DEFAULT 514,
	proto TEXT NOT NULL DEFAULT 'udp',
	logtype TEXT NOT NULL DEFAULT 'proxy',
	myhostname TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1,
	queue_size INTEGER NOT NULL DEFAULT 0,
	queue_size_mb INTEGER NOT NULL DEFAULT 0,
	ssl     INTEGER NOT NULL DEFAULT 0 )`

	_, _ = db.Exec(Query)

	ok, err := csqlite.FieldExists(db, "rules", "myhostname")
	if !ok {
		_, _ = db.Exec("ALTER TABLE rules ADD myhostname TEXT NOT NULL DEFAULT ''")
	}
	ok, err = csqlite.FieldExists(db, "rules", "queue_size")
	if !ok {
		_, _ = db.Exec("ALTER TABLE rules ADD queue_size INTEGER NOT NULL DEFAULT 0")
	}
	ok, err = csqlite.FieldExists(db, "rules", "queue_size_mb")
	if !ok {
		_, _ = db.Exec("ALTER TABLE rules ADD queue_size_mb INTEGER NOT NULL DEFAULT 0")
	}

	rows, err := db.Query(`SELECT ID,ssl,server,proto,port,myhostname,queue_size,queue_size_mb FROM rules WHERE enabled=1 AND logtype=?`, logtype)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("BuildRemoteSyslogs:%v %v", Query, err.Error()))
		_ = db.Close()
		return strings.Join(f, "\n")
	}
	ALREADY := make(map[string]bool)
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	for rows.Next() {
		var server sql.NullString
		var myhostname sql.NullString
		var Conf RemoteSyslogConf

		err := rows.Scan(&Conf.ID, &Conf.ssl, &server, &Conf.proto, &Conf.port, &myhostname, &Conf.queueSize, &Conf.queueSizeMb)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%v %v ", futils.GetCalleRuntime(), err.Error()))
			_ = rows.Close()
			_ = db.Close()
			return strings.Join(f, "\n")

		}
		if len(server.String) == 0 {
			continue
		}

		Conf.myhostname = myhostname.String
		Conf.server = server.String
		Conf.logtype = logtype
		KeyID := zmd5(fmt.Sprintf("%v%v%v%v", Conf.server, Conf.proto, Conf.port, Conf.logtype))

		if _, ok := ALREADY[KeyID]; ok {
			continue
		}

		ALREADY[KeyID] = true
		f = append(f, buildRemote(Conf))

	}
	if len(f) == 0 {
		return ""
	}
	return strings.Join(f, "\n")

}
func buildRemote(Conf RemoteSyslogConf) string {
	// André Patch 28/08/2025
	templatename := ""
	if Conf.queueSize == 0 {
		Conf.queueSize = 10000
	}
	if Conf.queueSizeMb == 0 {
		Conf.queueSizeMb = 500
	}
	if len(Conf.myhostname) > 3 {
		templatename = fmt.Sprintf("omfwd-tpl-%d", Conf.ID)
	}
	if Conf.queueSize > 500000 {
		Conf.queueSize = 100000
	}

	omfwdTpl := ""
	rule := ""
	prefix := ""
	queuePath := fmt.Sprintf("/home/artica/syslog/spool/%d", Conf.ID)
	queueP := fmt.Sprintf("queue.spoolDirectory=\"%v\"", queuePath)
	futils.CreateDir(queuePath)
	if len(templatename) > 1 {
		rule = fmt.Sprintf("template(name=\"%v\" type=\"string\" string=\"<%%PRI%%>%%TIMESTAMP%% %v %%syslogtag:1:32%%%%msg:::sp-if-no-1st-sp%%%%msg%%\")", templatename, Conf.myhostname)
	}
	compiled := fmt.Sprintf("%v.%v.%v.%v.%v.%v.%v.%v", Conf.ID, Conf.ID, Conf.server, Conf.proto, Conf.port, Conf.logtype, Conf.myhostname, futils.TimeStampToString())
	queueFilename := fmt.Sprintf("%v-%v", Conf.ID, zmd5(compiled))
	optSsl := ""
	if Conf.logtype == "all" {
		prefix = "*.*"
	}
	if Conf.ssl == 1 {
		Conf.proto = "tcp"
		optSsl = "StreamDriver=\"ossl\" StreamDriverMode=\"1\" StreamDriverAuthMode=\"anon\" StreamDriver.PermitExpiredCerts=\"on\""
	}
	Queues := QueuesConfig()
	var f []string
	f = append(f, "# Patch")
	if len(prefix) > 1 {
		f = append(f, prefix)
	}
	f = append(f, fmt.Sprintf("\taction(name=\"rule-%d\"", Conf.ID))
	f = append(f, fmt.Sprintf("\ttype=\"omfwd\""))
	f = append(f, omfwdTpl)
	f = append(f, "\tqueue.type=\"linkedlist\"")
	f = append(f, fmt.Sprintf("\tqueue.filename=\"%v\"", queueFilename))
	f = append(f, "\t"+Queues)
	f = append(f, fmt.Sprintf("\tqueue.maxDiskSpace=\"%vM\"", Conf.queueSizeMb))
	f = append(f, "\taction.resumeRetryCount=\"-1\"")
	f = append(f, "\taction.reportSuspension=\"on\"")
	f = append(f, "\tqueue.saveOnShutdown=\"on\"")
	f = append(f, "\t"+queueP)
	f = append(f, fmt.Sprintf("\ttarget=\"%v\"", Conf.server))
	f = append(f, fmt.Sprintf("\tport=\"%d\"", Conf.port))
	f = append(f, fmt.Sprintf("\tprotocol=\"%v\"", Conf.proto))
	if len(optSsl) > 0 {
		f = append(f, "\t"+optSsl)
	}
	f = append(f, "\t)")

	RsysRule := strings.Join(f, "\n")
	return fmt.Sprintf("%v\n%v", rule, RsysRule)
}
func IsMovingDir() bool {

	EnableSyslogLogSink := sockets.GET_INFO_INT("EnableSyslogLogSink")
	if EnableSyslogLogSink == 0 {
		return false
	}
	LogSyncMoveDir := sockets.GET_INFO_STR("LogSyncMoveDir")

	if len(LogSyncMoveDir) > 3 {
		log.Error().Msg("logsink.IsMovingDir A Moved operation is currently in use....")
		go func() {
			err, out := futils.ExecutePHP("exec.backup.logsink.php --move-directory")
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), out)
			}
		}()
		return true
	}

	return false
}
func MonitSyslog(text string) {
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

	Msg := fmt.Sprintf("'%v' %v [articarest]", "APP_RSYSLOG", text)
	_ = w.Info(Msg)
	_ = w.Close()
}
func Reload() {
	pid := GetPid()
	if !futils.ProcessExists(pid) {
		_ = Start()
		return
	}
	PidTime := futils.GetProcessTimeMin(pid)
	notifs.TosyslogGen(fmt.Sprintf("%v Reloading Syslog Daemon (running since %dmn)", futils.GetCalleRuntime(), PidTime), "rsyslogd")
	futils.KillReloadProcess(pid)

}

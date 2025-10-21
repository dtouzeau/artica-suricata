package articaunix

import (
	"GlobalsValues"
	"articasys"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"futils"
	"io"
	"io/ioutil"
	"log/syslog"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sockets"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-ini/ini"
	"github.com/leeqvip/gophp"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/host"
)

const ArticaBinary = GlobalsValues.ArticaBinary

var mutexes = sync.Map{}
var DebugStatus bool

type MasterPID struct {
	RealPID int
	Event   []string
}

type StatusIni struct {
	ProductCodeName      string
	TokenEnabled         string
	AlwaysON             bool
	Pidpath              string
	MemoryBin            string
	MultipleProcess      bool
	StartCmdLine         string
	StopCmdLine          string
	UninstallCmdLine     string
	NoAutomaticUninstall bool
	InitdPath            string
	LastStop             string
	InstallCmdLine       string
	Enabled              int64
	CheckSockets         string
	Installed            int
	NONotifyFailed       bool
	SyslogName           string
	MasterMemory         int64
	ProcessesNumber      int
	WatchdogMode         bool
	UseThisPID           int
	NoWatchdogProcess    bool
	ForceEnabled         int
	Debug                bool
	CheckHTTPAddr        string
	ErrorText            string
	FinalMasterPid       int
}

func getInfoInt(Token string) int64 {

	tfile := fmt.Sprintf("/etc/artica-postfix/settings/Daemons/%s", Token)
	if !fileExists(tfile) {
		return 0
	}
	val := strings.TrimSpace(fileGetContents(tfile))
	if len(val) == 0 {
		return 0
	}
	if val == "!nil" {
		return 0
	}

	return StrToInt64(val)
}
func SQLiteConnectNotifs() (error, *sql.DB) {
	dbpath := "/home/artica/SQLITE/system_events.db"
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return err, nil
	}
	return nil, db

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
func squidAdminMysql(severity int, subject string, text string, function string, line int) bool {

	if severity == 0 {
		HaClusterClient := sockets.GET_INFO_INT("HaClusterClient")
		if HaClusterClient == 1 {
			tosyslogGen(fmt.Sprintf("[ERROR]: %v", subject), "hacluster-client")
		}
	}

	err, db := SQLiteConnectNotifs()
	if err != nil {
		squidAdminMysqlQueue(severity, subject, text, function, line)
		return false
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	if len(function) == 0 {
		function = getFunctionName()
	}

	Hostname, _ := os.Hostname()
	Cpus := articasys.CpuNumber()
	Mem := articasys.TotalMemorymb()
	Kernel := articasys.KernelVersion()
	Interfaces := articasys.InterfacesReport()
	CurtTime := futils.CurrentTimeStr()
	Uptime, _ := getUptimeReadable()
	text = fmt.Sprintf("%v\n-------------------------------------\n\nfunction:%v\nUptime:%v\nTime: %v\nServer: %v %d cpus %vMB of ram on Kernel:%v\n%v", function, Uptime, text, CurtTime, Hostname, Cpus, Mem, Kernel, Interfaces)

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
	return true
}
func getFunctionName() string {
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

func CheckInstalled(status StatusIni) {

	if !status.WatchdogMode {
		return
	}
	Enabled := getInfoInt(status.TokenEnabled)
	if status.ForceEnabled == 1 {
		Enabled = 1
	}
	log.Debug().Msgf("%v %v=%v", futils.GetCalleRuntime(), status.TokenEnabled, Enabled)
	if status.AlwaysON {
		Enabled = 1
	}

	if len(status.InitdPath) < 3 {
		return
	}
	if Enabled == 0 {

		if len(status.UninstallCmdLine) < 3 {
			return
		}

		if !status.NoAutomaticUninstall {
			return
		}
	}
	if Enabled == 0 {
		if !fileExists(status.InitdPath) {
			return
		}
	}

	if Enabled == 0 {
		if fileExists(status.InitdPath) {
			xlog := fmt.Sprintf("{%v}: Installed but not enabled {action}=[{uninstall}]", status.ProductCodeName)
			squidAdminMysql(1, xlog, xlog, futils.GetCalleRuntime(), 84)
			_ = ExecuteShell(status.UninstallCmdLine)
			return
		}
		return
	}
	if Enabled == 1 {
		if fileExists(status.InitdPath) {
			return
		}
		if len(status.InstallCmdLine) < 3 {
			return
		}
		xlog := fmt.Sprintf("{%v}: Not installed, {action}=[{install}]", status.ProductCodeName)
		err := ExecuteShell(fmt.Sprintf("%v", status.InstallCmdLine))
		if err != nil {
			text := fmt.Sprintf("Error during installation %v", status.ProductCodeName)
			squidAdminMysql(0, text, err.Error()+"\n"+xlog+"\n"+status.InstallCmdLine, futils.GetCalleRuntime(), 98)
			return
		}
		squidAdminMysql(0, xlog, status.InstallCmdLine, futils.GetCalleRuntime(), 52)
		return
	}
}
func tosyslogGen(text string, processname string) bool {
	syslogger, err := syslog.New(syslog.LOG_INFO, processname)
	if err != nil {
		return false
	}
	log.Debug().Msg(text)
	_ = syslogger.Notice(text)
	_ = syslogger.Close()
	return true
}
func syslogSpec(text string, name string) {
	w, err := syslog.New(syslog.LOG_INFO, name)
	if err != nil {
		return
	}
	defer func(w *syslog.Writer) {
		_ = w.Close()
	}(w)
	_ = w.Info(text)
	_ = w.Close()
}

func StatusSyslog(text string, Success bool, status StatusIni) {
	w, err := syslog.New(syslog.LOG_INFO, "monit")
	if err != nil {
		return
	}
	defer func(w *syslog.Writer) {
		_ = w.Close()
	}(w)

	Result := "FAILED"
	if Success {
		Result = "SUCCESS"
	}
	Msg := fmt.Sprintf("'%v' %v: %v [%v]", status.ProductCodeName, "Watchdog", text, Result)
	_ = w.Info(Msg)
	_ = w.Close()
}

func lastLiveInMin() int {
	uptimeSeconds, err := host.Uptime()
	if err != nil {
		return 9999999
	}
	return int(uptimeSeconds / 60)
}

func WatchdogMode(status StatusIni) {
	if !status.WatchdogMode {
		return
	}

	Enabled := getInfoInt(status.TokenEnabled)
	if status.ForceEnabled == 1 {
		Enabled = 1
	}
	log.Debug().Msgf("%v %v=%v", futils.GetCalleRuntime(), status.TokenEnabled, Enabled)
	if Enabled == 0 {
		return
	}
	if len(status.StartCmdLine) < 3 {
		return
	}
	StatusSyslog(fmt.Sprintf("Not running! %v=%d", status.TokenEnabled, Enabled), false, status)
	LastStopped := ""
	if len(status.LastStop) > 5 {
		LastStoppedT := futils.TimeStampToDateStr(futils.StrToInt64(futils.FileGetContents(status.LastStop)))
		LastStopped = fmt.Sprintf("\nLast stopped time: %v", LastStoppedT)
	}
	status.ErrorText = fmt.Sprintf("%v\nRunning Process: [%v]%v", status.ErrorText, status.StartCmdLine, LastStopped)
	xlog := fmt.Sprintf("{%v}: Not running, {action}=[{start_service}]", status.ProductCodeName)

	if len(status.SyslogName) > 1 {
		syslogSpec(fmt.Sprintf("Watchdog: Service %v is not running : Start the service [%v]", status.ProductCodeName, status.StartCmdLine), status.SyslogName)
	}

	if lastLiveInMin() > 3 {
		if !status.NONotifyFailed {
			severity := 0
			if !futils.IsProductionTime() {
				severity = 2
			}
			squidAdminMysql(severity, xlog, status.ErrorText, futils.GetCalleRuntime(), 81)
		}
	}

	systemctl := futils.FindProgram("systemctl")
	if futils.FileExists(systemctl) {
		initName := Basename(status.InitdPath)
		fpath := fmt.Sprintf("/etc/systemd/system/%v.service", initName)
		if futils.FileExists(fpath) {
			cmd := fmt.Sprintf("%v start %v.service", systemctl, initName)
			StatusSyslog(cmd, false, status)
			_ = ExecuteShell(cmd)
			return
		}

	}

	StatusSyslog(status.StartCmdLine, false, status)
	_ = ExecuteShell(status.StartCmdLine)
}

func MyStatus() string {
	cfg := ini.Empty()
	masterPid := os.Getpid()
	var status StatusIni
	status.ProductCodeName = "SQUID_AD_RESTFULL"
	status.MasterMemory, status.ProcessesNumber = StatusMemoryUsage(masterPid)
	StatusBuildStats(status)
	defaultSection := cfg.Section(status.ProductCodeName) // Default section
	pptime, duration := getProcessAgeInSeconds(masterPid)

	defaultSection.Key("service_name").SetValue(status.ProductCodeName)
	defaultSection.Key("master_version").SetValue("")
	defaultSection.Key("service_cmd").SetValue("/etc/init.d/artica-ad-rest")
	defaultSection.Key("pid_path").SetValue("")
	defaultSection.Key("watchdog_features").SetValue("1")
	defaultSection.Key("family").SetValue("network")
	defaultSection.Key("installed").SetValue(fmt.Sprintf("%v", 1))
	defaultSection.Key("application_installed").SetValue("1")
	defaultSection.Key("service_disabled").SetValue("1")
	defaultSection.Key("running").SetValue(fmt.Sprintf("%v", 1))
	defaultSection.Key("master_pid").SetValue(fmt.Sprintf("%v", masterPid))
	defaultSection.Key("master_time").SetValue(fmt.Sprintf("%v", pptime))
	defaultSection.Key("processes_number").SetValue(fmt.Sprintf("%v", status.ProcessesNumber))
	defaultSection.Key("master_memory").SetValue(fmt.Sprintf("%v", status.MasterMemory))
	defaultSection.Key("uptime").SetValue(formatDuration(duration))
	defaultSection.Key("maxfd").SetValue(fmt.Sprintf("%v", getRlimit()))
	defaultSection.Key("curfd").SetValue(fmt.Sprintf("%v", countMyOpenFiles()))
	var buffer bytes.Buffer
	_, err := cfg.WriteTo(&buffer)
	if err != nil {
		return ""
	}

	// Convert buffer to string
	return buffer.String()
}
func getLoadAvg() (float64, error) {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return 0, err
	}
	load := float64(info.Loads[0]) / float64(1<<16)
	return load, nil
}
func IsOverLoaded() bool {
	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)

	if ok {
		file := futils.Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s[%v:%d]: ", file, fn.Name(), line)
	}

	Cpus := runtime.NumCPU()
	MaxLoad := float64(Cpus)
	Load, _ := getLoadAvg()
	if Load > MaxLoad {
		log.Debug().Msgf("%v Load %v is greater than %v, Aborting task (%v)", futils.GetCalleRuntime(), Load, MaxLoad, TheCall)
		return true
	}
	return false
}
func BuildIni(status StatusIni) string {

	var mutexPtr *sync.Mutex
	if m, loaded := mutexes.LoadOrStore(status.ProductCodeName, &sync.Mutex{}); loaded {
		mutexPtr = m.(*sync.Mutex)
	} else {
		mutexPtr = m.(*sync.Mutex)
	}
	mutexPtr.Lock()
	defer mutexPtr.Unlock()

	futils.CreateDir("/home/artica/watchdog")
	TempCache := "/home/artica/watchdog/cache/" + status.ProductCodeName + ".ini"
	if status.WatchdogMode {
		if futils.FileExists(TempCache) {
			log.Debug().Msgf("%v exists %v", TempCache, TempCache)
			TimeMin := futils.FileTimeMin(TempCache)
			if TimeMin < 3 {
				return futils.FileGetContents(TempCache)
			}
		}
	}
	if IsOverLoaded() {
		if futils.FileExists(TempCache) {
			return futils.FileGetContents(TempCache)
		}
	}

	cfg := ini.Empty()
	Enabled := getInfoInt(status.TokenEnabled)
	if status.ForceEnabled == 1 {
		Enabled = 1
	}
	log.Debug().Msgf("%v %v=%v", futils.GetCalleRuntime(), status.TokenEnabled, Enabled)
	if status.AlwaysON {
		Enabled = 1
	}
	status.Enabled = Enabled
	var masterPid MasterPID
	defaultSection := cfg.Section(status.ProductCodeName) // Default section
	defaultSection.Key("service_name").SetValue(status.ProductCodeName)
	defaultSection.Key("master_version").SetValue("0.0.0")
	defaultSection.Key("service_cmd").SetValue(status.StartCmdLine)
	defaultSection.Key("pid_path").SetValue(status.Pidpath)
	defaultSection.Key("watchdog_features").SetValue("1")
	defaultSection.Key("family").SetValue("network")
	defaultSection.Key("installed").SetValue(fmt.Sprintf("%v", status.Installed))
	defaultSection.Key("application_installed").SetValue(fmt.Sprintf("%v", status.Installed))
	defaultSection.Key("service_disabled").SetValue(fmt.Sprintf("%v", Enabled))

	if status.UseThisPID > 5 {
		masterPid.RealPID = status.UseThisPID
	} else {
		masterPid = IniGetPid(status)
	}

	CheckInstalled(status)
	if !status.NoWatchdogProcess {
		if !futils.ProcessExists(masterPid.RealPID) {
			if Enabled == 1 {
				log.Debug().Msgf("%v Not Running! %v NoWatchdogProcess=1", futils.GetCalleRuntime(), status.ProductCodeName)
				status.ErrorText = strings.Join(masterPid.Event, "\n")
			}
			WatchdogMode(status)
		}

		err := CheckHTTP(status)
		if err != nil {
			severity := 0
			if !futils.IsProductionTime() {
				severity = 2
			}
			xlog := fmt.Sprintf("{%v}: %v %v, {action}=[{restart_service}]", status.ProductCodeName, status.CheckHTTPAddr, err.Error())
			squidAdminMysql(severity, xlog, err.Error(), futils.GetCalleRuntime(), 145)
			RestartService(status)
		}

		if masterPid.RealPID > 2 {
			maxfd := futils.ProcessMaxOpenFiles(masterPid.RealPID)
			Curfd := futils.ProccessCurOpenFiles(masterPid.RealPID)
			MxLim := maxfd - 200
			if Curfd > 10 {
				if MxLim > 10 {
					if Curfd > MxLim {
						Ftext := fmt.Sprintf("Warning {%v} reach Max open files limit (%v/%v)", status.ProductCodeName, Curfd, maxfd)
						squidAdminMysql(1, Ftext, "", futils.GetCalleRuntime(), 156)
					}
				}
			}

			pptime, duration := getProcessAgeInSeconds(masterPid.RealPID)
			defaultSection.Key("running").SetValue(fmt.Sprintf("%v", 1))
			status.FinalMasterPid = masterPid.RealPID
			defaultSection.Key("master_pid").SetValue(fmt.Sprintf("%v", masterPid.RealPID))
			defaultSection.Key("master_time").SetValue(fmt.Sprintf("%v", pptime))
			status.MasterMemory, status.ProcessesNumber = StatusMemoryUsage(masterPid.RealPID)
			defaultSection.Key("processes_number").SetValue(fmt.Sprintf("%v", status.ProcessesNumber))
			defaultSection.Key("master_memory").SetValue(fmt.Sprintf("%v", status.MasterMemory))
			if status.MultipleProcess {
				MultipleMemory := int64(0)
				pids := futils.PIDOFPatternALL(status.MemoryBin)
				for _, pid := range pids {
					MasterMemory, _ := StatusMemoryUsage(pid)
					MultipleMemory = MultipleMemory + MasterMemory
				}
				defaultSection.Key("processes_number").SetValue(fmt.Sprintf("%v", len(pids)))
				defaultSection.Key("master_memory").SetValue(fmt.Sprintf("%v", MultipleMemory))
			}

			defaultSection.Key("uptime").SetValue(formatDuration(duration))
			defaultSection.Key("maxfd").SetValue(fmt.Sprintf("%v", futils.ProcessMaxOpenFiles(masterPid.RealPID)))
			defaultSection.Key("curfd").SetValue(fmt.Sprintf("%v", Curfd))
			StatusBuildStats(status)
		} else {
			defaultSection.Key("running").SetValue(fmt.Sprintf("%v", 0))
		}
	}
	var buffer bytes.Buffer
	_, err := cfg.WriteTo(&buffer)
	if err != nil {
		return ""
	}
	futils.DeleteFile(TempCache)
	_ = futils.FilePutContents(TempCache, buffer.String())
	return buffer.String()

}

func ProcessUptime(Pid int) string {
	_, duration := getProcessAgeInSeconds(Pid)
	return formatDuration(duration)
}

func RestartService(status StatusIni) {
	fname := futils.TempFileName()
	var sh []string
	sh = append(sh, "#!/bin/sh")
	sh = append(sh, "PATH=\"/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin\"")
	sh = append(sh, status.StopCmdLine)
	sh = append(sh, status.StartCmdLine)
	sh = append(sh, fmt.Sprintf("rm -f %v", fname))
	_ = filePutContents(fname, strings.Join(sh, "\n"))
	Chmod(fname, 0755)
	if len(status.SyslogName) > 1 {
		syslogSpec(fmt.Sprintf("Watchdog: Restart the service with [%v]", status.StartCmdLine), status.SyslogName)
	}
	_ = ExecuteShell(fname)
}

func CheckHTTP(status StatusIni) error {

	if !status.WatchdogMode {
		return nil
	}
	if len(status.CheckHTTPAddr) == 0 {
		return nil
	}

	if len(status.StartCmdLine) == 0 {
		return nil
	}
	if len(status.StopCmdLine) == 0 {
		return nil
	}

	Timeout := 3
	TimeOutDuration := time.Duration(Timeout) * time.Second
	localAddr := &net.TCPAddr{
		IP: net.ParseIP("127.0.0.1"),
	}
	dialer := &net.Dialer{
		Timeout:   TimeOutDuration,
		KeepAlive: TimeOutDuration,
		LocalAddr: localAddr,
	}
	client := &http.Client{
		Timeout: TimeOutDuration,
		Transport: &http.Transport{
			Dial:              dialer.Dial,
			DisableKeepAlives: true,
			MaxIdleConns:      0,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true,
			},
		},
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	fileURL := fmt.Sprintf("http://%v/", status.CheckHTTPAddr)

	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		_ = resp.Body.Close()
		return err
	}
	_ = resp.Body.Close()
	return nil

}

func StatusBuildStats(status StatusIni) {

	Max := 200
	var NewArray []string
	TempDir := "/usr/share/artica-postfix/ressources/pmemory"
	CreateDir(TempDir)
	fileprocess := fmt.Sprintf("%v/%v", TempDir, status.ProductCodeName)

	if status.Enabled == 0 {
		futils.DeleteFile(fileprocess)
		return
	}

	if fileExists(fileprocess) {
		Data := fileGetContents(fileprocess)
		NewArray = strings.Split(Data, ";")
		if len(NewArray) > Max {
			NewArray = []string{}
		}
	}
	NewArray = append(NewArray, fmt.Sprintf("%v", status.MasterMemory))
	_ = filePutContents(fileprocess, strings.Join(NewArray, ";"))

}
func filePutContents(filename string, data string) error {
	return os.WriteFile(filename, []byte(data), 0644)
}
func fileGetContents(filename string) string {
	if !fileExists(filename) {
		return ""
	}
	tk, err := os.ReadFile(filename)
	if err != nil {
		return ""
	}
	tk = bytes.TrimSpace(tk)
	return string(tk)
}

func fileExists(spath string) bool {
	if _, err := os.Stat(spath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}
func CreateDir(directoryPath string) {
	_, err := os.Stat(directoryPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(directoryPath, 0755)
		if err != nil {
			return
		}
		return
	}
}

func formatDuration(d time.Duration) string {
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	seconds := d / time.Second
	var tex []string
	Months := 0
	xDays := StrToInt64(fmt.Sprintf("%d", days))
	if xDays > 30 {
		Months = int(xDays) / 30
		DaysMonths := Months * 30
		xDays = xDays - int64(DaysMonths)
	}
	if Months > 0 {
		if Months == 1 {
			tex = append(tex, "1 month")
		} else {
			tex = append(tex, fmt.Sprintf("%d months", Months))
		}
	}

	if xDays > 0 {
		if xDays == 1 {
			tex = append(tex, "1 day")
		} else {
			tex = append(tex, fmt.Sprintf("%d days", xDays))
		}
	}
	if hours > 0 {
		if hours == 1 {
			tex = append(tex, "1 hour")
		} else {
			tex = append(tex, fmt.Sprintf("%d hours", hours))
		}
	}
	if minutes > 0 {
		if minutes == 1 {
			tex = append(tex, "1 minute")
		} else {
			tex = append(tex, fmt.Sprintf("%d minutes", minutes))
		}
	}

	if len(tex) == 0 {
		if seconds == 1 {
			tex = append(tex, "1 second")
		} else {
			tex = append(tex, fmt.Sprintf("%d seconds", seconds))
		}
	}

	return strings.Join(tex, ", ")
}
func IniGetPid(status StatusIni) MasterPID {

	var Status MasterPID

	if status.Debug {
		Status.Event = append(Status.Event, fmt.Sprintf("Pidpath: %v", status.Pidpath))
		log.Debug().Msgf("%v Pidpath:", futils.GetCalleRuntime(), status.Pidpath)
	}

	if len(status.Pidpath) > 3 {
		if DebugStatus {
			log.Debug().Msg(fmt.Sprintf("%v Get status from %v", status.ProductCodeName, status.Pidpath))
		}
		pid, err := GetPidFromPath(status.Pidpath)
		Status.Event = append(Status.Event, fmt.Sprintf("Pidpath results: %v", pid))
		if DebugStatus {
			log.Debug().Msg(fmt.Sprintf("%v Get status from %v = %v", status.ProductCodeName, status.Pidpath, pid))
		}
		if err != nil {
			Status.Event = append(Status.Event, fmt.Sprintf("Pidpath Error: %v", err.Error()))
		}
		Status.RealPID = pid
		if futils.ProcessExists(pid) {
			return Status
		}
	}

	Status.Event = append(Status.Event, fmt.Sprintf("Checkstatus of binary with: [%v]", status.MemoryBin))
	log.Debug().Msgf("%v Pidpath: %v", futils.GetCalleRuntime(), status.Pidpath)
	log.Debug().Msgf("%v Checkstatus of: %v", futils.GetCalleRuntime(), status.MemoryBin)

	pid := futils.PIDOFPattern(status.MemoryBin)
	if DebugStatus {
		log.Debug().Msg(fmt.Sprintf("%v Get status from [%v] = %v", status.ProductCodeName, status.MemoryBin, pid))
	}
	Status.Event = append(Status.Event, fmt.Sprintf("binary results: %v", pid))

	log.Debug().Msgf("%v %v=%d", futils.GetCalleRuntime(), status.MemoryBin, pid)

	if !futils.ProcessExists(pid) {
		Status.RealPID = 0
		return Status
	}
	if len(status.Pidpath) > 3 {
		_ = filePutContents(status.Pidpath, fmt.Sprintf("%v", pid))
	}
	Status.RealPID = pid
	return Status

}

func GetPidFromPath(pidFilePath string) (int, error) {
	pidBytes, err := os.ReadFile(pidFilePath)
	if err != nil {
		return 0, err
	}
	pidString := strings.TrimSpace(string(pidBytes))
	pid, err := strconv.Atoi(pidString)
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func regex_find(pattern, data string) bool {
	matched, _ := regexp.MatchString(pattern, data)
	return matched

}
func MemoryHumanBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%.2f B", float64(bytes))
	}
	div, exp := float64(unit), 0
	for n := float64(bytes) / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	value := float64(bytes) / div
	suffixes := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.2f %s", value, suffixes[exp])
}

func StatusMemoryUsage(pid int) (int64, int) {

	totalMemory := int64(0)
	pidsToCheck := []int{pid}
	checkedPIDs := make(map[int]bool)

	for len(pidsToCheck) > 0 {
		currentPID := pidsToCheck[0]
		pidsToCheck = pidsToCheck[1:]

		if _, checked := checkedPIDs[currentPID]; checked {
			continue
		}

		memory, err := getMemoryUsageByPID(currentPID)
		if err == nil {
			totalMemory += memory
		}

		childPIDs, err := getChildPIDs(currentPID)
		if err == nil {
			pidsToCheck = append(pidsToCheck, childPIDs...)
		}

		checkedPIDs[currentPID] = true
	}

	return totalMemory, len(checkedPIDs)
}

func getMemoryUsageByPID(pid int) (int64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, fmt.Errorf("unexpected content in /proc/%s/statm", pid)
	}

	// Usually, the second field in /proc/[pid]/statm is the resident set size
	// Convert pages to bytes (assuming standard page size of 4096 bytes)
	rss, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, err
	}
	// Convert to KB (or MB if needed)
	rssKB := rss * 4 // Multiply by 4 for KB (4096 bytes/page)
	return rssKB, nil
}

func getChildPIDs(pid int) ([]int, error) {
	var childPIDs []int
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, entry := range procEntries {
		if entry.IsDir() {
			entryPID, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue // Not a PID directory
			}

			data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
			if err != nil {
				continue // Can't read stat file
			}

			fields := strings.Fields(string(data))
			if len(fields) > 4 {
				ppid, err := strconv.Atoi(fields[3])
				if err == nil && ppid == pid {
					childPIDs = append(childPIDs, entryPID)
				}
			}
		}
	}
	return childPIDs, nil
}
func getTicksPerSecond() (int64, error) {
	// On many Unix systems, CLK_TCK is a constant value (often 100).
	// You might need to adjust this depending on your specific system.
	const CLK_TCK int64 = 100
	return CLK_TCK, nil
}

func getProcessAgeInSeconds(pid int) (int64, time.Duration) {
	// Read the system uptime
	uptimeBytes, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, 0
	}
	uptimeFields := strings.Fields(string(uptimeBytes))
	uptimeSecs, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil {
		return 0, 0
	}

	// Read the process's stat file
	stat, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0
	}

	// Extract the start time (field 22)
	parts := strings.Fields(string(stat))
	if len(parts) < 22 {
		return 0, 0
	}
	startTimeTicks, err := strconv.ParseInt(parts[21], 10, 64)
	if err != nil {
		return 0, 0
	}

	// Get clock ticks per second
	ticksPerSecond, err := getTicksPerSecond()
	if err != nil {
		return 0, 0
	}

	// Calculate the process's start time in seconds since the Unix epoch
	startTimeSecs := float64(startTimeTicks) / float64(ticksPerSecond)

	// Calculate the age of the process in seconds
	processAgeSeconds := int64(uptimeSecs) - int64(startTimeSecs)

	return processAgeSeconds, time.Duration(processAgeSeconds) * time.Second
}
func countMyOpenFiles() int64 {
	MyPID := os.Getpid()
	Dir := fmt.Sprintf("/proc/%d/fd", MyPID)
	fds, err := os.ReadDir(Dir)
	if err != nil {
		return int64(0)
	}
	return int64(len(fds))
}

func getRlimit() int64 {

	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("Error Getting Rlimit %v", err))
		return int64(9223372036854775807)
	}

	if rLimit.Max > math.MaxInt64 {
		return int64(9223372036854775807)
	}

	return int64(rLimit.Max)

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

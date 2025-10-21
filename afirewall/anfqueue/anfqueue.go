package anfqueue

import (
	"GlobalsValues"
	"apostgres"
	"articasys"
	"articaunix"
	"bytes"
	"crowdsec/CrowdSecTools"
	"fmt"
	"futils"
	"httpclient"
	"monit"
	"notifs"
	"os"
	"os/exec"
	"pfringcheck"
	"regexp"
	"runtime"
	"sockets"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

const PidPath = "/run/artica-nfqueue.pid"
const duration = 1 * time.Second
const SyslogConfPath = "/etc/rsyslog.d/00_artica-nfqueue.conf"
const RootDir = ""
const ServiceName = "NFQueue Filter"
const SourceBin = "/usr/share/artica-postfix/bin/artica-nfqueue"
const DestBin = "/usr/local/bin/nfqueue"
const MasterName = "artica-nfqueue"
const ArticaBinary = GlobalsValues.ArticaBinary
const MonitFile = "/etc/monit/conf.d/APP_NFQUEUE.monitrc"
const MonitName = "APP_NFQUEUE"
const InitdPath = "/etc/init.d/nfqueue"
const TokenEnabled = "EnableArticaNFQueue"
const TokenVersion = "APP_NFQUEUE_VERSION"
const StartProgram = ArticaBinary + " -start-nfqueue"
const StopProgram = ArticaBinary + " -stop-nfqueue"
const RestartProgram = ArticaBinary + " -restart-nfqueue"
const ReloadProgram = ArticaBinary + " -reload-nfqueue"
const UninstallProgram = ArticaBinary + " -uninstall-nfqueue"
const InstallProgram = ArticaBinary + " -install-nfqueue"
const ProgressF = "nfqueue.progress"

var versionRegex = regexp.MustCompile(`version\s+([0-9\.]+)`)

func Install() {

	DebianVersion := sockets.DebianVersion(true)
	if DebianVersion < 12 {
		kernelversion := articasys.KernelVersion()
		if kernelversion != "4.19.0-27-amd64" {
			notifs.BuildProgress(110, "Bad Kernel version", ProgressF)
			return
		}
	}

	sockets.SET_INFO_INT(TokenEnabled, 1)
	sockets.SET_INFO_INT("EnableCrowdsecFirewallBouncer", 0)
	go func() {
		_ = httpclient.RestAPIUnix("/crowdsec/firewall/bouncer/uninstall")
	}()
	notifs.BuildProgress(50, "{install_service}", ProgressF)
	Conf := ServiceConfig()
	log.Warn().Msgf("%v Installing %v", futils.GetCalleRuntime(), ServiceName)
	articaunix.EnableService(Conf)
	notifs.BuildProgress(60, "{install_service}", ProgressF)
	notifs.BuildProgress(80, "{install_service}", ProgressF)
	Start()
	notifs.SquidAdminMysql(1, "{install} "+ServiceName, "", futils.GetCalleRuntime(), 81)
	notifs.BuildProgress(100, "{install_service} {success}", ProgressF)
}
func Uninstall() {

	notifs.BuildProgress(35, "{uninstall_service}", ProgressF)
	sockets.SET_INFO_INT(TokenEnabled, 0)
	Conf := ServiceConfig()
	notifs.BuildProgress(50, "{uninstall_service}", ProgressF)
	articaunix.ServiceUninstall(Conf)
	futils.DeleteFile("/usr/share/artica-postfix/ressources/logs/NFQueue/error.txt")

	if futils.FileExists(MonitFile) {
		notifs.BuildProgress(70, "{uninstall_service}", ProgressF)
		futils.DeleteFile(MonitFile)
		log.Info().Msgf("%v Reloading the Monit service", futils.GetCalleRuntime())
		monit.Reload()
	}
	if futils.FileExists(SyslogConfPath) {
		notifs.BuildProgress(75, "{uninstall_service}", ProgressF)
		futils.DeleteFile(SyslogConfPath)
	}
	notifs.BuildProgress(100, "{uninstall_service} {done}", ProgressF)
}
func Start() bool {

	if !futils.FileExists(DestBin) {
		UpdateBinary()
	}

	Enable := sockets.GET_INFO_INT(TokenEnabled)
	if Enable == 0 {
		if futils.FileExists("/etc/monit/conf.d/APP_NFQUEUE.monitrc") {
			futils.DeleteFile("/etc/monit/conf.d/APP_NFQUEUE.monitrc")
			monit.Restart()
			return true
		}
		return true
	}

	if !futils.FileExists(DestBin) {
		log.Debug().Msgf("%v %v binary not found", futils.GetCalleRuntime(), MasterName)
		return false
	}

	pid := GetPID()

	if futils.ProcessExists(pid) {
		log.Info().Msgf("%v %v already running...", futils.GetCalleRuntime(), ServiceName)
		return true
	}
	UpdateBinary()
	if GlobalsValues.StartSystemd(GlobalsValues.SystemDConfig{
		InitdPath:  InitdPath,
		PidPath:    PidPath,
		PidPattern: "artica-nfqueue",
	}) {
		return true
	}

	checkCrowdSec()
	CreateMonitService()
	out, err := RunNFQUeue()
	if err != nil {
		log.Error().Msgf("%v Error running %v %v %v", futils.GetCalleRuntime(), err, ServiceName, out)
		return false
	}
	time.Sleep(duration)
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		log.Info().Msgf("%v %v", futils.GetCalleRuntime(), line)
	}
	if futils.ProcessExists(pid) {
		log.Info().Msgf("%v Starting...%v [SUCCESS]", futils.GetCalleRuntime(), ServiceName)
		return true
	}

	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetPID()
		if futils.ProcessExists(pid) {
			log.Info().Msgf("%v Starting...%v [SUCCESS] %d/5 Pid:%d (%v)", futils.GetCalleRuntime(), ServiceName, i, pid, futils.ProcessCommandLine(pid))
			return true
		}

	}

	pid = GetPID()
	if futils.ProcessExists(pid) {
		log.Info().Msgf("%v Starting...%v [SUCCESS]", futils.GetCalleRuntime(), ServiceName)
		return true
	}
	log.Error().Msgf("%v Starting %v Failed", futils.GetCalleRuntime(), ServiceName)
	return false
}

func checkCrowdSec() {

	EnableCrowdSec := sockets.GET_INFO_INT("EnableCrowdSec")

	if EnableCrowdSec == 0 {
		_, _ = futils.ExecuteShell(DestBin + " -crowdsec --enable=0")
		return
	}
	GetServerPort := CrowdSecTools.ServerPort()
	Keys := CrowdSecTools.ListApiKeys(false)

	_, ok := Keys["artica"]
	if ok {
		log.Info().Msgf("%v Current API Key: OK", futils.GetCalleRuntime())
	} else {
		log.Info().Msgf("%v Remove old Firewall Bouncer API KEY", futils.GetCalleRuntime())
		err, out := CrowdSecTools.BouncersDelete("firewall-bouncer")
		if err != nil {
			log.Error().Msgf("%v %v %v", futils.GetCalleRuntime(), err, out)
		}
		err, out = CrowdSecTools.BouncersDelete("artica")
		if err != nil {
			log.Error().Msgf("%v %v %v", futils.GetCalleRuntime(), err, out)
		}
		err, out = CrowdSecTools.BouncersAdd("artica")
		if err != nil {
			log.Error().Msgf("%v %v %v", futils.GetCalleRuntime(), err, out)
		}
		if err != nil {
			log.Error().Msgf("%v Create Firewall Bouncer API KEY %v %v", futils.GetCalleRuntime(), err.Error(), out)
			return
		}
	}
	Key := articasys.Getuuid()
	_, _ = futils.ExecuteShell(DestBin + fmt.Sprintf("-crowdsec --enable=1 --apikey=%v uri=http://127.0.0.1:%d", Key, GetServerPort))

}

func startUPScript() {
	var sh []string
	nohup := futils.FindProgram("nohup")
	sh = append(sh, "#!/bin/sh")
	sh = append(sh, fmt.Sprintf("%v %v >/var/log/nfqueue.startup.log 2>&1 &", nohup, DestBin))
	sh = append(sh, "exit 0")
	sh = append(sh, "")
	_ = futils.FilePutContents("/usr/bin/nfqueue-start.sh", strings.Join(sh, "\n"))
	futils.Chmod("/usr/bin/nfqueue-start.sh", 0755)
}
func RunNFQUeue() (string, error) {
	cmdPath := DestBin
	defer futils.DeleteFile("/var/log/nfqueue.startup.log")
	startUPScript()
	_ = pfringcheck.EnsurePFRING()
	err, out := futils.ExecuteShell("/usr/bin/nfqueue-start.sh")
	out = out + "\n" + futils.FileGetContents("/var/log/nfqueue.startup.log")
	if err == nil {
		return out, nil
	}

	if _, err := os.Stat(cmdPath); os.IsNotExist(err) {
		return "", fmt.Errorf("%v executable not found at %s", futils.GetCalleRuntime(), cmdPath)
	}
	futils.Chmod(cmdPath, 0755)
	cmd := exec.Command(cmdPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = futils.ExecEnv()

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // Start a new session to detach from parent
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("%v failed to start %v: %v", futils.GetCalleRuntime(), ServiceName, err)
	}
	output := ""
	if len(stdout.String()) > 5 {
		output := stdout.String()
		if stderrStr := stderr.String(); stderrStr != "" {
			if output != "" {
				output += "\n"
			}
			output += stderrStr
		}

	}
	output += out

	if len(stderr.String()) > 1 {
		log.Info().Msgf("%v stdErr=[%v]", futils.GetCalleRuntime(), stderr.String())
	}
	if len(output) > 5 {
		tb := strings.Split(output, "\n")
		for _, line := range tb {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			log.Info().Msgf("%v [%v]", futils.GetCalleRuntime(), line)
		}
	}

	return output, nil
}
func PcapPID() int {
	pid := futils.GetPIDFromFile("/var/run/articapsniffer.pid")
	if futils.ProcessExists(pid) {
		return pid
	}
	return futils.PIDOFPattern("articapsniffer")

}
func GetVersion() string {
	out := ""
	if futils.FileExists(DestBin) {
		_, out = futils.ExecuteShell(SourceBin + " -version")
	} else {
		futils.Chmod(SourceBin, 0755)
		_, out = futils.ExecuteShell(SourceBin + " -version")
	}
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		version := futils.RegexGroup1(versionRegex, line)
		if len(version) > 1 {
			sockets.SET_INFO_STR(TokenVersion, version)
		}
	}
	return "0.0.0"
}
func Status(Watchdog bool) string {

	if Watchdog {
		Enabled := sockets.GET_INFO_INT(TokenEnabled)
		if Enabled == 0 {
			futils.DeleteFile("/usr/share/artica-postfix/ressources/logs/NFQueue/error.txt")
		}

		if Enabled == 1 {

			DebianVersion := sockets.DebianVersion(true)
			if DebianVersion < 12 {
				kernelversion := articasys.KernelVersion()
				if kernelversion != "4.19.0-27-amd64" {
					notifs.BuildProgress(110, "Bad Kernel version", ProgressF)
					Uninstall()
					return ""
				}
			}

			futils.CreateDir("/usr/share/artica-postfix/ressources/logs/NFQueue")
			futils.ChownFolder("/usr/share/artica-postfix/ressources/logs/NFQueue", "www-data", "www-data")
			GetVersion()
			sockets.SET_INFO_STR(TokenVersion, GetVersion())
			pcapMigration()
			CheckUpdate()
			err := pfringcheck.EnsurePFRING()
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
				_ = futils.FilePutContents("/usr/share/artica-postfix/ressources/logs/NFQueue/error.txt", err.Error())
			} else {
				futils.DeleteFile("/usr/share/artica-postfix/ressources/logs/NFQueue/error.txt")
			}
		}
	}

	var ini articaunix.StatusIni
	var f []string
	opts := ServiceConfig()

	ini.ProductCodeName = opts.MonitName
	ini.Installed = 1
	ini.Pidpath = opts.Pidfile
	ini.MemoryBin = opts.SourceBin
	ini.TokenEnabled = TokenEnabled
	ini.WatchdogMode = Watchdog
	ini.Debug = false
	ini.CheckSockets = ""
	ini.StartCmdLine = opts.ExecStart
	ini.UninstallCmdLine = UninstallProgram
	ini.InstallCmdLine = InstallProgram
	ini.InitdPath = InitdPath
	f = append(f, articaunix.BuildIni(ini))
	return strings.Join(f, "\n")
}
func pcapMigration() {

	if !futils.FileExists("/etc/init.d/articapcap") {
		cleanPcapFiles()
		return
	}
	_, _ = futils.ExecutePHP("exec.articapcap.php --stop")
	_, _ = futils.ExecutePHP("exec.articapcap.php --uninstall")
	cleanPcapFiles()
	pid := PcapPID()
	if futils.ProcessExists(pid) {
		futils.KillProcess(pid)
	}
	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	} else {
		_, err = db.Exec(`TRUNCATE TABLE ipset_auto`)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		_, err = db.Exec(`TRUNCATE TABLE ipset_categories`)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
	}
	notifs.SquidAdminMysql(0, "ArticaPCAP Filter was migrated to Artica NFQueue Filter", "", futils.GetCalleRuntime(), 223)
	Install()

}
func cleanPcapFiles() {
	files := []string{"/usr/share/artica-postfix/exec.articapcap.php",
		"/etc/monit/conf.d/APP_ARTICAPCP.monitrc",
		"/usr/sbin/articapsniffer", "/usr/share/artica-postfix/bin/articapsniffer",
		"/usr/share/artica-postfix/ressources/class.status.articapcap.inc",
	}
	if futils.FileExists("/etc/init.d/articapcap") {
		articaunix.RemoveServiceINIT("/etc/init.d/articapcap")
	}
	for _, file := range files {
		futils.DeleteFile(file)
	}
}

func Restart() {
	notifs.BuildProgress(20, "{stopping}", ProgressF)
	Stop()
	notifs.BuildProgress(50, "{starting}", ProgressF)
	if !Start() {
		notifs.BuildProgress(110, "{starting} {failed}", ProgressF)
		return
	}
	notifs.BuildProgress(100, "{restarting} {success}", ProgressF)
}
func Reload() {

}
func CheckUpdate() {
	Enable := sockets.GET_INFO_INT(TokenEnabled)
	if Enable == 0 {
		return
	}
	md51 := futils.MD5File(SourceBin)
	md512 := futils.MD5File(DestBin)
	if md51 == md512 {
		return
	}
	log.Warn().Msgf("%v %v New version available, restart service", futils.GetCalleRuntime(), ServiceName)
	Restart()
}
func Stop() bool {
	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)

	if ok {
		file := futils.Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s[%v:%d]: ", file, fn.Name(), line)
	}
	pid := GetPID()
	if !futils.ProcessExists(pid) {
		log.Info().Msgf("%v %v already stopped (by %v)...", futils.GetCalleRuntime(), ServiceName, TheCall)
		return true
	}

	log.Info().Msgf("%v Ask to stop %v by %v", futils.GetCalleRuntime(), ServiceName, TheCall)
	if GlobalsValues.StopBySystemd(GlobalsValues.SystemDConfig{
		InitdPath:  InitdPath,
		PidPath:    PidPath,
		PidPattern: "artica-nfqueue",
	}) {
		return true
	}
	futils.KillSmoothProcess(pid)

	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetPID()
		if !futils.ProcessExists(pid) {
			log.Info().Msgf("%v Stopping...%v [SUCCESS]", futils.GetCalleRuntime(), ServiceName)
			return true
		}
		log.Info().Msgf("%v Stopping...%v pid %v %v/5", futils.GetCalleRuntime(), ServiceName, pid, i)
		futils.KillSmoothProcess(pid)
	}

	pid = GetPID()
	if !futils.ProcessExists(pid) {
		log.Warn().Msgf("%v Stopping..%v [SUCCESS]", futils.GetCalleRuntime(), ServiceName)
		return true
	}
	log.Warn().Msgf("%v Killing...%v pid %v", futils.GetCalleRuntime(), ServiceName, pid)
	futils.KillProcess(pid)
	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetPID()
		if !futils.ProcessExists(pid) {
			log.Info().Msgf("%v Stopping..%v [SUCCESS]", futils.GetCalleRuntime(), ServiceName)
			return true
		}
		log.Info().Msgf("%v Stopping...%v %v %v/5", futils.GetCalleRuntime(), ServiceName, pid, i)
		futils.KillProcess(pid)
	}
	pid = GetPID()
	if !futils.ProcessExists(pid) {
		log.Info().Msg(fmt.Sprintf("Stopping...%v [SUCCESS]", ServiceName))
		return true
	}
	log.Error().Msg(fmt.Sprintf("Stopping...%v [FAILED]", ServiceName))
	return false
}
func UpdateBinary() {

	if !futils.FileExists(SourceBin) {
		log.Error().Msgf("%v %v no such file", futils.GetCalleRuntime(), SourceBin)
		return
	}

	md51 := futils.MD5File(SourceBin)
	md52 := futils.MD5File(DestBin)
	if md51 == md52 {
		futils.Chmod(DestBin, 0755)
		return
	}
	_ = futils.CopyFile(SourceBin, DestBin)
	notifs.SquidAdminMysql(1, fmt.Sprintf("Updated new version of the %v Service", ServiceName), "", futils.GetCalleRuntime(), 71)
	futils.Chmod(DestBin, 0755)
}
func GetPID() int {
	pid := futils.GetPIDFromFile(PidPath)
	if futils.ProcessExists(pid) {
		return pid
	}
	return futils.PIDOFPattern(DestBin)
}
func CreateMonitService() {
	var f []string
	opts := ServiceConfig()
	f = append(f, fmt.Sprintf("check process %v with pidfile %v", MonitName, PidPath))
	f = append(f, fmt.Sprintf("\tstart program = \"%v\"", opts.ExecStart))
	f = append(f, "")

	md51 := futils.MD5File(MonitFile)
	_ = futils.FilePutContents(MonitFile, strings.Join(f, "\n"))
	md52 := futils.MD5File(MonitFile)
	if md51 == md52 {
		return
	}

	notifs.MonitSyslog(fmt.Sprintf("%v Starting [RELOADING MONITOR]", futils.GetCalleRuntime()), MonitName, ServiceName)
	monit.Reload()
}
func ServiceConfig() articaunix.ServiceOptions {
	var opts articaunix.ServiceOptions
	DestBin := futils.FindProgram(MasterName)
	opts.SourceBin = DestBin
	opts.CheckSocket = ""
	opts.ForcePidFile = true
	opts.ExecStart = StartProgram
	opts.ExecStop = StopProgram
	opts.ExecReload = ReloadProgram
	opts.ExecRestart = RestartProgram
	opts.ExecInstall = InstallProgram
	opts.ExecUninstall = UninstallProgram
	opts.InitdPath = InitdPath
	opts.Pidfile = PidPath
	opts.ServiceName = ServiceName
	opts.ProcessPattern = "artica-nfqueue"
	opts.ProcessNoWait = true
	opts.TokenEnabled = TokenEnabled
	opts.StartCmdLine = StartProgram
	opts.SyslogConfPath = SyslogConfPath
	opts.DisableMonitConfig = true
	opts.MonitName = MonitName
	return opts
}

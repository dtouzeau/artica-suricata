package monit

import (
	"GlobalsValues"
	"articaunix"
	"bytes"
	"context"
	"errors"
	"fmt"
	"futils"
	"log/syslog"
	"logsink"
	"notifs"
	"os"
	"os/exec"
	"sockets"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const SyslogConfPath = "/etc/rsyslog.d/monit.conf"
const ArticaBinary = GlobalsValues.ArticaBinary
const ServiceName = "System monitor"
const InitdPath = "/etc/init.d/monit"
const PidPath = "/run/monit/monit.pid"
const TokenVersion = "APP_MONIT_VERSION"
const TokenInstalled = "MONIT_INSTALLED"

func Install() {
	MainBin := futils.FindProgram("monit")
	if !futils.FileExists(MainBin) {
		return
	}

	Config := ServiceConfig()
	log.Info().Msgf("%v Creating the %v Service...", futils.GetCalleRuntime(), ServiceName)
	articaunix.EnableService(Config)
	log.Info().Msgf("%v Building Syslog Configuration the %v Service...", futils.GetCalleRuntime(), ServiceName)
	syslogConf()
	log.Info().Msgf("%v Creating %v Service success...", futils.GetCalleRuntime(), ServiceName)

}
func Start() bool {

	if !futils.FileExists("/etc/artica-postfix/settings/Daemons/EnableMonit") {
		sockets.SET_INFO_INT("EnableMonit", 1)
	}
	if futils.LockedInstall() {
		log.Error().Msgf("%v artica-as-rebooted no such file, aborting", futils.GetCalleRuntime())
		return false
	}

	if futils.ArticaRestLocked() {
		return false
	}

	if !futils.FileExists("/etc/init.d/monit") {
		Install()
	}
	DestBin := futils.FindProgram("monit")
	if GlobalsValues.StartSystemd(GlobalsValues.SystemDConfig{
		InitdPath:  InitdPath,
		PidPath:    PidPath,
		PidPattern: DestBin,
	}) {
		return true
	}

	futils.CreateDir("/run/monit")
	pid := GetPID()
	if futils.ProcessExists(pid) {
		log.Info().Msgf("%v Process monit already running PID %d", futils.GetCalleRuntime(), pid)
		return true
	}
	Dirs := []string{"/run/monit", "/var/monit", "/etc/monit/conf.d"}
	for _, dir := range Dirs {
		futils.CreateDir(dir)
		futils.Chmod(dir, 0600)
	}
	futils.DeleteFile("/etc/monit/conf.d/APP_INFLUXDB.monitrc")
	futils.DeleteFile("/etc/monit/conf.d/APP_SYSLOGDB.monitrc")
	futils.PopuplateCronMake("monit-start", "@reboot", GlobalsValues.ArticaBinary+" -monit-check")
	syslogConf()
	cronMonit()

	out, err := RunMonitWithTimeout()

	if err != nil {
		log.Error().Msgf("%v Unable to Start Monitor Daemon with error %v", futils.GetCalleRuntime(), err.Error())
		notifs.SquidAdminMysql(0, fmt.Sprintf("Unable to Start Monitor Daemon with error %v", err.Error()), out, "monit.start", 82)
		return false
	}

	duration := 1 * time.Second
	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetPID()
		if futils.ProcessExists(pid) {
			log.Debug().Msgf("%v Success Starting Monit Daemon", futils.GetCalleRuntime())
			return true
		}
	}

	notifs.SquidAdminMysql(0,
		fmt.Sprintf("Unable to Start Monitor Daemon with error %v", "Service Timed Out"),
		out, "monit.start", 82)

	return false

}
func RunMonitWithTimeout() (combinedOutput string, err error) {
	// Create a context with a 20-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel() // Ensure the context is canceled to release resources

	monitBin := futils.FindProgram("monit")
	var outputBuf bytes.Buffer

	cmd := exec.CommandContext(ctx, monitBin, "-c", "/etc/monit/monitrc", "-p", "/run/monit/monit.pid", "-s", "/run/monit/monit.state")
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf // Redirect stderr to the same buffer as stdout
	cmd.Env = append(cmd.Env, futils.ExecEnv()...)

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start sshd: %v", err)
	}
	err = cmd.Wait()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return outputBuf.String(), fmt.Errorf("timed out after 20 seconds")
		}
		return outputBuf.String(), fmt.Errorf("%v failed: %v", ServiceName, err)
	}

	return outputBuf.String(), nil
}
func StopMonitWithTimeout() (combinedOutput string, err error) {
	// Create a context with a 20-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel() // Ensure the context is canceled to release resources

	monitBin := futils.FindProgram("monit")
	var outputBuf bytes.Buffer

	cmd := exec.CommandContext(ctx, monitBin, "-c", "/etc/monit/monitrc", "-p", "/run/monit/monit.pid", "-s", "/run/monit/monit.state", "quit")
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf // Redirect stderr to the same buffer as stdout
	cmd.Env = append(cmd.Env, futils.ExecEnv()...)

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start sshd: %v", err)
	}
	err = cmd.Wait()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return outputBuf.String(), fmt.Errorf("timed out after 20 seconds")
		}
		return outputBuf.String(), fmt.Errorf("%v failed: %v", ServiceName, err)
	}

	return outputBuf.String(), nil
}
func ReloadMonitWithTimeout() (combinedOutput string, err error) {
	// Create a context with a 20-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel() // Ensure the context is canceled to release resources
	monitBin := futils.FindProgram("monit")
	var outputBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, monitBin, "-c", "/etc/monit/monitrc", "-p", "/run/monit/monit.pid", "-s", "/run/monit/monit.state", "reload")
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf
	cmd.Env = append(cmd.Env, futils.ExecEnv()...)

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start sshd: %v", err)
	}
	err = cmd.Wait()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return outputBuf.String(), fmt.Errorf("timed out after 20 seconds")
		}
		return outputBuf.String(), fmt.Errorf("%v failed: %v", ServiceName, err)
	}

	return outputBuf.String(), nil
}
func ForceStop() bool {
	pid := GetPID()
	duration := 1 * time.Second
	futils.KillProcess(pid)
	if !futils.ProcessExists(pid) {
		return true
	}
	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetPID()
		if !futils.ProcessExists(pid) {
			return true
		}
		futils.KillProcess(pid)
	}

	return false
}
func Stop() bool {
	duration := 1 * time.Second
	pid := GetPID()

	if !futils.ProcessExists(pid) {
		return true
	}
	if GlobalsValues.StopBySystemd(GlobalsValues.SystemDConfig{
		InitdPath:  InitdPath,
		PidPath:    PidPath,
		PidPattern: "monit -c",
	}) {
		return true
	}

	Syslog(fmt.Sprintf("Stopping Monit service PID %d", pid))
	_, _ = StopMonitWithTimeout()

	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetPID()
		if !futils.ProcessExists(pid) {
			return true
		}
	}
	Syslog(fmt.Sprintf("Stopping Monit service PID %d (kill)", pid))
	futils.StopProcess(pid)
	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetPID()
		if !futils.ProcessExists(pid) {
			return true
		}
		futils.StopProcess(pid)
	}
	futils.KillProcess(pid)
	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetPID()
		if !futils.ProcessExists(pid) {
			return true
		}
		futils.KillProcess(pid)
	}
	Syslog(fmt.Sprintf("[ERROR]: Unable to stop Monit service"))
	return false

}
func Syslog(message string) {
	w, err := syslog.New(syslog.LOG_INFO, "monit")
	if err != nil {
		return
	}
	defer func(w *syslog.Writer) {
		_ = w.Close()
	}(w)
	Msg := fmt.Sprintf("[SERVICE] %v", message)
	_ = w.Info(Msg)
	_ = w.Close()
}
func GetPID() int {
	DestBin := futils.FindProgram("monit")
	pid := futils.PIDOFPattern("/run/monit/monit.pid")
	if futils.ProcessExists(pid) {
		return pid
	}
	return futils.PIDOFPattern(DestBin)
}

func Reload() {
	if futils.FileExists("/etc/monit/conf.d/APP_UNBOUND.monitrc") {
		UnboundEnabled := sockets.GET_INFO_INT("UnboundEnabled")
		if UnboundEnabled == 0 {
			futils.DeleteFile("/etc/monit/conf.d/APP_UNBOUND.monitrc")
		}
	}
	futils.DeleteFile("/etc/monit/conf.d/APP_DHCP.monitrc")

	pid := GetPID()
	if !futils.ProcessExists(pid) {
		Start()
		return
	}

	out, err := ReloadMonitWithTimeout()
	if err != nil {
		if strings.Contains(err.Error(), "'/etc/monit/monitrc' is not a file") {
			_ = futils.RmRF("/etc/monit/monitrc")
			_ = os.Remove("/etc/monit/monitrc")
		}

		monitSyslog(fmt.Sprintf("%v Failed to reload service %v [%v]", futils.GetCalleRuntime(), err.Error(), out), false)
		return
	}
	monitSyslog(fmt.Sprintf("%v Success reloading Monit service", futils.GetCalleRuntime()), true)
}
func Restart() {
	Stop()
	Start()
}
func ServiceConfig() articaunix.ServiceOptions {
	DestBin := articaunix.FindProgram("monit")
	state := "-c /etc/monit/monitrc -p /run/monit/monit.pid -s /run/monit/monit.state"

	StartCmdline := fmt.Sprintf("%v -start-monit", ArticaBinary)
	StopCmdLine := fmt.Sprintf("%v -stop-monit", ArticaBinary)
	ReloadCmdLine := fmt.Sprintf("%v %v reload", DestBin, state)
	var opts articaunix.ServiceOptions
	opts.DisableMonitConfig = true
	opts.SystemdRestartAlways = true
	opts.SourceBin = DestBin
	opts.CheckSocket = ""
	opts.MaxFileDesc = 0
	opts.ForcePidFile = false
	opts.ExecRestart = fmt.Sprintf("%v -restart-monit", ArticaBinary)
	opts.ExecStart = StartCmdline
	opts.ExecStop = StopCmdLine
	opts.ExecReload = ReloadCmdLine
	opts.SystemdWatchdog = false
	opts.InitdPath = InitdPath
	opts.Pidfile = PidPath
	opts.KillMode = true
	opts.ServiceName = "Watchodg monitor"
	opts.ProcessPattern = "monit -c \\/etc\\/monit\\/monitrc"
	opts.ProcessNoWait = true
	opts.TokenEnabled = ""
	opts.StartCmdLine = StartCmdline
	opts.SyslogConfPath = ""
	opts.MonitName = "APP_MONIT"
	return opts
}
func monitSyslog(Action string, Success bool) {

	w, err := syslog.New(syslog.LOG_INFO, "monit")
	if err != nil {
		return
	}
	defer func(w *syslog.Writer) {
		err := w.Close()
		if err != nil {

		}
	}(w)

	Result := "FAILED"
	if Success {
		log.Info().Msg(Action)
		Result = "SUCCESS"
	} else {
		log.Warn().Msg(Action)
	}
	Msg := fmt.Sprintf("'%v' %v: %v [%v]", "APP_MONIT", Action, "Monit Service (via restapi)", Result)
	_ = w.Info(Msg)
	_ = w.Close()
}
func cronMonit() {
	futils.DeleteFile("/etc/monit/conf.d/APP_ZARAFASERVER.monitrc")
	futils.DeleteFile("/etc/monit/conf.d/APP_ZARAFAGATEWAY.monitrc")
	futils.DeleteFile("/etc/monit/conf.d/APP_ZARAFAAPACHE.monitrc")
	futils.DeleteFile("/etc/monit/conf.d/APP_ZARAFAWEB.monitrc")
	futils.DeleteFile("/etc/monit/conf.d/APP_ZARAFASPOOLER.monitrc")
	futils.DeleteFile("/etc/monit/conf.d/APP_ZARAFADB.monitrc")
	futils.DeleteFile("/etc/monit/conf.d/APP_SYSLOGDB.monitrc")
	if !futils.FileExists("/etc/monit/templates/rootbin") {
		return
	}
	var f []string
	f = append(f, "check process crond with pidfile /run/crond.pid")
	f = append(f, "   group system")
	f = append(f, "   group crond")
	f = append(f, "   start program = \"/etc/init.d/cron start\"")
	f = append(f, "   stop  program = \"/etc/init.d/cron stop\"")
	f = append(f, "   if 5 restarts with 5 cycles then timeout")
	f = append(f, "   depend cron_bin")
	f = append(f, "   depend cron_rc")
	f = append(f, "   depend cron_spool")
	f = append(f, "")
	f = append(f, " check file cron_bin with path /usr/sbin/cron")
	f = append(f, "   group crond")
	f = append(f, "   include /etc/monit/templates/rootbin")
	f = append(f, "")
	f = append(f, " check file cron_rc with path \"/etc/init.d/cron\"")
	f = append(f, "   group crond")
	f = append(f, "   include /etc/monit/templates/rootbin")
	f = append(f, "")
	f = append(f, " check directory cron_spool with path /var/spool/cron/crontabs")
	f = append(f, "   group crond")
	f = append(f, "   if failed permission 1730 then unmonitor")
	f = append(f, "   if failed uid root        then unmonitor")
	f = append(f, "   if failed gid crontab     then unmonitor")
	_ = futils.FilePutContents("/etc/monit/conf.d/cron.monitrc", strings.Join(f, "\n"))

}
func syslogConf() {
	var f []string

	tfile := SyslogConfPath
	logfile := "/var/log/monit.log"

	conf := logsink.LocalFileConf{File: logfile, AsyncWriting: true}

	f = append(f, "if  ($programname =='monit') then {")
	f = append(f, "\tif ( $msg contains \"Checking summary\") then {")
	f = append(f, "\t\tstop")
	f = append(f, "\t}")
	f = append(f, logsink.BuildRemoteSyslogs("monit", "monit"))
	f = append(f, logsink.BuildLocalFilelog(conf))
	f = append(f, "	& stop")
	f = append(f, "}")

	md51 := futils.MD5File(tfile)
	_ = futils.FilePutContents(tfile, strings.Join(f, "\n"))
	md52 := futils.MD5File(tfile)
	if md51 == md52 {
		return
	}
	log.Info().Msgf("%v Restarting syslog service", futils.GetCalleRuntime())
	go logsink.Restart()

}

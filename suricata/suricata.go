package suricata

import (
	"CacheMem"
	"GlobalsValues"
	"PFRing"
	"SuriConf"
	"SuriTables"
	"SuricataService"
	"Update"
	"apostgres"
	"articaunix"
	"database/sql"
	"fmt"
	"futils"
	"logsink"
	"monit"
	"notifs"
	"regexp"
	"sockets"
	"strings"
	"suricata/SuricataTools"
	"time"

	"github.com/rs/zerolog/log"
)

const InitdPath = "/etc/init.d/suricata"
const SyslogConfPath = "/etc/rsyslog.d/00_suricata.conf"
const MonitFile = "/etc/monit/conf.d/APP_SURICATA.monitrc"
const ArticaBinary = GlobalsValues.ArticaBinary
const MonitName = "APP_SURICATA"
const PidPath = SuricataService.PidPath
const ProgressF = "suricata.progress"
const MainBinary = "/usr/bin/suricata"
const ServiceName = "IDS Daemon"
const Duration = 1 * time.Second
const TokenEnabled = "EnableSuricata"
const TokenInstalled = "SURICATA_INSTALLED"
const TokenVersion = "SURICATA_VERSION"
const StartProgram = ArticaBinary + " -start-ids"
const StopProgram = ArticaBinary + " -stop-ids"

var RegexVersion = regexp.MustCompile(`version\s+([0-9\.]+)`)

type SuricataConfig struct {
	EnableSuricata int64
	BinaryPath     string
}

func Uninstall() {
	sockets.SET_INFO_INT(TokenEnabled, 0)
	notifs.BuildProgress(50, "{uninstall_service}", ProgressF)
	Conf := ServiceConfig()
	articaunix.ServiceUninstall(Conf)
	futils.DeleteFile(MonitFile)
	futils.DeleteFile("/etc/rsyslog.d/00_suricata.conf")
	logsink.Restart()
	sockets.SET_INFO_INT("SuricataDepmod", 0)
	sockets.SET_INFO_INT("SuricataPfRing", 0)
	sockets.SET_INFO_INT("HyperScanNotCompiled", 0)
	monit.Reload()
	notifs.BuildProgress(100, "{uninstall_service} {success}", ProgressF)
	db, err := apostgres.SQLConnect()
	if err != nil {
		return
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	_, _ = db.Exec("TRUNCATE TABLE suricata_events")

}
func Install() {
	notifs.BuildProgress(10, "{installing}", ProgressF)
	sockets.SET_INFO_INT(TokenEnabled, 1)
	notifs.BuildProgress(50, "{install_service}", ProgressF)
	Conf := ServiceConfig()
	log.Info().Msgf("%v Installing "+ServiceName, futils.GetCalleRuntime())
	articaunix.EnableService(Conf)
	notifs.BuildProgress(60, "{install_service}", ProgressF)
	notifs.BuildProgress(80, "{install_service}", ProgressF)
	CreateMonitService()
	_ = SuriConf.Build()
	go func() {
		Update.Run()
	}()
	//exec.openldap.upgrade.php --cve
	go func() {
		_ = Start()

	}()
	notifs.BuildProgress(100, "{install_service} {success}", ProgressF)

}
func CheckStartup() {
	Enabled := sockets.GET_INFO_INT(TokenEnabled)
	if Enabled == 0 {
		Uninstall()
		return
	}
	pid := GetPID()
	if futils.ProcessExists(pid) {
		return
	}
	log.Warn().Msgf("%v Suricata not running, Start it..", futils.GetCalleRuntime())
	err := Start()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}
}
func CreateMonitService() {
	var f []string

	f = append(f, fmt.Sprintf("check process %v with pidfile %v", MonitName, PidPath))
	f = append(f, fmt.Sprintf("\tstart program = \"%v\"", StartProgram))
	f = append(f, fmt.Sprintf("\tstop program = \"%v\"", StopProgram))
	f = append(f, "")
	md51 := futils.MD5File(MonitFile)
	_ = futils.FilePutContents(MonitFile, strings.Join(f, "\n"))
	md52 := futils.MD5File(MonitFile)
	if md51 == md52 {
		return
	}
	log.Info().Msgf("%v Reloading the Monit service", futils.GetCalleRuntime())
	monit.Reload()
}
func Start() error {
	if !futils.FileExists(MainBinary) {
		return fmt.Errorf("%v not found", MainBinary)
	}
	Enabled := sockets.GET_INFO_INT(TokenEnabled)

	if futils.FileExists("/etc/monit/conf.d/APP_SURICATA_TAIL.monitrc") {
		futils.DeleteFile("/etc/monit/conf.d/APP_SURICATA_TAIL.monitrc")
	}

	if Enabled == 0 {
		Uninstall()
		return fmt.Errorf("disabled feature")
	}

	PFRing.Check()
	return SuricataService.Start()
}

func GetVersion() string {
	if !futils.FileExists(MainBinary) {
		log.Debug().Msgf("%v %v no such file", futils.GetCalleRuntime(), MainBinary)
		sockets.SET_INFO_INT(TokenInstalled, 0)
		sockets.SET_INFO_INT(TokenEnabled, 0)
		sockets.SET_INFO_STR(TokenVersion, "0.0.0")
		return "0.0.0"
	}
	sockets.SET_INFO_INT(TokenInstalled, 1)

	val := CacheMem.GetStringFunc()
	if len(val) > 1 {
		sockets.SET_INFO_STR(TokenVersion, val)
		return val
	}

	cmdline := fmt.Sprintf("%v -V", MainBinary)
	log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), cmdline)
	err, out := futils.ExecuteShell(fmt.Sprintf("%v -V", MainBinary))

	if err != nil {
		tb := strings.Split(out, "\n")
		for _, line := range tb {
			if strings.Contains(line, "loading shared libraries: libpcap") {
				if !futils.FileExists("/etc/ld.so.conf.d/local.lib.conf") {
					_ = futils.FilePutContents("/etc/ld.so.conf.d/local.lib.conf", "/usr/local/lib\n")
				}
				_ = futils.RunLdconfig("")
			}

			log.Error().Msgf("%v [%v]", futils.GetCalleRuntime(), line)
		}

		log.Error().Msgf("%v %v [%v]", futils.GetCalleRuntime(), err.Error(), out)
	}

	tb := strings.Split(out, "\n")
	for _, v := range tb {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		ver := futils.RegexGroup1(RegexVersion, v)
		if len(ver) > 1 {
			CacheMem.SetStringFunc(ver)
			sockets.SET_INFO_STR(TokenVersion, ver)
			return ver
		}
		log.Debug().Msgf("%v %v no matches", futils.GetCalleRuntime(), v)

	}
	return "0.0.0"
}
func CheckSuricataInMemory() bool {
	Conf := Config()

	if Conf.EnableSuricata == 0 {
		pid := GetPID()
		if futils.ProcessExists(pid) {
			Cmdline := futils.ProcessCommandLine(pid)
			text := fmt.Sprintf("Detected PID %d with command line %v", pid, Cmdline)
			notifs.SquidAdminMysql(1, "Stopping IDS service ( not enabled)", text, "CheckSuricataInMemory", 15)
			return Stop()
		}
		return true
	}

	return true

}
func Config() SuricataConfig {
	var Conf SuricataConfig
	Conf.EnableSuricata = sockets.GET_INFO_INT("EnableSuricata")
	Conf.BinaryPath = futils.FindProgram("suricata")
	return Conf
}
func ServiceConfig() articaunix.ServiceOptions {
	var opts articaunix.ServiceOptions
	opts.SourceBin = MainBinary
	opts.CheckSocket = ""
	opts.ExecStart = StartProgram
	opts.ExecStop = StopProgram
	opts.ExecRestart = fmt.Sprintf("%v -restart-ids", ArticaBinary)
	opts.ExecUninstall = fmt.Sprintf("%v -uninstall-ids", ArticaBinary)
	opts.ExecInstall = fmt.Sprintf("%v -install-ids", ArticaBinary)
	opts.InitdPath = InitdPath
	opts.Pidfile = PidPath
	opts.ServiceName = ServiceName
	opts.ProcessPattern = MainBinary
	opts.AmbientCapabilities = true
	opts.PrivateDevices = true
	opts.CapabilityBoundingSet = true
	opts.RestrictAddressFamilies = true
	opts.PrivateTmp = true
	cmdline := opts.ExecStart
	opts.StartCmdLine = cmdline
	opts.DisableMonitConfig = true
	opts.MonitName = MonitName
	return opts
}

func RemoveOlds() {

	if futils.FileExists("/etc/init.d/suricata-tail") {
		articaunix.RemoveServiceINIT("/etc/init.d/suricata-tail")
		log.Warn().Msgf("%v Restart Artica Status service", futils.GetCalleRuntime())
		_, _ = futils.ExecuteShell("/etc/init.d/artica-status restart --force")

		pid := futils.PIDOFPattern("suricata-tail --")
		if futils.ProcessExists(pid) {
			futils.KillProcess(pid)
		}
		futils.DeleteFile("/etc/init.d/suricata-tail")
	}

	if futils.FileExists(MonitFile) {
		FindPHPFPM := false
		tb := strings.Split(futils.FileGetContents(MonitFile), "\n")
		for _, line := range tb {
			if strings.Contains(line, "artica-phpfpm-service") {
				FindPHPFPM = true
				break
			}
		}
		if !FindPHPFPM {
			Install()
			log.Warn().Msgf("%v Restart Monitor daemon service", futils.GetCalleRuntime())
			monit.Restart()
		}
	}

}

// A FAIRE:
// /usr/share/artica-postfix/exec.suricata-fw.php --build
// /usr/share/artica-postfix/exec.suricata.updates.php
// /usr/share/artica-postfix/exec.suricata.hourly.php --purge
// /usr/share/artica-postfix/exec.suricata-fw.php --purge
// /usr/share/artica-postfix/exec.suricata.dashboard.php

func UnloadPFring() bool {

	if !futils.IsModulesLoaded("pf_ring") {
		return true
	}

	rmmod := futils.FindProgram("rmmod")
	cmdline := fmt.Sprintf("%v pf_ring", rmmod)

	err, out := futils.ExecuteShell(cmdline)
	if err != nil {
		log.Error().Msgf("%v [%v]", futils.GetCalleRuntime(), out)
		return true

	}

	for i := 0; i < 5; i++ {
		if !futils.IsModulesLoaded("pf_ring") {
			break
		}
		_, _ = futils.ExecuteShell(cmdline)
		time.Sleep(1 * time.Second)
	}
	return true

}
func GetPID() int {
	return SuricataTools.GetPID()
}
func Stop() bool {

	pid := GetPID()

	if !futils.ProcessExists(pid) {
		log.Debug().Msgf("%v Already stopped", futils.GetCalleRuntime())
		return UnloadPFring()
	}
	log.Warn().Msgf("%v kill Pid %d", futils.GetCalleRuntime(), pid)
	futils.KillSmoothProcess(pid)

	for i := 0; i < 5; i++ {
		time.Sleep(Duration)
		pid := GetPID()
		if !futils.ProcessExists(pid) {
			log.Info().Msgf("%v Stopping.. %vc [SUCCESS]", futils.GetCalleRuntime(), ServiceName)
			return UnloadPFring()
		}
		log.Info().Msgf("%v Stopping...Redis server pid %v %v/5", futils.GetCalleRuntime(), pid, i)
		futils.StopProcess(pid)
	}

	pid = GetPID()

	if !futils.ProcessExists(pid) {
		return UnloadPFring()
	}
	return false

}
func Status(Watchdog bool) string {

	if Watchdog {
		RemoveOlds()
		SuriTables.Check()
	}

	var ini articaunix.StatusIni
	var f []string
	opts := ServiceConfig()
	ini.ProductCodeName = MonitName
	ini.Installed = int(sockets.GET_INFO_INT(TokenInstalled))
	ini.Pidpath = opts.Pidfile
	ini.MemoryBin = opts.SourceBin
	ini.TokenEnabled = TokenEnabled
	ini.WatchdogMode = Watchdog
	ini.Debug = false
	ini.CheckSockets = opts.CheckSocket
	ini.StartCmdLine = opts.ExecStart
	ini.InitdPath = opts.InitdPath
	ini.UninstallCmdLine = opts.ExecUninstall
	ini.InstallCmdLine = opts.ExecInstall
	f = append(f, articaunix.BuildIni(ini))
	return strings.Join(f, "\n")
}
func Restart() {
	notifs.BuildProgress(15, "{restarting} {stopping}", ProgressF)
	if !Stop() {
		notifs.BuildProgress(110, "{restarting} {stopping} {failed}", ProgressF)
		return
	}
	notifs.BuildProgress(50, "{starting}", ProgressF)
	err := Start()
	if err != nil {
		notifs.BuildProgress(110, err.Error(), ProgressF)
		return
	}
	notifs.BuildProgress(100, "{restarting} {success}", ProgressF)
}

func Reload() {
	SuricataTools.Reload()

}

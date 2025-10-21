package suricata

import (
	"CacheMem"
	"GlobalsValues"
	"apostgres"
	"articaunix"
	"database/sql"
	"fmt"
	"futils"
	"logsink"
	"monit"
	"notifs"
	"os"
	"path/filepath"
	"regexp"
	"sockets"
	"strings"
	"suricata/SuricataTools"
	"suricata/SuricataUpdates"
	"suricata/suricataConfig"
	"time"

	"github.com/rs/zerolog/log"
)

const InitdPath = "/etc/init.d/suricata"
const SyslogConfPath = "/etc/rsyslog.d/00_suricata.conf"
const MonitFile = "/etc/monit/conf.d/APP_SURICATA.monitrc"
const ArticaBinary = GlobalsValues.ArticaBinary
const MonitName = "APP_SURICATA"
const PidPath = "/run/suricata/suricata.pid"
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
	
	go func() {
		err := SuricataUpdates.Update()
		if err != nil {

		}
	}()
	//exec.openldap.upgrade.php --cve
	go func() {
		err := Start()
		if err != nil {

		}
	}()
	notifs.BuildProgress(100, "{install_service} {success}", ProgressF)

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
	futils.CreateDir("/run/suricata")
	futils.CreateDir("/var/log/suricata")
	futils.Chmod("/usr/share/artica-postfix/bin/sidrule", 0755)
	notifs.BuildProgress(51, "{configuring} ( CheckPFRing )", ProgressF)
	PFRing := CheckPFRing()
	err := suricataConfig.SuricataConfig(PFRing.Enable)
	if err != nil {
		return err
	}
	notifs.BuildProgress(52, "DepMod...", ProgressF)
	SuricataDepmod := sockets.GET_INFO_INT("SuricataDepmod")

	if !futils.FileExists("/etc/ld.so.conf.d/local.lib.conf") {
		_ = futils.FilePutContents("/etc/ld.so.conf.d/local.lib.conf", "/usr/local/lib\n")
		_ = futils.RunLdconfig("")
	}

	if SuricataDepmod == 0 {
		err := futils.RunDepmod()
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		sockets.SET_INFO_INT("SuricataDepmod", 1)
	}
	notifs.BuildProgress(55, "{configuring} PF_RING", ProgressF)

	log.Debug().Msgf("%v Starting suricata PFRing=%d", futils.GetCalleRuntime(), PFRing.Enable)
	if PFRing.Enable == 1 {
		if !futils.FileExists("/etc/modprobe.d/pfring.conf") {
			ldconfig := futils.FindProgram("ldconfig")
			_, _ = futils.ExecuteShell(ldconfig)
		}
		_ = futils.FilePutContents("/etc/modprobe.d/pfring.conf", "options pf_ring transparent_mode=0 min_num_slots=32768 enable_tx_capture=1\n")
		modprobe := futils.FindProgram("modprobe")
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v pf_ring transparent_mode=0 min_num_slots=32768 enable_tx_capture=1", modprobe))
		for i := 0; i < 5; i++ {
			if futils.IsModulesLoaded("pf_ring") {
				break
			}
			_, _ = futils.ExecuteShell(fmt.Sprintf("%v pf_ring transparent_mode=0 min_num_slots=32768 enable_tx_capture=1", modprobe))
			time.Sleep(1 * time.Second)
		}

	}
	if PFRing.Enable == 0 {
		if futils.IsModulesLoaded("pf_ring") {
			rmmod := futils.FindProgram("rmmod")
			_, _ = futils.ExecuteShell(fmt.Sprintf("%v pf_ring", rmmod))
			if futils.FileExists("/etc/modprobe.d/pfring.conf") {
				futils.DeleteFile("/etc/modprobe.d/pfring.conf")
			}
		}
	}
	notifs.BuildProgress(56, "{configuring} ethtool", ProgressF)
	removeOldSuricataLogs()
	ethtool := futils.FindProgram("ethtool")

	if futils.FileExists(ethtool) {
		SuricataInterface := sockets.GET_INFO_STR("SuricataInterface")
		if SuricataInterface == "" {
			SuricataInterface = "eth0"
		}
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v -K %v gro off", ethtool, SuricataInterface))
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v -K %v lro off", ethtool, SuricataInterface))
	}
	setcapBin := futils.FindProgram("setcap")

	_, _ = futils.ExecuteShell(fmt.Sprintf("%v cap_net_raw,cap_net_admin=eip %v", setcapBin, MainBinary))

	cmd := buildSuricataCommand(PFRing.Enable)
	futils.DeleteFile("/run/suricata/suricata.pid")
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	notifs.BuildProgress(57, "{starting}...", ProgressF)
	err, out := futils.ExecuteShell(cmd)
	out = strings.TrimSpace(out)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), out)

	if err != nil {
		log.Error().Msgf("%v Failed to start %v [%v]", futils.GetCalleRuntime(), cmd, err)
		return fmt.Errorf("unable to start %v (%v): [%v]", ServiceName, cmd, out)
	}

	c := 57
	for i := 0; i < 5; i++ {
		c++
		notifs.BuildProgress(c, fmt.Sprintf("{starting}...%d/5", i), ProgressF)
		time.Sleep(Duration)
		pid := GetPID()
		if futils.ProcessExists(pid) {
			log.Info().Msgf("%v Starting...%v [SUCCESS]", futils.GetCalleRuntime(), ServiceName)
			return nil
		}
	}

	return fmt.Errorf("unable to start the %v (%v): [%v]", ServiceName, err, out)

}
func buildSuricataCommand(SuricataPfRing int) string {
	masterbin := futils.FindProgram("suricata")
	var cm []string

	cm = append(cm, masterbin)
	cm = append(cm, "--pidfile", "/run/suricata/suricata.pid")

	if SuricataPfRing == 1 {
		cm = append(cm, "--pfring")
		cm = append(cm, "--pfring-cluster-id=99")
		cm = append(cm, "--pfring-cluster-type=cluster_flow")
	} else {
		cm = append(cm, "--af-packet")
	}

	cm = append(cm, "-D")
	command := strings.Join(cm, " ")

	return command
}
func removeOldSuricataLogs() {
	dirPath := "/var/log/suricata"
	files, err := os.ReadDir(dirPath)
	if err != nil {
		fmt.Printf("Error reading directory: %v\n", err)
		return
	}

	pattern := regexp.MustCompile(`unified2\.alert\.`)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		fileName := file.Name()
		filePath := filepath.Join(dirPath, fileName)
		if pattern.MatchString(fileName) {
			if futils.FileTimeMin(filePath) > 10 {
				futils.DeleteFile(filePath)
			}
		}
	}
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
		suricataConfig.PatchTables()
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
func CheckPFRing() PFringInfo {
	var Mod PFringInfo
	kernel := futils.KernelVersion()
	log.Debug().Msgf("%v kernel version: %v", futils.GetCalleRuntime(), kernel)
	koPath := fmt.Sprintf("/usr/lib/modules/%v/kernel/net/pf_ring/pf_ring.ko", kernel)
	if !futils.FileExists(koPath) {
		Mod.Enable = 0
		log.Warn().Msgf("%v %v no such module...", futils.GetCalleRuntime(), koPath)
		return Mod
	}
	modinfo := futils.FindProgram("modinfo")
	err, out := futils.ExecuteShell(fmt.Sprintf("%s pf_ring", modinfo))
	if err != nil {
		log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), out)
		if strings.Contains(out, "pf_ring not found") {
			err := futils.RunDepmod()
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			}
		}
		modprobe := futils.FindProgram("modprobe")
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v pf_ring transparent_mode=0 min_num_slots=32768", modprobe))
		modinfo := futils.FindProgram("modinfo")
		err, out = futils.ExecuteShell(fmt.Sprintf("%s pf_ring", modinfo))
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), out)
			Mod.Enable = 0
			return Mod
		}

	}
	log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), out)
	Mod, err = parseModuleInfo(out)
	if err != nil {
		Mod.Enable = 0
		return Mod
	}
	Mod.Enable = 1
	return Mod
}
func parseModuleInfo(data string) (PFringInfo, error) {
	lines := strings.Split(data, "\n")
	module := PFringInfo{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "filename":
			module.Filename = value
		case "alias":
			module.Alias = value
		case "version":
			module.Version = value
		case "description":
			module.Description = value
		case "author":
			module.Author = value
		case "license":
			module.License = value
		case "srcversion":
			module.SrcVersion = value
		case "depends":
			module.Depends = value
		case "retpoline":
			module.Retpoline = value
		case "name":
			module.Name = value
		case "vermagic":
			module.Vermagic = value
		case "parm":
			if strings.Contains(value, "Min number of ring slots") {
				module.MinNumSlots = value
			} else if strings.Contains(value, "Perfect rules hash size") {
				module.PerfectRulesHashSize = value
			} else if strings.Contains(value, "capture outgoing packets") {
				module.EnableTxCapture = value
			} else if strings.Contains(value, "handle fragments") {
				module.EnableFragCoherence = value
			} else if strings.Contains(value, "enable IP defragmentation") {
				module.EnableIPDefrag = value
			} else if strings.Contains(value, "keep vlan stripping") {
				module.KeepVlanOffload = value
			} else if strings.Contains(value, "run at full speed") {
				module.QuickMode = value
			} else if strings.Contains(value, "force ring locking") {
				module.ForceRingLock = value
			} else if strings.Contains(value, "enable PF_RING debug") {
				module.EnableDebug = value
			} else if strings.Contains(value, "(deprecated)") {
				module.TransparentModeDeprecated = value
			}
		}
	}

	return module, nil
}
func Reconfigure() {
	notifs.BuildProgress(30, "{reconfiguring}", ProgressF)
	md51 := futils.MD5File("/etc/suricata/suricata.yaml")
	notifs.BuildProgress(50, "{reconfiguring}", ProgressF)
	PFRing := CheckPFRing()
	err := suricataConfig.SuricataConfig(PFRing.Enable)
	if err != nil {
		notifs.BuildProgress(110, err.Error(), ProgressF)
		return
	}
	md52 := futils.MD5File("/etc/suricata/suricata.yaml")
	if md51 == md52 {
		notifs.BuildProgress(100, "{reconfiguring} {success}", ProgressF)
		return
	}
	notifs.BuildProgress(60, "{reconfiguring} {reloading}", ProgressF)
	SuricataTools.Reload()
	notifs.BuildProgress(100, "{restarting} {success}", ProgressF)
}
func Reload() {
	SuricataTools.Reload()

}

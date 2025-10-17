package articaunix

import (
	"GlobalsValues"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"futils"
	"io"
	"log/syslog"
	"net"
	"notifs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sockets"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/process"
)

type ServiceOptions struct {
	ExecStart               string
	ExecStartPre            string
	ExecStop                string
	ExecRestart             string
	DefaultTimeoutStopSec   int
	ExecReload              string
	SystemdWatchdog         bool
	SystemdRestartAlways    bool
	KillMode                bool
	RunAsUser               string
	RunAsGroup              string
	ExecStatus              string
	ExecInstall             string
	ExecUninstall           string
	ExecReconfigure         string
	CheckSocket             string
	HomeDir                 string
	InitdPath               string
	Pidfile                 string
	RemovePIDBefore         bool
	StartCmdLine            string
	SourceBin               string
	Forking                 bool
	SyslogConfPath          string
	MonitName               string
	CPUQuota                int
	CPUShares               int
	DisableMonitConfig      bool
	ServiceName             string
	ProcessPattern          string
	AmbientCapabilities     bool
	AllwaysON               bool
	PrivateDevices          bool
	SystemdSilent           bool
	RestrictAddressFamilies bool
	PrivateTmp              bool
	ProcessNoWait           bool
	NONotifyFailed          bool
	MallocArenaMax          int
	DefaultLimitNOFILE      bool
	Environements           []string
	CapabilityBoundingSet   bool
	TokenEnabled            string
	ForceEnabled            bool
	StartAfter              string
	StopAfter               string
	MaxFileDesc             int64
	ForcePidFile            bool
	Ulimit                  bool
	ExecStartPrePHP         string
	MonitorProto            string
	MonitorIP               string
	MonitorPort             int
	KillPorts               int
	Out                     bool
}
type StopOptions struct {
	PidFile        string
	ServiceName    string
	ProcessPattern string
	StartAfter     string
}
type ServiceStartStopOptions struct {
	PidFile          string
	ServiceName      string
	ProcessPattern   string
	StartAfter       string
	ProcessNoWait    bool
	BinaryPath       string
	CheckSocket      string
	StartCommandLine string
	KillPorts        int
	MaxFileDesc      int64
	Out              bool
	ForcePidFile     bool
	RemovePIDBefore  bool
	MonitName        string
	TokenEnabled     string
	ForceEnabled     bool
}

func ServiceStartStopOptionsFromServiceOptions(conf ServiceOptions) ServiceStartStopOptions {
	var Final ServiceStartStopOptions
	Final.PidFile = conf.Pidfile
	Final.ServiceName = conf.ServiceName
	Final.ProcessPattern = conf.ProcessPattern
	Final.BinaryPath = conf.ProcessPattern
	Final.StartCommandLine = conf.StartCmdLine
	Final.CheckSocket = conf.CheckSocket
	Final.Out = conf.Out
	Final.KillPorts = conf.KillPorts
	Final.MaxFileDesc = conf.MaxFileDesc
	Final.ForcePidFile = conf.ForcePidFile
	Final.ProcessNoWait = conf.ProcessNoWait
	Final.MonitName = conf.MonitName
	Final.RemovePIDBefore = conf.RemovePIDBefore
	Final.ForceEnabled = conf.ForceEnabled
	return Final
}
func isUnixSocketAvailable(socketPath string) bool {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
func FileExists(spath string) bool {
	if _, err := os.Stat(spath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}
func StopWatchDogs() {
	notifs.SquidAdminMysql(1, fmt.Sprintf("Stopping watchdogs for rebooting"), "", futils.GetCalleRuntime(), 129)
	_, _ = futils.ExecuteShell("/etc/init.d/monit stop")
	_, _ = futils.ExecuteShell("/etc/init.d/cron stop")
	_, _ = futils.ExecuteShell("/etc/init.d/artica-ad-watchdog stop")

}
func StartWatchdogs() {
	_, _ = futils.ExecuteShell("/etc/init.d/monit start")
	_, _ = futils.ExecuteShell("/etc/init.d/cron start")
	_, _ = futils.ExecuteShell("/etc/init.d/artica-ad-watchdog start")

}
func Reboot() {

	lockFile := "/etc/artica-postfix/GrubDebian5.lock"

	if futils.FileExists(lockFile) {
		notifs.SquidAdminMysql(0, fmt.Sprintf("unable to Reboot the system - "+lockFile), "", futils.GetCalleRuntime(), 129)
		return
	}

	notifs.SquidAdminMysql(0, fmt.Sprintf("Rebooting the system!"), "", futils.GetCalleRuntime(), 129)
	StopWatchDogs()
	systemctl := futils.FindProgram("systemctl")
	if futils.FileExists(systemctl) {
		err, out := futils.ExecuteShell(fmt.Sprintf("%v reboot", systemctl))
		if err != nil {
			notifs.SquidAdminMysql(0, fmt.Sprintf("failed Rebooting the system!"), out, futils.GetCalleRuntime(), 129)
			log.Error().Msgf("%v Reboot Failed! %v", futils.GetCalleRuntime(), out)
			syscall.Sync()
			_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
			go StartWatchdogs()
			return
		}

		return

	}

	syscall.Sync()
	err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
	if err != nil {
		notifs.SquidAdminMysql(0, fmt.Sprintf("Failed to reboot: %v", err.Error()), err.Error(), futils.GetCalleRuntime(), 129)
		log.Error().Msg(fmt.Sprintf("Failed to reboot: %v", err.Error()))
		go StartWatchdogs()
		return
	}

}
func ForceReboot() {
	lockFile := "/etc/artica-postfix/GrubDebian5.lock"

	if futils.FileExists(lockFile) {
		notifs.SquidAdminMysql(0, fmt.Sprintf("unable to Reboot the system - "+lockFile), "", futils.GetCalleRuntime(), 129)
		return
	}

	// Sync the filesystem to attempt to flush filesystem buffers
	syscall.Sync()

	// Force reboot the system
	err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART2)
	if err != nil {
		notifs.SquidAdminMysql(0, fmt.Sprintf("Failed to force reboot: %v", err.Error()), err.Error(), futils.GetCalleRuntime(), 129)
		log.Error().Msg(fmt.Sprintf("Failed to force reboot: %v", err.Error()))
	}
	notifs.SquidAdminMysql(0, fmt.Sprintf("Force Rebooting the system!"), "", "articaunix.reboot", 149)
}
func FilePutContents(filename string, data string) error {
	return os.WriteFile(filename, []byte(data), 0644)
}
func ExecuteShell(CommandLine string) error {
	cmd := exec.Command("/usr/bin/bash", "-c", CommandLine)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v [%v]", err.Error(), string(out))
	}
	return nil
}
func Basename(path string) string {
	return filepath.Base(path)
}
func DirectoryExists(path string) bool {
	fileInfo, err := os.Stat(path)

	if err != nil {
		return false
	}

	if fileInfo.IsDir() {
		return true
	}
	return false
}
func EnableMonit(opts ServiceOptions) {
	if opts.DisableMonitConfig {
		return
	}
	if len(opts.MonitName) < 3 {
		return
	}
	if len(opts.Pidfile) < 3 {
		return
	}
	var f []string
	finalFile := fmt.Sprintf("/etc/monit/conf.d/%v.monitrc", opts.MonitName)
	f = append(f, fmt.Sprintf("check process %v with pidfile %v", opts.MonitName, opts.Pidfile))
	f = append(f, fmt.Sprintf("\tstart program = \"%v\"", opts.ExecStart))
	f = append(f, fmt.Sprintf("\tstop program = \"%v\"", opts.ExecStop))
	var MonitProto []string
	if len(opts.MonitorIP) > 4 {
		MonitProto = append(MonitProto, fmt.Sprintf("\tif failed host %v", opts.MonitorIP))
		if opts.MonitorPort > 0 {
			MonitProto = append(MonitProto, fmt.Sprintf("\tport %d IPV4", opts.MonitorPort))
		}
		if opts.MonitorProto == "dns" {
			MonitProto = append(MonitProto, fmt.Sprintf("\ttype udp protocol dns then restart"))
		}

	}
	if len(MonitProto) > 0 {
		f = append(f, strings.Join(MonitProto, ""))
	}

	f = append(f, fmt.Sprintf("\tif 5 restarts within 5 cycles then timeout"))
	f = append(f, "")
	Md51 := FileMD5(finalFile)
	_ = filePutContents(finalFile, strings.Join(f, "\n"))
	Md52 := FileMD5(finalFile)
	if Md52 == Md51 {
		return
	}
	monitReload()
}
func monitReload() {
	DestBin := futils.FindProgram("monit")
	state := "-c /etc/monit/monitrc -p /run/monit/monit.pid -s /run/monit/monit.state"
	ReloadCmdline := fmt.Sprintf("%v %v reload", DestBin, state)
	err, out := ServiceExecuteShell(ReloadCmdline)
	if err != nil {
		if strings.Contains(err.Error()+" "+out, "'/etc/monit/monitrc' is not a file") {
			_ = futils.RmRF("/etc/monit/monitrc")
			_ = os.Remove("/etc/monit/monitrc")
		}

		return
	}

}
func RemoveServiceINIT(InitdPath string) {
	if fileExists(InitdPath) {
		_, _ = ServiceExecuteShell(fmt.Sprintf("%v stop", InitdPath))
	}

	program := Basename(InitdPath)
	if FileExists("/lib/systemd/systemd-sysv-install") {
		pid := PIDOFPattern(fmt.Sprintf("systemd-sysv-install disable %v", program))
		if pid == 0 {
			_, _ = ServiceExecuteShell(fmt.Sprintf("/lib/systemd/systemd-sysv-install disable %v", program))
		}
	}
	if FileExists("/usr/sbin/update-rc.d") {
		_, _ = ServiceExecuteShell(fmt.Sprintf("/usr/sbin/update-rc.d -f %v", program))
	}
	if FileExists("/usr/sbin/chkconfig") {
		_, _ = ServiceExecuteShell(fmt.Sprintf("/usr/sbin/chkconfig --del %v", program))
	}
	if FileExists(InitdPath) {
		_ = os.Remove(InitdPath)
	}

}
func ServiceUninstall(opts ServiceOptions) {

	if len(opts.InitdPath) < 3 {
		return
	}

	RemoveServiceINIT(opts.InitdPath)
	program := Basename(opts.InitdPath)
	SystemDTarget := fmt.Sprintf("/etc/systemd/system/%v.service", program)

	if FileExists(SystemDTarget) {
		_ = os.Remove(SystemDTarget)
	}

	if len(opts.TokenEnabled) > 3 {
		sockets.SET_INFO_INT(opts.TokenEnabled, 0)
	}
	if len(opts.SyslogConfPath) > 0 {
		if FileExists(opts.SyslogConfPath) {
			_ = os.Remove(opts.SyslogConfPath)
			_ = ExecuteShell("/etc/init.d/rsyslog restart")
		}
	}
	if len(opts.MonitName) > 3 {
		PossibleMonitFile := fmt.Sprintf("/etc/monit/conf.d/%v.monitrc", opts.MonitName)
		if FileExists(PossibleMonitFile) {
			_ = os.Remove(PossibleMonitFile)
			DestBin := FindProgram("monit")
			state := "-c /etc/monit/monitrc -p /run/monit/monit.pid -s /run/monit/monit.state"
			ReloadCmdline := fmt.Sprintf("%v %v reload", DestBin, state)
			_ = ExecuteShell(ReloadCmdline)
		}
	}

}
func EnableService(opts ServiceOptions) {
	var f []string

	if len(opts.TokenEnabled) > 3 {
		sockets.SET_INFO_INT(opts.TokenEnabled, 1)
	}

	var HelpCmd []string
	MD51 := FileMD5(opts.InitdPath)

	program := Basename(opts.InitdPath)
	f = append(f, "#!/bin/sh")
	f = append(f, "### BEGIN INIT INFO")
	f = append(f, fmt.Sprintf("# Provides:         %v", program))
	f = append(f, "# Required-Start:    $local_fs $syslog")
	f = append(f, "# Required-Stop:     $local_fs $syslog")
	f = append(f, "# Should-Start:")
	f = append(f, "# Should-Stop:")
	f = append(f, "# Default-Start:     3 4 5")
	f = append(f, "# Default-Stop:      0 1 6")
	f = append(f, fmt.Sprintf("# Short-Description: %v", program))
	f = append(f, "# chkconfig: - 80 75")
	f = append(f, fmt.Sprintf("# description: %v", program))
	f = append(f, "# Modified by: Artica")
	f = append(f, "### END INIT INFO")

	HelpCmd = append(HelpCmd, "stop")
	HelpCmd = append(HelpCmd, "start")
	HelpCmd = append(HelpCmd, "restart")

	ChmodExec := opts.ExecStart
	if strings.Contains(opts.ExecStart, " ") {
		tb := strings.Split(opts.ExecStart, " ")
		ChmodExec = tb[0]
	}

	f = append(f, "case \"$1\" in")
	f = append(f, " start)")
	if opts.MallocArenaMax > 0 {
		f = append(f, fmt.Sprintf("\texport MALLOC_ARENA_MAX=%d || true", opts.MallocArenaMax))
	}
	if len(opts.Environements) > 0 {
		for _, Env := range opts.Environements {
			tb := strings.Split(Env, "=")
			f = append(f, fmt.Sprintf("\t%v", Env))
			if len(tb) > 0 {
				f = append(f, fmt.Sprintf("\texport %v || true", tb[0]))
			}
		}
	}

	if opts.Ulimit {
		f = append(f, fmt.Sprintf("\tulimit -s unlimited"))
	}

	f = append(f, fmt.Sprintf(" echo \"Starting service %v\"", program))
	if len(opts.ExecStartPre) > 3 {
		f = append(f, fmt.Sprintf("\t%v", opts.ExecStartPre))
	}
	if len(opts.ExecStartPrePHP) > 3 {
		f = append(f, fmt.Sprintf("\t%v /usr/share/artica-postfix/%v", LocatePHP5bin(), opts.ExecStartPrePHP))
	}

	if strings.Contains(opts.ExecStart, "artica-phpfpm-service") {
		f = append(f, opts.ExecStart)
	} else {
		f = append(f, fmt.Sprintf("\t/usr/bin/nohup %v >/dev/null 2>&1 &", opts.ExecStart))
	}

	f = append(f, "    ;;")
	f = append(f, "")
	f = append(f, "  stop)")
	f = append(f, fmt.Sprintf(" echo \"Stopping service %v\"", program))
	f = append(f, fmt.Sprintf("    %v", opts.ExecStop))
	f = append(f, "    ;;")
	f = append(f, "")
	f = append(f, " restart)")
	f = append(f, fmt.Sprintf("\techo \"Restarting service %v\"", program))

	if len(opts.ExecRestart) > 3 {
		if strings.Contains(opts.ExecRestart, "artica-phpfpm-service") {
			f = append(f, fmt.Sprintf("\t%v", opts.ExecRestart))
		} else {
			f = append(f, fmt.Sprintf("\t/usr/bin/nohup %v >/dev/null 2>&1 &", opts.ExecRestart))
		}
	} else {
		f = append(f, fmt.Sprintf("\techo \"Stopping service %v\"", program))
		f = append(f, fmt.Sprintf("\t/usr/bin/chmod 0755 %v || true", ChmodExec))
		f = append(f, fmt.Sprintf("\t%v", opts.ExecStop))
		f = append(f, fmt.Sprintf("\techo \"Starting service %v\"", program))
		f = append(f, fmt.Sprintf("\t/usr/bin/chmod 0755 %v || true", ChmodExec))
		if strings.Contains(opts.ExecStart, "artica-phpfpm-service") {
			f = append(f, "\t"+opts.ExecStart)
		} else {
			f = append(f, fmt.Sprintf("\t/usr/bin/nohup %v >/dev/null 2>&1 &", opts.ExecStart))
		}
	}

	f = append(f, "\t;;")
	f = append(f, "")
	if len(opts.ExecStatus) > 3 {
		HelpCmd = append(HelpCmd, "status")
		f = append(f, " status)")
		f = append(f, fmt.Sprintf("    %v", opts.ExecStatus))
		f = append(f, "    ;;")
	}
	f = append(f, "")
	if len(opts.ExecReconfigure) > 3 {
		HelpCmd = append(HelpCmd, "reconfigure")
		f = append(f, " reconfigure)")
		f = append(f, fmt.Sprintf("    %v", opts.ExecReconfigure))
		f = append(f, "    ;;")
	}
	if len(opts.ExecReload) > 3 {
		HelpCmd = append(HelpCmd, "reload")
		f = append(f, " reload)")
		f = append(f, fmt.Sprintf("    %v", opts.ExecReload))
		f = append(f, "    ;;")
	}

	f = append(f, "")
	f = append(f, "  *)")
	f = append(f, fmt.Sprintf("    echo \"Usage: $0 {%v} (+ '--verbose' for more infos)\"", strings.Join(HelpCmd, "|")))
	f = append(f, "    exit 1")
	f = append(f, "    ;;")
	f = append(f, "esac")
	f = append(f, "exit 0\n")
	_ = FilePutContents(opts.InitdPath, strings.Join(f, "\n"))
	_ = os.Chmod(opts.InitdPath, 0755)
	MD52 := FileMD5(opts.InitdPath)
	EnableMonit(opts)

	if MD51 != MD52 {
		if FileExists("/usr/sbin/update-rc.d") {
			_ = ExecuteShell(fmt.Sprintf("/usr/sbin/update-rc.d -f %v defaults >/dev/null 2>&1", program))

		}

		if FileExists("/sbin/chkconfig") {
			_ = ExecuteShell(fmt.Sprintf("/sbin/chkconfig --add %v >/dev/null 2>&1", program))
			_ = ExecuteShell(fmt.Sprintf("/sbin/chkconfig --level 345 %v on >/dev/null 2>&1", program))
		}
	}

	EnableSystemdService(opts)

}
func allLocalIPs() []string {
	var ips []string
	EnableipV6 := sockets.GET_INFO_INT("EnableipV6")
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	// Iterate over all interfaces
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return ips
		}

		// Iterate over all addresses for the interface
		for _, addr := range addrs {
			var ip net.IP

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Append IP to slice, excluding loopback and undefined addresses
			if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				if EnableipV6 == 0 {
					if isIPv6(ip.String()) {
						continue
					}
				}
				ips = append(ips, ip.String())
			}
		}
	}

	return ips
}
func isIPv6(address string) bool {
	var ipv4Regex = regexp.MustCompile(`^(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)
	address = strings.TrimSpace(address)
	if ipv4Regex.MatchString(address) {
		return false
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	// If To4() returns nil, it means the address is not IPv4, so it's IPv6
	return ip.To4() == nil
}
func EnableSystemdService(opts ServiceOptions) {
	if !DirectoryExists("/etc/systemd/system") {
		return
	}
	systemctl := FindProgram("systemctl")

	if !FileExists(systemctl) {
		return
	}
	program := Basename(opts.InitdPath)

	MD51 := ""
	MD52 := ""
	//SystemdServiceName := fmt.Sprintf("%v.service", program)
	SystemDTarget := fmt.Sprintf("/etc/systemd/system/%v.service", program)
	MD51 = FileMD5(SystemDTarget)
	var z []string
	z = append(z, "[Unit]")
	z = append(z, fmt.Sprintf("\tDescription=%v", program))
	z = append(z, "\tAfter=network.target")
	z = append(z, "[Service]")

	if strings.Contains(opts.ExecStart, "artica-phpfpm-service") {
		if len(opts.Pidfile) > 3 {
			z = append(z, "\tType = forking")
		} else {
			z = append(z, "\tType = simple")
		}

	}
	if opts.KillMode {
		z = append(z, "\tKillMode=process")
	}

	if len(opts.RunAsUser) > 1 {
		z = append(z, fmt.Sprintf("\tUser=%v", opts.RunAsUser))
	}
	if len(opts.RunAsGroup) > 1 {
		z = append(z, fmt.Sprintf("\tGroup=%v", opts.RunAsGroup))
	}

	if opts.SystemdSilent {
		z = append(z, "\tStandardOutput = null")
		z = append(z, "\tStandardError = null")
	} else {
		z = append(z, "\tStandardOutput=journal")
		z = append(z, "\tStandardError=journal")
	}

	if opts.Ulimit {
		z = append(z, "\tLimitSTACK=infinity")
	}
	if opts.CPUShares > 0 {
		z = append(z, fmt.Sprintf("\tCPUWeight=%d", opts.CPUShares))
	}
	if opts.CPUQuota > 0 {
		z = append(z, fmt.Sprintf("\tCPUQuota=%d%%", opts.CPUQuota))
	}
	if opts.AmbientCapabilities {
		z = append(z, "\tAmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN")
		z = append(z, "\tCapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN")
		z = append(z, "\tNoNewPrivileges=true")
	}

	if opts.PrivateDevices {
		z = append(z, "\tPrivateDevices=true")
	}
	if opts.CapabilityBoundingSet {
		z = append(z, "\tCapabilityBoundingSet=CAP_SETGID CAP_SETUID CAP_SYS_RESOURCE")
	}
	if opts.RestrictAddressFamilies {
		z = append(z, "\tCapabilityBoundingSet=AF_INET AF_INET6 AF_UNIX")
	}
	if opts.PrivateTmp {
		z = append(z, "\tPrivateTmp=true")
	}

	if opts.DefaultLimitNOFILE {
		z = append(z, "\tLimitNOFILE=2147483584")
	}

	if opts.MallocArenaMax > 0 {
		z = append(z, fmt.Sprintf("\tEnvironment=\"MALLOC_ARENA_MAX=%d\"", opts.MallocArenaMax))
	}
	NoPr := []string{"127.0.0.1", "localhost", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"}
	ips := allLocalIPs()
	for _, ip := range ips {
		NoPr = append(NoPr, ip)
	}
	z = append(z, fmt.Sprintf("\tEnvironment=\"NO_PROXY=%v\"", strings.Join(NoPr, ",")))

	if len(opts.Environements) > 0 {
		for _, Env := range opts.Environements {
			z = append(z, fmt.Sprintf("\tEnvironment=\"%v\"", Env))
		}
	}

	if opts.SystemdWatchdog {
		z = append(z, fmt.Sprintf("\tRestart=on-failure"))
		z = append(z, fmt.Sprintf("\tRestartSec=10"))
		z = append(z, fmt.Sprintf("\tStartLimitInterval=60s"))
		z = append(z, fmt.Sprintf("\tStartLimitBurst=3"))
	} else {
		if opts.SystemdRestartAlways {
			z = append(z, fmt.Sprintf("\tRestart=always"))
			z = append(z, fmt.Sprintf("\tRestartSec=10"))
		}

		z = append(z, "\tRestart=no")
	}

	if len(opts.Pidfile) > 3 {
		ZpidFile := opts.Pidfile
		ZpidFile = strings.TrimPrefix(ZpidFile, "/var")
		z = append(z, fmt.Sprintf("\tPIDFile=%v", opts.Pidfile))
	}
	if len(opts.ExecStartPrePHP) > 3 {
		phpfile := fmt.Sprintf("/usr/share/artica-postfix/%v", opts.ExecStartPrePHP)
		z = append(z, fmt.Sprintf("ExecStartPre=%v %v", LocatePHP5bin(), phpfile))
	}
	if !strings.Contains(opts.ExecStop, "-systemd") {
		opts.ExecStop = opts.ExecStop + " -systemd"
	}
	if opts.DefaultTimeoutStopSec > 1 {
		z = append(z, fmt.Sprintf("\tTimeoutStopSec=%ds", opts.DefaultTimeoutStopSec))
	}
	if len(opts.ExecStartPrePHP) < 3 {
		if len(opts.ExecStartPre) > 3 {
			z = append(z, fmt.Sprintf("\tExecStartPre=%v", opts.ExecStartPre))
		}
	}

	z = append(z, fmt.Sprintf("\tExecStart=%v", opts.ExecStart))
	z = append(z, fmt.Sprintf("\tExecStop=%v", opts.ExecStop))
	if opts.MaxFileDesc > 0 {
		z = append(z, fmt.Sprintf("\tLimitNOFILE=%d", opts.MaxFileDesc))
	}

	z = append(z, "[Install]")
	z = append(z, "\tWantedBy=default.target")
	_ = FilePutContents(SystemDTarget, strings.Join(z, "\n"))
	MD52 = FileMD5(SystemDTarget)
	futils.Chmod(SystemDTarget, 0644)

	Link := fmt.Sprintf("/etc/systemd/system/default.target.wants/%v.service", program)
	if !FileExists(Link) {
		out, err := futils.ExecCommand(fmt.Sprintf("%v enable %v", systemctl, program))
		if err != nil {
			if !strings.Contains(out, "no runlevel symlinks to modify") {
				log.Error().Msgf("%v [%v enable %v] [%v]", futils.GetCalleRuntime(), systemctl, program, out)
			}
		}
		_, _ = futils.ExecCommand(fmt.Sprintf("%v daemon-reload", systemctl))
		return
	}
	if !FileExists(Link) {
		log.Error().Msgf("%v Link %v does not exist !!", futils.GetCalleRuntime(), Link)
	}

	if MD51 == MD52 {
		if isDaemonMustReload(program) {
			out, err := GlobalsValues.RunDaemonReload()
			if err != nil {
				log.Error().Msgf("%v: %v [%v]", err.Error(), futils.GetCalleRuntime(), out)
			}
		}
		return
	}
	log.Debug().Msgf("EnableSystemdService(575): [%v daemon-reload", systemctl)
	out, err := GlobalsValues.RunDaemonReload()
	if err != nil {
		log.Error().Msgf("%v: %v [%v]", err.Error(), futils.GetCalleRuntime(), out)
	}
}

func isDaemonMustReload(UnitName string) bool {

	Out, _ := RunDaemonStatus(UnitName)
	if strings.Contains(Out, "systemctl daemon-reload") {
		return true
	}
	return false

}
func RunDaemonStatus(UnitName string) (combinedOutput string, err error) {
	// Create a context with a 10-second timeout
	TimeOut := time.Duration(10)
	ctx, cancel := context.WithTimeout(context.Background(), TimeOut*time.Second)
	defer cancel() // Ensure the context is canceled to release resources

	Masterbin := futils.FindProgram("systemctl")
	var outputBuf bytes.Buffer

	cmd := exec.CommandContext(ctx, Masterbin, "status", UnitName)
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf // Redirect stderr to the same buffer as stdout
	cmd.Env = append(cmd.Env, futils.ExecEnv()...)

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start sshd: %v", err)
	}
	err = cmd.Wait()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return outputBuf.String(), fmt.Errorf("timed out after %d", TimeOut.Seconds())
		}
		return outputBuf.String(), fmt.Errorf("%v failed: %v", "systemctl", err)
	}

	return outputBuf.String(), nil
}
func isLink(path string) bool {

	info, err := os.Lstat(path)
	if err != nil {
		return false
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return false
}
func RmRF(Directory string) error {

	if len(Directory) < 3 {
		return fmt.Errorf("remove recusrively this base path %v is denied", Directory)
	}

	Denied := []string{"/root", "/home", "/var", "/lib", "/bin", "/usr", "/usr/lib", "/usr/share", "/etc",
		"/etc/init.d", "/opt", "/usr/local", "/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin",
		"/usr/libexec", "/lib64", "/lib/x86_64-linux-gnu", "/proc", "/tmp", "/home/artica",
	}

	DeniedSuffix := []string{"/lib/x86_64-linux-gnu/", "/lib/", "/bin/", "/usr/sbin/", "/lib64/", "/usr/bin/"}

	for _, deniedP := range Denied {

		if Directory == deniedP {
			return fmt.Errorf("remove recusrively this base path %v is denied", Directory)
		}
		Denied2 := fmt.Sprintf("%v/", deniedP)
		if Directory == Denied2 {
			return fmt.Errorf("remove recusrively this base path %v/ is denied", Directory)
		}
	}

	for _, deniedP := range DeniedSuffix {

		if strings.HasPrefix(Directory, deniedP) {
			return fmt.Errorf("rmRF(): Remove recusrively this base path %v recusrsively is denied", Directory)
		}
	}

	if !isDirDirectory(Directory) {
		return nil
	}

	err := os.RemoveAll(Directory)
	if err != nil {
		return fmt.Errorf("RmRF(): Error while RemoveAll %v: %v", Directory, err)
	}
	return nil
}
func isDirDirectory(directoryPath string) bool {
	if isLink(directoryPath) {
		link, err := os.Readlink(directoryPath)
		if err != nil {
			return false
		}
		directoryPath = link
	}

	fileinfo, err := os.Stat(directoryPath)
	if err != nil {
		return false
	}

	if os.IsNotExist(err) {
		return false
	}
	return fileinfo.IsDir()
}
func CopyFile(Source string, destination string) error {

	if !FileExists(Source) {
		return errors.New(fmt.Sprintf("%v No such file", Source))
	}

	srcFile, err := os.Open(Source)
	if err != nil {
		return errors.New(fmt.Sprintf("%v Open failed %v", Source, err.Error()))

	}

	defer func() {
		closeErr := srcFile.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if FileExists(destination) {
		err = os.Remove(destination)
		if err != nil {
			_ = srcFile.Close()
			return errors.New(fmt.Sprintf("%v remove failed %v", destination, err.Error()))

		}
	}
	// Create the destination file for writing
	destFile, err := os.Create(destination)
	if err != nil {
		_ = srcFile.Close()
		return errors.New(fmt.Sprintf("%v Create failed %v", destination, err.Error()))
	}

	defer func() {
		closeErr := destFile.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	// Copy the contents from source to destination
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		_ = srcFile.Close()
		_ = destFile.Close()
		return errors.New(fmt.Sprintf("%v Copy failed %v", destination, err.Error()))
	}
	_ = srcFile.Close()
	_ = destFile.Close()
	return nil
}
func FileMD5(filename string) string {
	if !FileExists(filename) {
		return ""
	}

	file, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer func() {
		closeErr := file.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	hash := md5.New()

	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	hashInBytes := hash.Sum(nil)
	md5Hash := hex.EncodeToString(hashInBytes)
	return md5Hash
}
func RemoveServiceWithoutStop(InitdPath string) {
	if len(InitdPath) == 0 {
		return
	}
	if !FileExists(InitdPath) {
		return
	}
	basename := Basename(InitdPath)
	if FileExists("/usr/bin/systemctl") {
		_ = ExecuteShell(fmt.Sprintf("/usr/bin/systemctl disable %v", basename))
	}
	if FileExists("/usr/sbin/update-rc.d") {
		_ = ExecuteShell(fmt.Sprintf("/usr/sbin/update-rc.d -f %v remove", basename))
	}
	if FileExists("/sbin/chkconfig") {
		_ = ExecuteShell(fmt.Sprintf("/sbin/chkconfig --del %v", basename))
	}
	if FileExists(InitdPath) {
		_ = os.Remove(InitdPath)
	}
}
func RemoveService(InitdPath string) {
	if len(InitdPath) == 0 {
		return
	}
	if !FileExists(InitdPath) {
		return
	}

	_ = ExecuteShell(fmt.Sprintf("%v stop", InitdPath))
	RemoveServiceWithoutStop(InitdPath)

}
func LocatePHP5bin() string {

	locates := []string{"/usr/bin/php", "/usr/bin/php7.4", "/usr/bin/php7.3", "/usr/bin/php7.2", "/usr/bin/php7.1", "/usr/bin/php7.0"}
	for _, spath := range locates {
		if fileExists(spath) {
			return spath
		}
	}
	return ""
}
func FindProgram(pname string) string {

	PossibleDirs := []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
		"/usr/local/sbin", "/usr/kerberos/bin", "/usr/libexec",
	}

	for _, dir := range PossibleDirs {
		tpath := fmt.Sprintf("%v/%v", dir, pname)
		if FileExists(tpath) {
			return tpath
		}

	}
	return ""
}
func CurDateAddDay(daysToAdd int) string {
	currentTime := time.Now()
	if daysToAdd == 0 {
		daysToAdd = 5
	}
	newTime := currentTime.AddDate(0, 0, daysToAdd)
	return newTime.Format("2006-01-02 15:04:05")
}
func StrToInt64(svalue string) int64 {
	svalue = strings.TrimSpace(svalue)
	n, err := strconv.ParseInt(svalue, 10, 64)
	if err == nil {
		return n
	}
	return 0
}
func ServiceStop(conf ServiceStartStopOptions) bool {
	duration := 1 * time.Second
	pid := GetServicePid(conf)

	if conf.Out {
		fmt.Println(fmt.Sprintf("%v Checking PID %v...", conf.ServiceName, pid))
	}
	if !futils.ProcessExists(pid) {
		if conf.Out {
			fmt.Println(fmt.Sprintf("%v Already stopped", conf.ServiceName))
		}

		MonitSyslog("Stopping", true, conf)
		return true
	}
	if conf.Out {
		fmt.Println(fmt.Sprintf("%v killing PID %v...", conf.ServiceName, pid))
	}

	killSIGTERM(pid)

	pid = GetServicePid(conf)
	if !futils.ProcessExists(pid) {
		if conf.Out {
			fmt.Println(fmt.Sprintf("%v Stopped [Success]", conf.ServiceName))
		}

		MonitSyslog("Stopping", true, conf)
		return true
	}

	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetServicePid(conf)
		if !futils.ProcessExists(pid) {
			MonitSyslog("Stopping after SIGTERM", true, conf)
			return true
		}
		killSIGTERM(pid)

	}

	pid = GetServicePid(conf)
	if futils.ProcessExists(pid) {
		MonitSyslog(fmt.Sprintf("Stopping %d using SIGKILL", pid), false, conf)
		futils.KillProcess(pid)
	}

	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid = GetServicePid(conf)
		if !futils.ProcessExists(pid) {
			MonitSyslog("Stopping after SIGKILL", true, conf)
			return true
		}
		if pid > 0 {
			futils.KillProcess(pid)
		}
	}
	pid = GetServicePid(conf)
	if !futils.ProcessExists(pid) {
		MonitSyslog("Stopping", true, conf)
		return true
	}
	MonitSyslog("Stopping", false, conf)
	return false
}
func killSIGTERM(pid int) {
	cmdline := processCommandLine(pid)
	logKillProc(fmt.Sprintf("KILL SIGTERM %d [%v] (articaunix)", pid, cmdline))
	_ = syscall.Kill(pid, syscall.SIGTERM)
}
func logKillProc(message string) {
	logFile := "/var/log/killproc.log"
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)

	// Open the file in append mode (or create it if it doesn't exist)
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)

	// Write the log entry
	if _, err := f.WriteString(logEntry); err != nil {
		return
	}
	return
}
func ServiceStartGlobal(conf ServiceOptions) error {
	opts := ServiceStartStopOptionsFromServiceOptions(conf)
	opts.Out = false
	EnableMonit(conf)
	EnableSystemdService(conf)
	return ServiceStart(opts)
}
func processCommandLine(pid int) string {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	finale := strings.Replace(string(content), "\x00", " ", -1)
	return strings.TrimSpace(finale)
}
func ServiceStopGlobal(conf ServiceOptions) bool {
	opts := ServiceStartStopOptionsFromServiceOptions(conf)
	opts.Out = false
	return ServiceStop(opts)
}
func CheckSocket(conf ServiceStartStopOptions) error {
	if len(conf.CheckSocket) < 3 {
		return nil
	}
	if isUnixSocketAvailable(conf.CheckSocket) {
		return nil
	}

	duration := 1 * time.Second
	for i := 0; i < 3; i++ {
		time.Sleep(duration)
		if isUnixSocketAvailable(conf.CheckSocket) {
			fmt.Println(fmt.Sprintf("Starting %v Checking socket [%v] [OK]", conf.ServiceName, conf.CheckSocket))
			return nil
		}
		if conf.Out {
			fmt.Println(fmt.Sprintf("Starting %v Checking socket [%v] %d/3", conf.ServiceName, conf.CheckSocket, i))
		}
	}

	if isUnixSocketAvailable(conf.CheckSocket) {
		fmt.Println(fmt.Sprintf("Starting %v Checking socket [%v] [OK]", conf.ServiceName, conf.CheckSocket))
		return nil
	}

	if conf.Out {
		fmt.Println(fmt.Sprintf("Starting %v [%v] not available -> Stop/start", conf.ServiceName, conf.CheckSocket))
	}
	ServiceStop(conf)
	conf.CheckSocket = ""
	return ServiceStart(conf)
}
func SetMaxFileDesc(pid int, conf ServiceStartStopOptions) {

	if conf.MaxFileDesc == 0 {
		return
	}
	prlimit := FindProgram("prlimit")
	if !fileExists(prlimit) {
		return
	}
	fmt.Println(fmt.Sprintf("Starting %v modifies filedescriptors limitation of %d", conf.ServiceName, pid))
	_ = ExecuteShell(fmt.Sprintf("%v --pid %d --nofile=\"324288:524288\"", prlimit, pid))
}
func ForcePidFile(pid int, conf ServiceStartStopOptions) {
	if !conf.ForcePidFile {
		return
	}
	if pid == 0 {
		return
	}
	if len(conf.PidFile) < 3 {
		return
	}

	OldPid := int(StrToInt64(fileGetContents(conf.PidFile)))
	if OldPid == pid {
		return
	}
	MonitSyslog(fmt.Sprintf("%v --> %d", conf.PidFile, pid), true, conf)
	_ = filePutContents(conf.PidFile, fmt.Sprintf("%d", pid))
}
func ServiceStart(conf ServiceStartStopOptions) error {
	duration := 1 * time.Second
	pid := GetServicePid(conf)

	if len(conf.TokenEnabled) > 3 {
		Enabled := sockets.GET_INFO_INT(conf.TokenEnabled)
		if Enabled == 0 {
			if conf.Out {
				fmt.Println(fmt.Sprintf("Starting %v is disbaled see [%v]...", conf.ServiceName, conf.TokenEnabled))
			}
			if futils.ProcessExists(pid) {
				ServiceStop(conf)
			}
			return fmt.Errorf("Service is disabled")
		}
	}

	if futils.ProcessExists(pid) {
		if conf.Out {
			fmt.Println(fmt.Sprintf("(Unix/ServiceStart) Starting %v Already executed pid [%v]...", conf.ServiceName, pid))
		}
		MonitSyslog("Already Executed", true, conf)
		ForcePidFile(pid, conf)
		SetMaxFileDesc(pid, conf)
		return CheckSocket(conf)
	}

	if len(conf.StartCommandLine) == 0 {
		fmt.Println(fmt.Sprintf("Starting %v no Cmdline set!...", conf.ServiceName))
		return fmt.Errorf("no Cmdline set!...")
	}

	if FileExists(conf.BinaryPath) {
		_ = os.Chmod(conf.BinaryPath, 0755)
	}

	out := ""
	var ok error

	var h []string
	ShellFile := futils.TempFileName()
	ShellFileLog := fmt.Sprintf("%v.log", ShellFile)
	nohup := FindProgram("nohup")
	rm := FindProgram("rm")

	h = append(h, "#!/bin/sh")
	h = append(h, conf.StartCommandLine)
	h = append(h, fmt.Sprintf("%v -f %v", rm, ShellFile))
	h = append(h, "")
	cmdline := fmt.Sprintf("%v %v >%v 2>&1 &", nohup, ShellFile, ShellFileLog)

	_ = filePutContents(ShellFile, strings.Join(h, "\n"))
	Chmod(ShellFile, 0755)

	MonitSyslog(fmt.Sprintf("Starting %v", conf.StartCommandLine), true, conf)
	if conf.RemovePIDBefore {
		if len(conf.PidFile) > 3 {
			if FileExists(conf.PidFile) {
				MonitSyslog(fmt.Sprintf("Starting removing %v", conf.PidFile), true, conf)
				_ = os.Remove(conf.PidFile)
			}
		}
	}
	ok, out = ServiceExecuteShell(cmdline)

	if ok != nil {
		if conf.Out {
			fmt.Println(fmt.Sprintf("Starting %v Error %v [%v]...", conf.ServiceName, ok.Error(), out))
		}

		return errors.New(fmt.Sprintf("%v %v", ok.Error(), out))
	}
	for i := 0; i < 5; i++ {
		time.Sleep(duration)
		pid := GetServicePid(conf)
		if futils.ProcessExists(pid) {
			if conf.Out {
				fmt.Println(fmt.Sprintf("Starting %v Success PID [%v]...", conf.ServiceName, pid))
			}
			ForcePidFile(pid, conf)
			SetMaxFileDesc(pid, conf)
			MonitSyslog("Starting", true, conf)
			_ = os.Remove(ShellFileLog)
			return CheckSocket(conf)
		}
		if conf.Out {
			MonitSyslog(fmt.Sprintf("Starting waiting %v/5", i), true, conf)
			fmt.Println(fmt.Sprintf("Starting %v Waiting %v/5...", conf.ServiceName, i))
		}
	}
	if conf.Out {
		fmt.Println(fmt.Sprintf("Starting %v FAILED %v", conf.ServiceName, out))
	}
	MonitSyslog("Starting", false, conf)
	tmpstr := strings.Split(fileGetContents(ShellFileLog), "\n")
	_ = os.Remove(ShellFileLog)
	for _, line := range tmpstr {
		if conf.Out {
			fmt.Println(fmt.Sprintf("Starting %v [%v]", conf.ServiceName, line))
		}
		MonitSyslog(line, false, conf)
	}

	return fmt.Errorf(fmt.Sprintf("%v %v", out, tmpstr))
}
func ServiceReload(conf ServiceStartStopOptions) error {
	pid := GetServicePid(conf)
	if futils.ProcessExists(pid) {
		return syscall.Kill(pid, syscall.SIGHUP)
	}
	return ServiceStart(conf)

}
func ExecutePHP(phpfilenameandcommand string) (error, string) {
	ArticaPath := "/usr/share/artica-postfix"
	phpBin := "/usr/bin/php"
	if !DirectoryExists(ArticaPath) {
		return errors.New(fmt.Sprintf("LinuxExecutePHP:: %v no such directory", ArticaPath)), ""
	}

	CommandLine := fmt.Sprintf("%v %v/%v", phpBin, ArticaPath, phpfilenameandcommand)
	cmd := exec.Command("/usr/bin/bash", "-c", CommandLine)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return err, string(output)
	}
	return nil, string(output)
}
func GetServicePid(Conf ServiceStartStopOptions) int {

	if len(Conf.PidFile) > 3 {
		pid := GetPIDFromFile(Conf.PidFile)
		if futils.ProcessExists(pid) {
			return pid
		}
	}
	if len(Conf.ProcessPattern) > 3 {
		pid := PIDOFPattern(Conf.ProcessPattern)
		if futils.ProcessExists(pid) {
			return pid
		}
	}
	if len(Conf.BinaryPath) > 3 {
		pid := PIDOFPattern(Conf.BinaryPath)
		if futils.ProcessExists(pid) {
			return pid
		}
	}
	return 0

}
func GetPIDFromFile(path string) int {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		return 0
	}
	return pid
}
func PIDOFPattern(PnameRegex string) int {
	processes, err := process.Processes()
	if err != nil {
		return 0
	}
	for _, p := range processes {
		zcmdline, _ := p.Cmdline()
		if len(zcmdline) == 0 {
			zcmdline, _ = p.Name()
		}
		pid := p.Pid
		if futils.RegexFind(regexp.MustCompile(PnameRegex), zcmdline) {
			return int(pid)
		}

	}
	return 0
}
func ServiceExecuteShell(CommandLine string) (error, string) {
	cmd := exec.Command("/usr/bin/bash", "-c", CommandLine)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return err, string(output)
	}
	return nil, string(output)
}
func Chmod(TargetPath string, desiredMode os.FileMode) {
	if !fileExists(TargetPath) {
		return
	}
	_ = os.Chmod(TargetPath, desiredMode)
}
func MonitSyslog(Action string, Success bool, Conf ServiceStartStopOptions) {
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

	Result := "FAILED"
	if Success {
		Result = "SUCCESS"
	}
	Msg := fmt.Sprintf("'%v' %v: %v [%v]", Conf.MonitName, Action, Conf.ServiceName, Result)
	_ = w.Info(Msg)
	_ = w.Close()
}
func InstallLogon() {
	var f []string
	f = append(f, "[Unit]")
	f = append(f, "Description=Execute Artica Logon script")
	f = append(f, "After=network.target network-online.target nss-lookup.target multi-user.target graphical.target")
	f = append(f, "Wants=network-online.target")
	f = append(f, "Before=getty.target")
	//f = append(f, "Before=getty@tty1.service")
	//f = append(f, "After=multi-user.target")
	f = append(f, "")
	f = append(f, "[Service]")
	f = append(f, "Type=oneshot")
	f = append(f, "ExecStart=/usr/share/artica-postfix/logon.sh")
	f = append(f, "")
	f = append(f, "[Install]")
	f = append(f, "WantedBy=multi-user.target")
	_ = FilePutContents("/etc/systemd/system/artica-logon.service", strings.Join(f, "\n"))
	_ = ExecuteShell("chmod +x /usr/share/artica-postfix/logon.sh")
	_ = ExecuteShell("sudo systemctl enable artica-logon.service")
}

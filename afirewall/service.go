package afirewall

import (
	"GlobalsValues"
	"TuneKernel"
	"UniversalProxy"
	"afirewall/ProxyFirewall"
	"afirewall/aFirewallTools"
	"afirewall/nDPI"
	"articaunix"
	"fmt"
	"futils"
	"notifs"
	"regexp"
	"sockets"
	"squid/Wccp"
	"strings"

	"github.com/rs/zerolog/log"
)

const ServiceName = "Categories Service"
const MainBinary = "/usr/sbin/dnscatz"
const ArticaBinary = GlobalsValues.ArticaBinary
const SyslogConfPath = "/etc/rsyslog.d/dnblcats.conf"
const InitdPath = "/etc/init.d/firehol"
const TokenEnabled = "FireHolEnable"
const MonitName = "APP_FIREHOL"
const TokenInstalled = "IPTABLES_INSTALLED"
const TokenVersion = "IPTABLES_VERSION"
const progressF = "firehol.reconfigure.progress"

func Install() {

	sockets.SET_INFO_INT(TokenEnabled, 1)
	notifs.SquidAdminMysql(1, "{install} Local firewall service", "", futils.GetCalleRuntime(), 31)
	notifs.BuildProgress(50, "{install}", progressF)
	log.Warn().Msgf("%v [FIREWALL]: Reconfiguring the Firewall...", futils.GetCalleRuntime())
	Reconfigure(true)
	notifs.BuildProgress(55, "{install}", progressF)
	Conf := ServiceConfig()
	articaunix.EnableService(Conf)
	Start()
	notifs.BuildProgress(100, "{success}", progressF)
}
func GetVersion() string {

	// Find the iptables binary
	IptablesBin := futils.FindProgram("iptables")

	if !futils.FileExists(IptablesBin) {
		sockets.SET_INFO_INT(TokenInstalled, 0)
		sockets.SET_INFO_STR(TokenVersion, "0.0.0")
		return "0.0.0"
	}

	kernel := futils.KernelVersion()
	XTNDPIInstalled := int64(1)
	XTGeoIPInstalled := int64(1)
	xtNdpi := fmt.Sprintf("/usr/lib/modules/%v/extra/xt_ndpi.ko", kernel)
	xtGeoip := fmt.Sprintf("/usr/lib/modules/%v/extra/xt_geoip.ko", kernel)
	xtIpv4options := fmt.Sprintf("/usr/lib/modules/%v/extra/xt_ipv4options.ko", kernel)
	xtIpv4optionsInstalled := int64(0)

	if futils.FileExists(xtIpv4options) {
		xtIpv4optionsInstalled = 1
	}
	if futils.FileExists(xtNdpi) {
		XTNDPIInstalled = 0
	}

	if !futils.FileExists(xtGeoip) {
		XTGeoIPInstalled = 0
	}
	sockets.SET_INFO_INT("XTNDPIInstalled", XTNDPIInstalled)
	sockets.SET_INFO_INT("XTGeoIPInstalled", XTGeoIPInstalled)
	sockets.SET_INFO_INT("xtIpv4optionsInstalled", xtIpv4optionsInstalled)

	err, output := futils.ExecuteShell(fmt.Sprintf("%v -V", IptablesBin))

	if err != nil {
		log.Error().Msgf("%v failed to execute %s -V: %v [%v]", futils.GetCalleRuntime(), IptablesBin, err, output)
	}
	sockets.SET_INFO_INT(TokenInstalled, 1)
	lines := strings.Split(output, "\n")
	versionPattern := regexp.MustCompile(`^iptables v([0-9.]+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if matches := versionPattern.FindStringSubmatch(line); matches != nil {
			iptablesVersion := matches[1]
			sockets.SET_INFO_STR(TokenVersion, iptablesVersion)
			return iptablesVersion
		}
	}

	return "0.0.0"
}
func Uninstall() {
	notifs.BuildProgress(50, "{uninstall}", progressF)
	sockets.SET_INFO_INT(TokenEnabled, 0)
	Conf := ServiceConfig()
	articaunix.ServiceUninstall(Conf)
	log.Warn().Msgf("%v Flushing iptables configuration", futils.GetCalleRuntime())
	Flush()

	Modules := make(map[string]string)

	Modules["xt_geoip"] = "/etc/modules-load.d/xt_geoip.conf"
	rmmod := futils.FindProgram("rmmod")
	for modulename, modulepath := range Modules {
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v %v", rmmod, modulename))
		futils.DeleteFile(modulepath)
	}

	_ = RoutersBuild(false)
	if futils.FileExists("/etc/init.d/squid") {
		_, _ = futils.ExecutePHP("exec.squid.global.access.php --chk-port --no-firehol")
	}
	notifs.SquidAdminMysql(1, "{uninstall} Local firewall service", "", futils.GetCalleRuntime(), 31)
	notifs.BuildProgress(100, "{uninstall} {success}", progressF)
}
func Reconfigure(Alone bool) {
	if sockets.GET_INFO_INT(TokenEnabled) == 0 {
		log.Debug().Msgf("%v Firewall is disabled, building MASQERADE", futils.GetCalleRuntime())
		_ = RoutersBuild(false)
		Wccp.Configure(false)
		return
	}
	Conf := ServiceConfig()
	articaunix.EnableService(Conf)
	iptables := futils.FindProgram("iptables")
	futils.CreateDir("/home/artica/firewall")
	log.Warn().Msgf("%v Flushing iptables configuration", futils.GetCalleRuntime())
	Flush()
	Count := CountOfTrafficShapingRules()

	if Count > 0 {
		_, _ = futils.ExecuteShell("/usr/sbin/modprobe xt_ratelimit")
	}
	notifs.BuildProgress(59, "{configure}", progressF)
	log.Warn().Msgf("%v Flushing iptables configuration", futils.GetCalleRuntime())
	Flush()
	TuneKernel.TuneKernel()
	notifs.BuildProgress(60, "{configure}", progressF)
	_ = RoutersBuild(false)
	notifs.BuildProgress(61, "{configure}", progressF)
	MasqueradeBuild()
	notifs.BuildProgress(62, "{configure}", progressF)
	_ = CreateFirewallRoutingTables()
	notifs.BuildProgress(63, "{configure}", progressF)
	TuneKernel.TuneKernel()
	aFirewallTools.CleanRulesByString([]string{":ARTICAFW_"})
	TimeS := futils.TimeStampToString()
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -N ARTICAFW_%v", iptables, TimeS))
	notifs.BuildProgress(64, "{configure}", progressF)
	NginxFireWall()
	// Create IPset for the Firewall itself.
	err := PublicServers()
	if err != nil {
		log.Error().Msgf(err.Error())
	}
	notifs.BuildProgress(64, "{configure}", progressF)
	err = AntiDDos()
	if err != nil {
		log.Error().Msgf(err.Error())
	}
	notifs.BuildProgress(65, "{configure}", progressF)
	notifs.BuildProgress(66, "{configure}", progressF)
	notifs.BuildProgress(67, "{configure}", progressF)
	ProxyFirewall.SquidRules()
	notifs.BuildProgress(68, "{configure}", progressF)
	CreateNginxfwwIPSet()
	notifs.BuildProgress(69, "{configure}", progressF)
	TrustedAddRules()
	notifs.BuildProgress(70, "{configure}", progressF)
	CrowdSecRules()
	notifs.BuildProgress(71, "{configure}", progressF)
	BuildFirewallByInterfaces(false)
	BuildFirewallByNATs(false)
	notifs.BuildProgress(72, "{configure}", progressF)
	err = ipRatelimit()
	notifs.BuildProgress(73, "{configure}", progressF)

	notifs.BuildProgress(74, "{configure}", progressF)
	log.Info().Msgf("%v Building routers", futils.GetCalleRuntime())
	err = RoutersBuild(false)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}
	Wccp.Configure(false)
	//3Proxy, toujours à la fin
	Enable3Proxy := sockets.GET_INFO_INT("Enable3Proxy")
	if Enable3Proxy == 1 {
		UniversalProxy.Build()
	}
	if err != nil {
		log.Error().Msgf(err.Error())
	}
	if Alone {
		notifs.BuildProgress(100, "{configure} {success}", progressF)
	}
	//NDPI
	_ = nDPI.Start()
	// NFQUEUE
	log.Debug().Msgf("%v ENF!-----------------------------", futils.GetCalleRuntime())
}
func Start() {
	log.Warn().Msgf("%v [FIREWALL]: Reconfiguring the Firewall...", futils.GetCalleRuntime())
	Reconfigure(false)

	ExternScripts := []string{
		"/usr/sbin/firewall-builder.sh", "/etc/init.d/proxy-wccp", "/etc/init.d/mikrotik", "/bin/suricata-fw.sh",
	}

	for _, script := range ExternScripts {

		if !futils.FileExists(script) {
			continue
		}

		if strings.Contains(script, "init.d") {
			_, _ = futils.ExecuteShell(script + " start")
			continue
		}
		_, _ = futils.ExecuteShell(script)

	}

	if futils.FileExists("/etc/init.d/proxy-wccp") {
		_, _ = futils.ExecuteShell("/etc/init.d/proxy-wccp ")
	}

}
func Stop(Alone bool) {
	notifs.BuildProgress(10, "{stopping}", progressF)
	log.Warn().Msgf("%v Flushing iptables configuration", futils.GetCalleRuntime())
	Flush()
	notifs.BuildProgress(15, "{stopping}", progressF)
	_ = RoutersClean()
	notifs.BuildProgress(20, "{stopping}", progressF)
	MasqueradeBuild()
	notifs.BuildProgress(25, "{stopping}", progressF)
	_ = CleanFirewallRoutingTables()
	notifs.BuildProgress(30, "{stopping}", progressF)
	ExternScripts := []string{
		"/etc/init.d/proxy-wccp", "/etc/init.d/mikrotik", "/bin/suricata-fw.sh", "/bin/iptables-parents.sh",
	}
	for _, script := range ExternScripts {
		if !strings.Contains(script, "init.d") {
			continue
		}
	}
	SquidTransparentBuild()
	if Alone {
		notifs.BuildProgress(100, "{stopping} {success}", progressF)
	}

}
func ServiceConfig() articaunix.ServiceOptions {

	var opts articaunix.ServiceOptions
	opts.DisableMonitConfig = true
	opts.SourceBin = MainBinary
	opts.CheckSocket = ""
	opts.MaxFileDesc = 0
	opts.ForcePidFile = false
	opts.ExecStartPrePHP = ""
	opts.ExecStart = fmt.Sprintf("%v -start-firewall", ArticaBinary)
	opts.ExecStop = fmt.Sprintf("%v -stop-firewall", ArticaBinary)
	opts.ExecReload = fmt.Sprintf("%v -restart-firewall", ArticaBinary)
	opts.ExecUninstall = fmt.Sprintf("%v -uninstall-firewall", ArticaBinary)
	opts.ExecInstall = fmt.Sprintf("%v -install-firewall", ArticaBinary)
	opts.InitdPath = InitdPath
	opts.Pidfile = ""
	opts.ServiceName = ServiceName
	opts.ProcessPattern = MainBinary
	opts.ProcessNoWait = true
	opts.TokenEnabled = TokenEnabled
	opts.StartCmdLine = opts.ExecStart
	opts.SyslogConfPath = SyslogConfPath
	opts.MonitName = MonitName
	opts.MallocArenaMax = 0
	opts.KillPorts = 0
	return opts
}
func IsActive() (bool, int) {
	Lines := aFirewallTools.CurrentRules()
	firewallActivePath := "/usr/share/artica-postfix/ressources/logs/web/FIREWALL_ACTIVE"
	futils.DeleteFile(firewallActivePath)

	for _, line := range Lines {
		articaFwPattern := regexp.MustCompile(`^:ARTICAFW_([0-9]+)`)
		if matches := articaFwPattern.FindStringSubmatch(line); matches != nil {
			_ = futils.FilePutContents(firewallActivePath, "1")
			return true, futils.StrToInt(matches[1])
		}
		log.Debug().Msgf("%v [%v] NO MATCH", futils.GetCalleRuntime(), line)
		if strings.HasPrefix(line, "-A INPUT") {
			break
		}
	}
	return false, 0
}
func Status(watchdog bool) string {
	if !watchdog {
		return ""
	}
	Enabled := sockets.GET_INFO_INT(TokenEnabled)
	if Enabled == 0 {
		return ""
	}
	UncreatedRules := aFirewallTools.MissingIDS()
	if len(UncreatedRules) == 0 {
		return ""
	}
	var f []string
	for _, rule := range UncreatedRules {
		f = append(f, fmt.Sprintf("Missing rule ID:%v", rule))
	}
	notifs.SquidAdminMysql(1, fmt.Sprintf("{your_firewall}: Missing %d rules {action}={reconfigure}", len(UncreatedRules)), strings.Join(f, "\n"), futils.GetCalleRuntime(), 299)
	log.Warn().Msgf("%v [FIREWALL]: Reconfiguring the Firewall...", futils.GetCalleRuntime())
	Reconfigure(true)
	return ""
}

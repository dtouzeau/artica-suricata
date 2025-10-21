package nDPI

import (
	"CacheMem"
	"afirewall/aFirewallTools"
	"articaunix"
	"bytes"
	"fmt"
	"futils"
	"notifs"
	"os"
	"os/exec"
	"regexp"
	"sockets"
	"strings"
	"time"

	"github.com/go-ini/ini"
	"github.com/rs/zerolog/log"
)

var NDPIError1 = regexp.MustCompile(`(?i)unknown option.*?--error`)
var NDPITime1 = regexp.MustCompile(`NDPI_TIME:([0-9]+)`)
var reGexLine = regexp.MustCompile(`^\[([0-9]+):([0-9]+)\]\s+-A(.+?)NDPI_TIME:([0-9]+).+?-j NDPI --flow-info`)
var reGexLineNumber = regexp.MustCompile(`^([0-9]+)\s+[0-9]+.*?NDPI`)
var reGexVersion = regexp.MustCompile(`^nDPI version\s+([0-9.]+)`)
var reGexDmesgVersion = regexp.MustCompile(`xt_ndpi v([0-9.]+)`)

const ProgressF = "firehol.reconfigure.progress"
const ProgressR = "ndpi.restart.progress"

type Firewallinfo struct {
	RulePar   string `json:"RulePar"`
	Packets   int64  `json:"Packets"`
	Bytes     int64  `json:"Bytes"`
	TimeStart int64  `json:"TimeStart"`
}

func GetVersion() {

	EnablenDPI := sockets.GET_INFO_INT("EnablenDPI")
	DisablePostGres := sockets.GET_INFO_INT("DisablePostGres")
	if DisablePostGres == 1 {
		EnablenDPI = 0
	}
	if EnablenDPI == 0 {
		return

	}
	val := CacheMem.GetStringFunc()
	if len(val) > 1 {
		sockets.SET_INFO_STR("NDPI_VERSION", val)
		return
	}
	Kernel := futils.KernelVersion()
	ndpiPath := fmt.Sprintf("/usr/lib/modules/%v/extra/xt_ndpi.ko", Kernel)
	log.Debug().Msgf("%v ndpiPath: %v", ndpiPath, futils.GetCalleRuntime())
	if !futils.FileExists(ndpiPath) {
		return
	}

	iptablesBin := futils.FindProgram("iptables")
	cmd := fmt.Sprintf("%v -m ndpi -h", iptablesBin)
	err, out := futils.ExecuteShell(cmd)

	if err != nil {
		if strings.Contains(out, `Couldn't load match`) {
			return
		}
		if strings.Contains(out, "missing kernel module") {
			NdpioCheckKey := fmt.Sprintf("NDpiCheck%v", Kernel)
			Value := sockets.GET_INFO_INT(NdpioCheckKey)
			if Value == 1 {
				sockets.SET_INFO_INT("EnablenDPI", 0)
				return
			}
			err := futils.RunDepmod()
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			}

			err = futils.RunModeProbe("xt_ndpi")
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			}
			sockets.SET_INFO_INT(NdpioCheckKey, 1)
			err, out = futils.ExecuteShell(cmd)
		} else {
			log.Error().Msgf("%v %v %v (%v)", futils.GetCalleRuntime(), err, out, ndpiPath)
			return
		}
	}

	if err != nil {
		log.Error().Msgf("%v %v (%v)", futils.GetCalleRuntime(), out, ndpiPath)
		return
	}
	inProtocolsSection := false
	VersionFound := false
	var protocols []string
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line := strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") || strings.HasPrefix(line, "iptables") {
			continue
		}
		if !inProtocolsSection {
			version := futils.RegexGroup1(reGexVersion, line)
			if len(version) > 0 {
				log.Debug().Msgf("%v found %v in [%v]", futils.GetCalleRuntime(), version, line)
				sockets.SET_INFO_STR("NDPI_VERSION", version)
				VersionFound = true
				continue
			}
			log.Debug().Msgf("%v not found in [%v]", futils.GetCalleRuntime(), line)

		}
		if strings.HasPrefix(line, "Enabled protocols:") {
			inProtocolsSection = true
			continue
		}
		if inProtocolsSection {
			fields := strings.Fields(line)
			for _, field := range fields {
				if !strings.HasPrefix(field, "--") {
					protocols = append(protocols, field)
				}
			}
		}
	}
	sockets.SET_INFO_INT("NDPI_PROTOS", int64(len(protocols)))
	if !VersionFound {
		dmesg := futils.FindProgram("dmesg")
		_, out := futils.ExecuteShell(dmesg)
		tb := strings.Split(out, "\n")
		for _, line := range tb {
			line := strings.TrimSpace(line)
			version := futils.RegexGroup1(reGexDmesgVersion, line)
			if len(version) > 0 {
				log.Debug().Msgf("%v found %v in [%v]", futils.GetCalleRuntime(), version, line)
				CacheMem.SetStringFunc(version)
				sockets.SET_INFO_STR("NDPI_VERSION", version)
				VersionFound = true
				break
			}

		}
	}
}

func RuleInfo() Firewallinfo {
	var Info Firewallinfo
	iptablesSave := futils.FindProgram("iptables-save")
	cmdline := fmt.Sprintf("%v -t mangle -c", iptablesSave)
	log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), cmdline)
	err, out := futils.ExecuteShell(cmdline)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), out)
	if err != nil {
		log.Error().Msgf("%v [%v]", futils.GetCalleRuntime(), out)
		return Info
	}
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		sPackets, sBytes, RulePar, sTime := futils.RegexGroup4(reGexLine, line)
		if len(RulePar) < 2 {
			log.Debug().Msgf("%v not found [%v]", futils.GetCalleRuntime(), out)
			continue
		}
		Info.Packets = futils.StrToInt64(sPackets)
		Info.Bytes = futils.StrToInt64(sBytes)
		Info.TimeStart = futils.StrToInt64(sTime)
		Info.RulePar = RulePar
		break
	}
	return Info

}

func Status(watchdog bool) string {

	if futils.FileExists("/etc/init.d/nDPI") {
		articaunix.RemoveServiceINIT("/etc/init.d/nDPI")
		go func() {
			log.Warn().Msgf("%v Restart Artica Status service", futils.GetCalleRuntime())
			err, _ := futils.ExecuteShell("/etc/init.d/artica-status restart --force")
			if err != nil {

			}
		}()
	}

	EnablenDPI := sockets.GET_INFO_INT("EnablenDPI")
	DisablePostGres := sockets.GET_INFO_INT("DisablePostGres")
	if DisablePostGres == 1 {
		EnablenDPI = 0
	}
	Kernel := futils.KernelVersion()
	ndpiPath := fmt.Sprintf("/usr/lib/modules/%v/extra/xt_ndpi.ko", Kernel)
	cfg := ini.Empty()
	defaultSection := cfg.Section("APP_NDPI") // Default section
	defaultSection.Key("service_name").SetValue("APP_NDPI")
	defaultSection.Key("master_version").SetValue("0.0.0")
	defaultSection.Key("service_cmd").SetValue("")
	defaultSection.Key("pid_path").SetValue("")
	defaultSection.Key("watchdog_features").SetValue("1")
	defaultSection.Key("family").SetValue("network")

	if !futils.FileExists(ndpiPath) {
		cfg := ini.Empty()
		defaultSection.Key("installed").SetValue("0")
		defaultSection.Key("application_installed").SetValue("0")
		defaultSection.Key("service_disabled").SetValue("0")
		var buffer bytes.Buffer
		_, err := cfg.WriteTo(&buffer)
		if err != nil {
			return ""
		}
		return buffer.String()
	}
	defaultSection.Key("installed").SetValue("1")
	defaultSection.Key("application_installed").SetValue("1")
	if EnablenDPI == 0 {
		if watchdog {
			if Check() {
				Uninstall()
			}
		}
		defaultSection.Key("service_disabled").SetValue("0")
		var buffer bytes.Buffer
		_, err := cfg.WriteTo(&buffer)
		if err != nil {
			return ""
		}
		return buffer.String()
	}

	defaultSection.Key("service_disabled").SetValue("1")

	if !Check() {
		defaultSection.Key("running").SetValue("0")
		var buffer bytes.Buffer
		_, err := cfg.WriteTo(&buffer)
		if err != nil {
			return ""
		}
		return buffer.String()
	} else {
		defaultSection.Key("running").SetValue("1")
	}

	zTime := ruleTime()
	if zTime > 0 {
		defaultSection.Key("master_time").SetValue(fmt.Sprintf("%v", zTime))
		xdate := time.Unix(zTime, 0)
		distance := futils.DistanceOfTimeInWordsInterface(time.Now(), xdate, true)
		defaultSection.Key("uptime").SetValue(distance)
	}
	defaultSection.Key("master_pid").SetValue("1")
	defaultSection.Key("processes_number").SetValue("1")
	defaultSection.Key("master_memory").SetValue("1024")
	var buffer bytes.Buffer
	_, err := cfg.WriteTo(&buffer)
	if err != nil {
		return ""
	}
	return buffer.String()
}

func Restart() {

	notifs.BuildProgress(20, "{stopping}", ProgressR)
	Stop()
	notifs.BuildProgress(50, "{starting}", ProgressR)
	err := Start()
	if err != nil {
		notifs.BuildProgress(110, "{starting} {failed}", ProgressR)
		log.Error().Msgf("%v Error starting service: %v", futils.GetCalleRuntime(), err)
	}
	notifs.BuildProgress(100, "{starting} {success}", ProgressR)

}

func RemoveRule() {
	iptablesBin := futils.FindProgram("iptables")
	cmd := fmt.Sprintf("%v -t mangle -L PREROUTING -v --line-numbers", iptablesBin)
	_, out := futils.ExecuteShell(cmd)
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		sLineNumber := futils.RegexGroup1(reGexLineNumber, line)
		LineNumber := futils.StrToInt64(sLineNumber)
		if LineNumber == 0 {
			continue
		}
		cmdDel := fmt.Sprintf("%v -t mangle -D PREROUTING %d", iptablesBin, LineNumber)
		err, out := futils.ExecuteShell(cmdDel)
		if err != nil {
			log.Error().Msgf("%v %v %v", futils.GetCalleRuntime(), cmdDel, out)
		}
	}
}

func Check() bool {
	if !futils.IsModulesLoaded("xt_ndpi") {
		return false
	}
	if ifRulesExist() {
		return true
	}
	info := RuleInfo()
	if len(info.RulePar) > 3 {
		return true
	}
	return false

}
func Stop() {
	aFirewallTools.CleanRulesByString([]string{"NDPI_TIME", "NDPI --flow-info"})
	modprobe := futils.FindProgram("modprobe")
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -r %v", modprobe, "xt_ndpi"))
	info := RuleInfo()
	if len(info.RulePar) > 3 {
		RemoveRule()
	}
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v -r %v", modprobe, "xt_ndpi"))
}
func Start() error {
	EnablenDPI := sockets.GET_INFO_INT("EnablenDPI")
	if EnablenDPI == 0 {
		return nil
	}
	DisablePostGres := sockets.GET_INFO_INT("DisablePostGres")
	if DisablePostGres == 1 {
		return fmt.Errorf("%v DisablePostGres is 1", futils.GetCalleRuntime())
	}

	if !futils.FileExists("/usr/lib/x86_64-linux-gnu/xtables/libxt_ndpi.so") {
		notifs.SquidAdminMysql(0, "Unable to load nDPI module (xtables/libxt_ndpi.so) [{action}={uninstall}]", "", futils.GetCalleRuntime(), 82)
		Uninstall()
		return fmt.Errorf("xtables/libxt_ndpi.so not found")
	}

	if !futils.IsModulesLoaded("xt_ndpi") {
		err := futils.RunDepmod()
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}

		modprobe := futils.FindProgram("modprobe")
		err, out := futils.ExecuteShell(fmt.Sprintf("%v xt_ndpi ndpi_enable_flow=1", modprobe))
		if err != nil {

			tb := strings.Split(out, "\n")
			for _, line := range tb {
				line := strings.TrimSpace(line)
				if line != "" {
					continue
				}
				notifs.TosyslogGen(fmt.Sprintf("%v %v", futils.GetCalleRuntime(), line), "ndpi")
				if strings.Contains(line, "Exec format error") {
					sockets.SET_INFO_INT("EnablenDPI", 0)
					notifs.SquidAdminMysql(0, "Unable to load nDPI module (Exec format error) [action=uninstall]", out, futils.GetCalleRuntime(), 82)
					Uninstall()
				}
			}

			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), out)
			return fmt.Errorf("%v %v", futils.GetCalleRuntime(), out)
		}
	}
	if !futils.IsModulesLoaded("xt_ndpi") {
		Uninstall()
		log.Error().Msgf("%v failed to load module xt_ndpi", futils.GetCalleRuntime())
		return fmt.Errorf("%v failed to load module xt_ndpi", futils.GetCalleRuntime())
	}

	if ifRulesExist() {
		log.Info().Msgf("%v firewall rule already enabled", futils.GetCalleRuntime())
		err := saveValue("/proc/net/xt_ndpi/flows", "limit=3000000")
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		err = saveValue("/proc/net/xt_ndpi/flows", "timeout=330")
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		return nil
	}
	iptables := futils.FindProgram("iptables")

	comment := fmt.Sprintf("-m comment --comment \"NDPI_TIME:%v\"", futils.TimeStampToString())
	cmd := fmt.Sprintf("%v -t mangle -I PREROUTING -m ndpi ! --error %v -j NDPI --flow-info", iptables, comment)
	log.Info().Msgf("%v %v", futils.GetCalleRuntime(), cmd)
	err, out := futils.ExecuteShell(cmd)
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line := strings.TrimSpace(line)
		if line != "" {
			continue
		}
		if strings.Contains(line, "No such file or directory") {
			return fmt.Errorf("%v %v", futils.GetCalleRuntime(), line)
		}
		log.Info().Msgf("%v [%v]", futils.GetCalleRuntime(), line)
	}

	if err != nil {
		log.Error().Msgf("%v %v %v", futils.GetCalleRuntime(), err.Error(), out)
		for _, line := range tb {
			line := strings.TrimSpace(line)
			if line != "" {
				continue
			}
			if futils.RegexFind(NDPIError1, line) {
				notifs.SquidAdminMysql(0, "Deep inspection, wrong package [{action}={uninstall}]", out, futils.GetCalleRuntime(), 82)
				sockets.SET_INFO_INT("EnablenDPI", 0)
				return fmt.Errorf("%v %v", futils.GetCalleRuntime(), line)
			}

			if strings.Contains(line, "xt_ndpi: kernel module not load") {
				notifs.SquidAdminMysql(0, "Deep inspection, Kernel module not loaded", out, futils.GetCalleRuntime(), 82)
				return fmt.Errorf("%v %v", futils.GetCalleRuntime(), line)
			}

		}

	}

	err = saveValue("/proc/net/xt_ndpi/flows", "limit=3000000")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}
	err = saveValue("/proc/net/xt_ndpi/flows", "timeout=330")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}
	return nil
}
func Export() {
	EnablenDPI := sockets.GET_INFO_INT("EnablenDPI")
	if EnablenDPI == 0 {
		return
	}
	futils.CreateDir("/home/artica/ndpi-temp")
	cat := futils.FindProgram("cat")
	zTime := futils.TimeStampToString()
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v /proc/net/xt_ndpi/flows > /home/artica/ndpi-temp/%v.ndpi /dev/null 2>&1", cat, zTime))
	_, _ = futils.ExecutePHP("exec.ndpi.flow.php --loop")
}

func saveValue(filePath string, value string) error {
	// Open the file in write-only mode
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	_, err = file.WriteString(value)
	if err != nil {
		return err
	}

	return nil
}
func Install() {

	DisablePostGres := sockets.GET_INFO_INT("DisablePostGres")
	if DisablePostGres == 1 {
		log.Error().Msgf("%v Install failed, need PostgreSQL")
		notifs.BuildProgress(110, "{install} {failed} need PostGreSQL", ProgressF)
		return
	}

	notifs.BuildProgress(10, "{install}", ProgressF)
	sockets.SET_INFO_INT("EnablenDPI", 1)

	notifs.BuildProgress(20, "{install} {starting}", ProgressF)
	err := Start()
	if err != nil {
		sockets.SET_INFO_INT("EnablenDPI", 0)
		notifs.BuildProgress(110, "{install} {failed}", ProgressF)
		return
	}
	conf := "xt_ndpi ndpi_enable_flow=1\n"
	_ = futils.FilePutContents("/etc/modules-load.d/xt_ndpi.conf", conf)
	dmesg := futils.FindProgram("dmesg")
	re := regexp.MustCompile(`xt_ndpi v.*?ndpi\s+([0-9\.\-]+)`)
	cmd := exec.Command(dmesg, "--kernel", "--nopager", "--notime", "--level", "info")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Msgf("%v Error executing dmesg: %v", futils.GetCalleRuntime(), output)
		return
	}

	lines := string(output)
	matches := re.FindStringSubmatch(lines)
	if len(matches) > 1 {
		// Process the matched version
		version := matches[1]
		notifs.BuildProgress(55, fmt.Sprintf("{APP_NDPI} v%s", version), ProgressF)
		futils.CreateDir("/usr/share/nDPI")
		_ = futils.FilePutContents("/usr/share/nDPI/REAL", version)
	}
	err = Start()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		notifs.BuildProgress(110, "{failed} "+err.Error(), ProgressF)
		return
	}

	notifs.BuildProgress(100, "{install} {success}", ProgressF)
}
func Uninstall() {
	notifs.BuildProgress(10, "{uninstall}", ProgressF)
	sockets.SET_INFO_INT("EnablenDPI", 0)
	notifs.BuildProgress(50, "{uninstall}", ProgressF)
	UninstallTemp()
	articaunix.RemoveServiceINIT("/etc/init.d/nDPI")
	_ = futils.RmRF("/home/artica/ndpi-temp")
	notifs.BuildProgress(100, "{success}", ProgressF)
}
func ruleTime() int64 {
	err, Tables := currentIPTablesRules()
	if err != nil {
		return 0
	}
	for _, line := range Tables {
		if strings.Contains(line, "NDPI_TIME:") {
			zTime := futils.RegexGroup1(NDPITime1, line)
			if len(zTime) > 0 {
				return futils.StrToInt64(zTime)
			}
			return 0
		}
	}
	return 0
}
func ifRulesExist() bool {
	err, Tables := currentIPTablesRules()
	if err != nil {
		return false
	}
	for _, line := range Tables {
		if strings.Contains(line, "NDPI --flow-info") {
			return true
		}
	}

	return false
}
func UninstallTemp() {

	futils.DeleteFile("/etc/modules-load.d/xt_ndpi.conf")

	if futils.IsModulesLoaded("xt_ndpi") {
		conntrack := futils.FindProgram("conntrack")
		if futils.FileExists(conntrack) {
			_, _ = futils.ExecuteShell(fmt.Sprintf("%v -F", conntrack))
		}

		modprobe := futils.FindProgram("modprobe")
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v -r %v", modprobe, "xt_ndpi"))
	}
	cronFile := []string{
		"/etc/cron.d/ndpi-schedule", "/etc/cron.d/ndpi-parse", "/etc/cron.d/ndpi-stats", "/etc/cron.d/ndpi-month",
	}
	RebootCron := false
	for _, file := range cronFile {
		if futils.FileExists(file) {
			RebootCron = true
			futils.DeleteFile(file)
		}
	}
	if RebootCron {
		_, _ = futils.ExecuteShell("/etc/init.d/cron reload")
	}
}
func currentIPTablesRules() (error, []string) {
	var stdout bytes.Buffer
	IptablesSave := futils.FindProgram("iptables-save")
	cmd := exec.Command(IptablesSave)
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return err, []string{}
	}
	Out := stdout.String()
	return nil, strings.Split(Out, "\n")
}

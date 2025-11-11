package SuricataService

import (
	"PFRing"
	"fmt"
	"futils"
	"httpclient"
	"ipclass"
	"notifs"
	"os"
	"path/filepath"
	"regexp"
	"sockets"
	"strings"
	"suricata/SuricataTools"
	"time"

	"github.com/rs/zerolog/log"
)

const Duration = 1 * time.Second
const ServiceName = "IDS Daemon"
const PidPath = SuricataTools.PidPath
const TokenEnabled = "EnableSuricata"
const MainBinary = SuricataTools.MainBinary
const ProgressF = "suricata.progress"

func Start() error {
	if !futils.FileExists(MainBinary) {
		return fmt.Errorf("%v not found", MainBinary)
	}
	Enabled := sockets.GET_INFO_INT(TokenEnabled)

	if futils.FileExists("/etc/monit/conf.d/APP_SURICATA_TAIL.monitrc") {
		futils.DeleteFile("/etc/monit/conf.d/APP_SURICATA_TAIL.monitrc")
	}

	if Enabled == 0 {
		return fmt.Errorf("disabled feature")
	}
	futils.CreateDir("/run/suricata")
	futils.CreateDir("/var/log/suricata")
	futils.Chmod("/usr/share/artica-postfix/bin/sidrule", 0755)

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

	notifs.BuildProgress(56, "{configuring} ethtool", ProgressF)
	removeOldSuricataLogs()
	ethtool := futils.FindProgram("ethtool")

	if futils.FileExists(ethtool) {
		SuricataInterface := sockets.GET_INFO_STR("SuricataInterface")
		if SuricataInterface == "" {
			SuricataInterface = ipclass.DefaultInterface()
			log.Info().Msgf("%v Default interface %v", futils.GetCalleRuntime(), SuricataInterface)
		}
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v -K %v gro off", ethtool, SuricataInterface))
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v -K %v lro off", ethtool, SuricataInterface))
	}
	setcapBin := futils.FindProgram("setcap")

	_, _ = futils.ExecuteShell(fmt.Sprintf("%v cap_net_raw,cap_net_admin=eip %v", setcapBin, MainBinary))
	if !futils.FileExists("/etc/suricata/suricata.yaml") {
		log.Warn().Msgf("%v %v no such file, reconfigure...", futils.GetCalleRuntime(), "/etc/suricata/suricata.yaml")
		_ = httpclient.SuricataAPIUnix("/reconfigure/wait")
	}
	cmd := SuricataTools.Commands()
	log.Info().Msgf("%v Starting [%v]", futils.GetCalleRuntime(), cmd)
	futils.DeleteFile(PidPath)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	notifs.BuildProgress(57, "{starting}...", ProgressF)
	pid, ExecOut, errOut, err := SuricataTools.RunSuricata()

	out := strings.TrimSpace(errOut) + " " + strings.TrimSpace(ExecOut)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), out)

	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		log.Info().Msgf("%v [%v]", futils.GetCalleRuntime(), line)
	}

	if futils.ProcessExists(pid) {
		log.Info().Msgf("%v Starting...%v [SUCCESS]", futils.GetCalleRuntime(), ServiceName)
		return nil
	}

	if err != nil {
		if strings.Contains(err.Error(), "found with name pfring") {
			LibPath := PFRing.PFringSoPath()
			log.Error().Msgf("%v it seems the pfring library (%v) is not defined in configuration. -> Reconfigure smooth", futils.GetCalleRuntime(), LibPath)
			_ = httpclient.SuricataAPIUnix("/reconfigure/smooth")
			return fmt.Errorf("missing library [%v]", LibPath)
		}

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
func GetPID() int {

	pid := futils.GetPIDFromFile(PidPath)
	if futils.ProcessExists(pid) {
		return pid
	}
	Binary := futils.FindProgram("suricata")

	if len(Binary) < 3 {
		return 0
	}
	return futils.PIDOFPattern("suricata --pidfile")
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

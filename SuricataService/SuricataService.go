package SuricataService

import (
	"PFRingIfaces"
	"bytes"
	"context"
	"errors"
	"fmt"
	"futils"
	"ipclass"
	"notifs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sockets"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const Duration = 1 * time.Second
const ServiceName = "IDS Daemon"
const PidPath = "/run/suricata/suricata.pid"
const TokenEnabled = "EnableSuricata"
const MainBinary = "/usr/bin/suricata"
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

	cmd := Commands()
	log.Info().Msgf("%v Starting [%v]", futils.GetCalleRuntime(), cmd)
	futils.DeleteFile(PidPath)
	log.Debug().Msgf("%v [%v]", futils.GetCalleRuntime(), cmd)
	notifs.BuildProgress(57, "{starting}...", ProgressF)
	pid, ExecOut, errOut, err := RunSuricata()

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
func Commands() []string {
	var cm []string
	cm = append(cm, "--pidfile", "/run/suricata/suricata.pid")
	cm = append(cm, "--pfring")
	ifaces := PFRingIfaces.Load()
	for _, iface := range ifaces {
		if ipclass.IsInterfaceExists(iface.Iface) {
			cm = append(cm, fmt.Sprintf("--pfring-int=%v", iface.Iface))
		}
	}

	cm = append(cm, "-D")
	return cm
}
func RunSuricata() (int, string, string, error) {
	const (
		timeoutTotal = 20 * time.Second
	)

	// Extract pidfile path from Commands() so we know what to wait for.

	ctx, cancel := context.WithTimeout(context.Background(), timeoutTotal)
	defer cancel()

	args := Commands()
	cmd := exec.CommandContext(ctx, MainBinary, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	if err := cmd.Start(); err != nil {
		// If context already expired, surface that
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return 0, stdout.String(), stderr.String(), fmt.Errorf("suricata start timed out (pre-start): %w", ctx.Err())
		}
		return 0, stdout.String(), stderr.String(), fmt.Errorf("failed to start suricata: %w (stderr: %s)", err, stderr.String())
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	// Wait for launcher process to end or timeout.
	select {
	case err := <-waitErr:
		// Launcher exited (expected with -D). Record remaining time for PID wait.
		if err != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// Non-zero exit before daemonizing
			return 0, stdout.String(), stderr.String(), fmt.Errorf("suricata launcher exited with error: %w (stderr: %s)", err, stderr.String())
		}
	case <-ctx.Done():
		// Launcher did not complete in time; attempt to kill the remaining foreground proc.
		_ = cmd.Process.Kill()
		return 0, stdout.String(), stderr.String(), fmt.Errorf("suricata start timed out after %s", timeoutTotal)
	}

	// Poll for PID file within the remaining time budget.
	remaining := timeoutTotal - time.Since(start)
	if remaining <= 0 {
		return 0, stdout.String(), stderr.String(), fmt.Errorf("suricata started but PID check exceeded %s window", timeoutTotal)
	}

	pid, err := waitForPIDFile(remaining)
	if err != nil {
		// Not fatal in all contexts, but return as error so caller can decide.
		return 0, stdout.String(), stderr.String(), fmt.Errorf("suricata started, but PID file not ready: %w", err)
	}

	return pid, stdout.String(), stderr.String(), nil
}
func waitForPIDFile(maxWait time.Duration) (int, error) {
	deadline := time.Now().Add(maxWait)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		// Try read
		if b, err := os.ReadFile(PidPath); err == nil {
			s := strings.TrimSpace(string(b))
			if s != "" {
				if pid, perr := strconv.Atoi(s); perr == nil && pid > 0 {
					return pid, nil
				}
			}
		}
		// Check timeout
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("pid file %q not found or invalid within %s", PidPath, maxWait)
		}
		<-ticker.C
	}
}

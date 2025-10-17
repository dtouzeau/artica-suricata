package GlobalsValues

import (
	"CacheMem"
	"bytes"
	"context"
	"errors"
	"fmt"
	"futils"
	"os"
	"os/exec"
	"regexp"
	"sockets"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const PROGRESS_DIR = "/usr/share/artica-postfix/ressources/logs/web"

var RegexVersion = regexp.MustCompile(`^([0-9]+)\.([0-9]+)`)

type SystemDConfig struct {
	InitdPath  string
	PidPath    string
	PidPattern string
}

var RegexVersionHaProxy = regexp.MustCompile(`^(HA-Proxy|HAProxy)\s+version\s+([0-9\.]+)`)

const ArticaBinary = "/usr/sbin/artica-phpfpm-service"

func HaProxyVersion(path string) string {
	if len(path) == 0 {
		path = futils.FindProgram("haproxy")
	}
	if path == "" {
		return "0.0.0"
	}

	val := CacheMem.GetStringFunc()
	if len(val) > 1 {
		return val
	}

	_, out := futils.ExecuteShell(fmt.Sprintf("%v -v", path))
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_, version := futils.RegexGroup2(RegexVersionHaProxy, line)
		if len(version) > 0 {
			CacheMem.SetStringFunc(version)
			return version
		}
	}
	return "0.0.0"
}

func RunDaemonReload() (combinedOutput string, err error) {
	// Create a context with a 10-second timeout
	TimeOut := time.Duration(10)
	ctx, cancel := context.WithTimeout(context.Background(), TimeOut*time.Second)
	defer cancel() // Ensure the context is canceled to release resources

	Masterbin := futils.FindProgram("systemctl")
	var outputBuf bytes.Buffer

	cmd := exec.CommandContext(ctx, Masterbin, "daemon-reload")
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf // Redirect stderr to the same buffer as stdout
	cmd.Env = append(cmd.Env, futils.ExecEnv()...)

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start %v: %v", Masterbin, err)
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

// systemctl set-default multi-user.target
func RunSystemctlSetDefaultTarget() string {
	TimeOut := time.Duration(10)
	ctx, cancel := context.WithTimeout(context.Background(), TimeOut*time.Second)
	defer cancel()
	systemctl := futils.FindProgram("systemctl")
	if !futils.FileExists(systemctl) {
		return ""
	}
	var outputBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, systemctl, "set-default", "multi-user.target")
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf // Redirect stderr to the same buffer as stdout
	cmd.Env = append(cmd.Env, futils.ExecEnv()...)
	if err := cmd.Start(); err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return ""
	}
	err := cmd.Wait()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), "Timed-out!")
			return outputBuf.String()
		}
		return outputBuf.String()
	}
	return outputBuf.String()
}
func RunSystemctlGetDefault() string {
	TimeOut := time.Duration(10)
	ctx, cancel := context.WithTimeout(context.Background(), TimeOut*time.Second)
	defer cancel()
	systemctl := futils.FindProgram("systemctl")
	if !futils.FileExists(systemctl) {
		return ""
	}
	var outputBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, systemctl, "get-default")
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf // Redirect stderr to the same buffer as stdout
	cmd.Env = append(cmd.Env, futils.ExecEnv()...)
	if err := cmd.Start(); err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return ""
	}
	err := cmd.Wait()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), "Timed-out!")
			return outputBuf.String()
		}
		return outputBuf.String()
	}
	return outputBuf.String()
}
func RunDaemonStatus(UnitName string) (combinedOutput string, err error) {
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

func RunDaemonStart(serviceName string) (combinedOutput string, err error) {
	TimeOut := time.Duration(10)
	ctx, cancel := context.WithTimeout(context.Background(), TimeOut*time.Second)
	defer cancel() // Ensure the context is canceled to release resources

	Masterbin := futils.FindProgram("systemctl")
	var outputBuf bytes.Buffer

	cmd := exec.CommandContext(ctx, Masterbin, "start", serviceName)
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
func RunDaemonStop(serviceName string) (combinedOutput string, err error) {
	// Create a context with a 10-second timeout
	TimeOut := time.Duration(10)
	ctx, cancel := context.WithTimeout(context.Background(), TimeOut*time.Second)
	defer cancel() // Ensure the context is canceled to release resources

	Masterbin := futils.FindProgram("systemctl")
	var outputBuf bytes.Buffer

	cmd := exec.CommandContext(ctx, Masterbin, "stop", serviceName)
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

func SystemdStatus() (string, error) {
	ctx := context.Background()
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
	}
	Masterbin := futils.FindProgram("systemctl")
	cmd := exec.CommandContext(ctx, Masterbin, "is-system-running")
	stdout, err := cmd.Output()

	status := strings.TrimSpace(string(stdout))
	// If the command failed but produced a status, prefer returning the status.
	if status != "" {
		return strings.ToLower(status), nil
	}

	// Try to surface a more meaningful error when no status was captured.
	if err != nil {
		// If it's a context timeout/cancel, surface that directly.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return "", err
		}
		// If it's an ExitError without output, return the error.
		return "", err
	}

	// No output and no error is unexpected; treat as unknown.
	return "unknown", nil
}

func StartSystemd(config SystemDConfig) bool {
	exePath, err := os.Executable()
	if err != nil {
		log.Error().Msgf("%v Failed to get executable path", futils.GetCalleRuntime())
		return false
	}
	state, err := SystemdStatus()
	if err != nil {
		log.Debug().Msgf("%v Failed to get systemd status", futils.GetCalleRuntime())
		return false
	}
	if state != "running" {
		log.Debug().Msgf("%v Systemd is not running", futils.GetCalleRuntime())
		return false
	}

	BaseName := futils.Basename(exePath)
	if BaseName == "artica-phpfpm-service" {
		return false
	}
	systemctl := futils.FindProgram("systemctl")
	if !futils.FileExists(systemctl) {
		return false
	}
	ServiceName := futils.Basename(config.InitdPath)
	if !futils.FileExists(fmt.Sprintf("/etc/systemd/system/%s.service", ServiceName)) {
		return false
	}
	log.Warn().Msgf("%v Starting %v", futils.GetCalleRuntime(), ServiceName)
	out, err := RunDaemonStart(ServiceName)

	if strings.Contains(out, "daemon-reload") {
		out, _ = RunDaemonReload()
		if len(out) > 2 {
			log.Info().Msgf("%v %v", futils.GetCalleRuntime(), out)
		}
	}
	pid := getPID(config)
	if futils.ProcessExists(pid) {
		return true
	}

	return false

}
func StopBySystemd(config SystemDConfig) bool {
	systemctl := futils.FindProgram("systemctl")
	if !futils.FileExists(systemctl) {
		return false
	}

	state, err := SystemdStatus()
	if err != nil {
		log.Debug().Msgf("%v Failed to get systemd status", futils.GetCalleRuntime())
		return false
	}
	if state != "running" {
		log.Debug().Msgf("%v Systemd is not running", futils.GetCalleRuntime())
		return false
	}

	ServiceName := futils.Basename(config.InitdPath)
	if !futils.FileExists(fmt.Sprintf("/etc/systemd/system/%s.service", ServiceName)) {
		return false
	}

	exePath, _ := os.Executable()
	BaseName := futils.Basename(exePath)
	if BaseName == "artica-phpfpm-service" {
		return false
	}

	out, _ := RunDaemonStop(ServiceName)
	if strings.Contains(out, "daemon-reload") {
		out, _ = RunDaemonReload()
		log.Info().Msgf("%v %v", futils.GetCalleRuntime(), out)
	}
	pid := getPID(config)
	if !futils.ProcessExists(pid) {
		return true
	}
	return false
}
func getPID(config SystemDConfig) int {
	pid := futils.GetPIDFromFile(config.PidPath)
	if futils.ProcessExists(pid) {
		return pid
	}
	if len(config.PidPattern) > 3 {
		pid = futils.PIDOFPattern(config.PidPattern)
	}
	return pid
}

type HaVers struct {
	Major int
	Minor int
	Ver   string
}

func HaProxyVersions() HaVers {
	var h HaVers
	h.Ver = sockets.GET_INFO_STR("HAPROXY_VERSION")
	h.Major = 0
	h.Minor = 0
	a, b := futils.RegexGroup2(RegexVersion, h.Ver)
	if len(a) > 0 {
		h.Major = futils.StrToInt(a)
		h.Minor = futils.StrToInt(b)
	}
	return h
}
func UseDNSForEUBackendsUDP() []string {

	DNSForEUBackends := sockets.GET_INFO_INT("UseDNSForEUBackends")
	if DNSForEUBackends == 0 {
		return []string{}
	}
	if DNSForEUBackends == 1 {
		return []string{"86.54.11.1", "86.54.11.201"}
	}
	if DNSForEUBackends == 2 {
		return []string{"86.54.11.12", "86.54.11.212"}
	}
	if DNSForEUBackends == 3 {
		return []string{"86.54.11.13", "86.54.11.213"}
	}
	if DNSForEUBackends == 4 {
		return []string{"6.54.11.11", "86.54.11.211"}
	}
	if DNSForEUBackends == 5 {
		return []string{"86.54.11.100", "86.54.11.200"}
	}
	return []string{}
}

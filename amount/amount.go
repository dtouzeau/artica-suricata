package amount

import (
	"bufio"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
	"notifs"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

type ShareSettings struct {
	Hostname    string `json:"Hostname"`
	ShareFolder string `json:"ShareFolder"`
	MountPoint  string `json:"MountPoint"`
	UserName    string `json:"UserName"`
	Password    string `json:"Password"`
	Domain      string `json:"Domain"`
}

const fstabPath = "/etc/fstab"

var RegexFsTabByDest = regexp.MustCompile(`^.+?\s+(.+?)\s+.+?\s+.+?`)

func isMounted(path string) bool {

	file, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)

		if len(parts) >= 2 {
			mountPoint := parts[1]
			if mountPoint == path {
				return true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return false
	}

	return false
}
func Unmount(mountPoint string) error {

	if !isMounted(mountPoint) {
		return nil
	}
	umount := futils.FindProgram("umount")
	cmd := exec.Command(umount, "-l", mountPoint)

	// Run executes the command and returns an error if any
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to unmount %s: %w", mountPoint, err)
	}
	return nil
}
func SmbShare(opts ShareSettings) error {
	if len(opts.MountPoint) < 3 {
		return fmt.Errorf(fmt.Sprintf("Mount Path, no such defined path"))
	}
	if len(opts.ShareFolder) < 3 {
		return fmt.Errorf(fmt.Sprintf("Share Path, no defined such path"))
	}
	if isMounted(opts.MountPoint) {
		return nil
	}
	opts.Hostname = strings.ReplaceAll(opts.Hostname, `\`, "")
	opts.Hostname = strings.ReplaceAll(opts.Hostname, `/`, "")
	opts.ShareFolder = futils.StripLeadingSlash(opts.ShareFolder)

	if strings.Contains(opts.ShareFolder, "/") {
		tb := strings.Split(opts.ShareFolder, "/")
		opts.ShareFolder = tb[0]
	}

	SharePath := fmt.Sprintf("//%v/%v", opts.Hostname, opts.ShareFolder)
	var patternRegex []string
	var args []string
	mount := futils.FindProgram("mount")
	mountCifs := futils.FindProgram("mount.cifs")
	mount_smbfs := futils.FindProgram("mount.smbfs")
	var options []string
	args = append(args, "-t")

	if !futils.FileExists(mountCifs) {
		if futils.FileExists(mount_smbfs) {
			patternRegex = append(patternRegex, mount_smbfs)
			args = append(args, "smbfs")
		}
	}

	if futils.FileExists(mountCifs) {
		patternRegex = append(patternRegex, mountCifs)
		args = append(args, "cifs")
	}

	args = append(args, SharePath)
	args = append(args, opts.MountPoint)
	patternRegex = append(patternRegex, opts.MountPoint)

	args = append(args, "-o")

	RegexProcess := strings.Join(patternRegex, ".*?")
	Pid := futils.PIDOFPattern(RegexProcess)
	if futils.ProcessExists(Pid) {
		return fmt.Errorf("already mount process (%v) exists PID %d", RegexProcess, Pid)
	}

	if strings.Contains(opts.UserName, "@") {
		tb := strings.Split(opts.UserName, "@")
		opts.UserName = tb[0]
		opts.Domain = tb[1]
	}

	options = append(options, fmt.Sprintf("username=%v", opts.UserName))
	if len(opts.Domain) > 3 {
		options = append(options, fmt.Sprintf("domain=%v", opts.Domain))
	}
	options = append(options, fmt.Sprintf("password=%v", opts.Password))
	options = append(options, "vers=2.0")

	args = append(args, strings.Join(options, ","))
	// Prepare the mount command
	cmd := exec.Command(mount, args...)
	log.Debug().Msgf("%v [%v %v]", futils.GetCalleRuntime(), mount, strings.Join(args, " "))

	// Execute the mount command
	output, err := cmd.CombinedOutput()
	if err != nil {
		//log.Error().Msg(fmt.Sprintf("%v %v", mount, strings.Join(args, " ")))
		return fmt.Errorf(fmt.Sprintf("%v Error mounting %v %v [%v]", futils.GetCalleRuntime(), SharePath, err.Error(), string(output)))
	}

	return nil
}
func MountPointOf(path string) string {

	file, err := os.Open("/proc/mounts")
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)

		if len(parts) >= 2 {
			mountSource := parts[0]
			//fmt.Println("Found ", path, "->", mountSource, "(", parts[1], ")")
			if mountSource == path {
				return parts[1]
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return ""
	}

	return ""
}
func Umount(mountPoint string) error {

	err := unix.Unmount(mountPoint, 0)
	if err != nil {
		log.Warn().Msgf("%v Umount %v %v going to force...", futils.GetCalleRuntime(), mountPoint, err.Error())
		err := unix.Unmount(mountPoint, unix.MNT_FORCE)
		if err != nil {
			return fmt.Errorf("%v Failed to force unmount %s: %v", futils.GetCalleRuntime(), mountPoint, err.Error())

		}
	}

	return nil

}

func MountPointOfDest(path string) string {

	file, err := os.Open("/proc/mounts")
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)

		if len(parts) >= 2 {
			mountSource := parts[0]
			MountDest := parts[1]
			if MountDest == path {
				return mountSource
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return ""
	}

	return ""
}

func GetBindMountSource(target string) (string, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		log.Debug().Msg(fmt.Sprintf("%v error opening /proc/self/mountinfo: %v", futils.GetCalleRuntime(), err))
		return "", fmt.Errorf("error opening /proc/self/mountinfo: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, " ")
		if len(fields) < 10 {
			continue
		}
		Source := fields[3]
		if Source == "/" {
			continue
		}
		mountPoint := fields[4]
		log.Debug().Msg(fmt.Sprintf("%v) mountpoint=[%v]", futils.GetCalleRuntime(), mountPoint))
		//mountOptions := fields[5]
		//optionalFields := fields[6]
		//optionalNone := fields[7]
		optionalDisk := fields[8]
		optionalDev := fields[9]
		//fmt.Println("[0]", fields[0], "[1]", fields[1], "[2]", fields[2], "[3]", fields[3])

		if mountPoint == target {
			log.Debug().Msg(fmt.Sprintf("%v) [OK]mountpoint=[%v]==[%v] optionalDisk=%v optionalDev=%v", futils.GetCalleRuntime(), mountPoint, target, optionalDisk, optionalDev))

			if !strings.HasPrefix(optionalDev, "/dev") {
				log.Debug().Msg(fmt.Sprintf("%v) %v doesn't contains /dev", futils.GetCalleRuntime(), optionalDev))
				if strings.HasPrefix(optionalDisk, "/dev") {
					optionalDev = optionalDisk
				}
			}
			log.Debug().Msg(fmt.Sprintf("%v) Find the mounted point of %v", futils.GetCalleRuntime(), optionalDev))
			Path := MountPointOf(optionalDev)
			FinalTarget := fmt.Sprintf("%v%v", Path, Source)
			return FinalTarget, nil
		}

	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading /proc/self/mountinfo: %v", err)
	}

	return "", fmt.Errorf("the directory %s is not a bind mount point", target)
}
func DirectoryTarget(DirectoryPath string) string {

	if futils.IsLink(DirectoryPath) {
		DirectoryPath = futils.ReadLink(DirectoryPath)
	}

	if !futils.IsDirDirectory(DirectoryPath) {
		return ""
	}

	Source, _ := GetBindMountSource(DirectoryPath)
	if len(Source) > 3 {
		return strings.ReplaceAll(Source, "//", "/")
	}
	return strings.ReplaceAll(DirectoryPath, "//", "/")
}

func MoveBinDirectory(FromPath string, ToPath string, SuffixDir string) {
	rsync := futils.FindProgram("rsync")
	if !futils.FileExists(rsync) {
		fmt.Println("rsync required")
		notifs.BuildProgress(110, "Rsync required...", "movelogs.progress")
		return
	}
	log.Debug().Msgf("%v Checking: %v", futils.GetCalleRuntime(), FromPath)
	FromPathSource := DirectoryTarget(FromPath)
	if len(FromPathSource) == 0 {
		log.Error().Msgf("%v %v failed to get source", futils.GetCalleRuntime(), FromPath)
		notifs.BuildProgress(110, futils.GetCalleRuntime(), "movelogs.progress")
		return
	}
	ToPath = fmt.Sprintf("%v/%v", ToPath, SuffixDir)
	ToPath = strings.ReplaceAll(ToPath, "//", "/")
	futils.CreateDir(ToPath)
	if !futils.IsDirDirectory(ToPath) {
		notifs.BuildProgress(110, ToPath+" permission denied", "movelogs.progress")
		return
	}

	if FromPath == "/var/log" {
		stopAllServices()
	}
	notifs.BuildProgress(40, "{moving}", "movelogs.progress")
	MovedDir := fmt.Sprintf("%v-%d", FromPathSource, futils.TimeStamp())
	fmt.Println("Move", FromPathSource, "to", MovedDir)
	err := futils.RenameWithRetry(FromPathSource, MovedDir, 15)
	if err != nil {
		startAllServices()
		notifs.BuildProgress(110, fmt.Sprintf("Error renaming directory: %v", err.Error()), "movelogs.progress")
		fmt.Printf("Error renaming directory: %v\n", err)
		return
	}
	notifs.BuildProgress(50, "{mouting}", "movelogs.progress")
	mount := futils.FindProgram("mount")
	futils.CreateDir(FromPath)

	if futils.IsMounted(FromPath) {
		umount := futils.FindProgram("umount")
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v -l %v", umount, FromPath))
	}

	cmd := fmt.Sprintf("%v --bind %v %v", mount, ToPath, FromPath)
	fmt.Println(cmd)
	err, out := futils.ExecuteShell(cmd)
	if err != nil {
		fmt.Println(futils.GetCalleRuntime(), out, "---------- >FAILED!")
		_ = os.Rename(MovedDir, FromPathSource)
		startAllServices()
		notifs.BuildProgress(110, fmt.Sprintf("Mount bind failed: %v", err.Error()), "movelogs.progress")
		return
	}
	notifs.BuildProgress(60, fmt.Sprintf("%v --> %v", MovedDir, ToPath), "movelogs.progress")
	cmd = fmt.Sprintf("%v -av %v/ %v/", rsync, MovedDir, ToPath)
	log.Warn().Msgf("%v %v", futils.GetCalleRuntime(), cmd)
	systemctl := futils.FindProgram("systemctl")
	if FromPath == "/var/log" {
		if futils.FileExists(systemctl) {
			_, _ = futils.ExecuteShell(fmt.Sprintf("%v stop var-log.mount", systemctl))
		}
	}

	_, out = futils.ExecuteShell(cmd)
	fmt.Println("Remove", MovedDir)
	_ = futils.RmRF(MovedDir)
	fmt.Println(out)
	_ = RemoveFstabContains(FromPath)
	_ = RemoveFstabEntry(ToPath)
	err = AddBindFstabEntry(ToPath, FromPath)

	if futils.FileExists(systemctl) {
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v daemon-reload", systemctl))
	}

	if err != nil {
		startAllServices()
		fmt.Println(err.Error())
		notifs.BuildProgress(110, err.Error(), "movelogs.progress")
		return
	}

	startAllServices()
	fmt.Println("Success..")
	notifs.BuildProgress(100, "{success}", "movelogs.progress")

}
func allServices() []string {
	return []string{"artica-status", "cron", "artica-ad-rest", "monit", "hacluster", "unbound", "squid", "artica-postgres", "dnscache", "slapd", "pgbouncer", "suricata",
		"wazuh-agent", "vnstat", "ntp", "web-error-page", "collectd", "munin", "cloudflared", "bandwhich", "dstat", "dnsdist", "nginx", "crowdsec"}
}
func stopAllServices() {
	services := allServices()
	for _, svc := range services {
		if futils.FileExists("/etc/init.d/" + svc) {
			notifs.BuildProgress(31, "Stopping "+svc, "movelogs.progress")
			fmt.Println("Stopping", svc)
			_, _ = futils.ExecuteShell("/etc/init.d/" + svc + " stop")
		}
	}
}
func startAllServices() {
	services := allServices()
	for _, svc := range services {
		if futils.FileExists("/etc/init.d/" + svc) {
			fmt.Println("Starting", svc)
			notifs.BuildProgress(90, "Starting "+svc, "movelogs.progress")
			_, _ = futils.ExecuteShell("/etc/init.d/" + svc + " start")
		}
	}
}
func AddBindFstabEntry(source, destination string) error {
	const fstabPath = "/etc/fstab"

	tb := strings.Split(futils.FileGetContents(fstabPath), "\n")

	var lines []string
	entry := fmt.Sprintf("%s %s none bind 0 0", source, destination)

	for _, line := range tb {
		lines = append(lines, line)
		if strings.TrimSpace(line) == entry {
			log.Warn().Msgf("%v Entry %v already exists in /etc/fstab", destination)
			return nil
		}
	}
	lines = append(lines, entry)
	_ = futils.FilePutContents(fstabPath, strings.Join(lines, "\n"))
	log.Info().Msgf("%v Entry %v added to /etc/fstab successfully", futils.GetCalleRuntime(), destination)
	return nil
}
func RemoveFstabEntryDest(Desintation string) error {
	file, err := os.Open(fstabPath)
	if err != nil {
		return fmt.Errorf("error opening /etc/fstab: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading /etc/fstab: %v", err)
	}
	var newLines []string
	siFound := false
	for _, line := range lines {
		SecondEntry := futils.RegexGroup1(RegexFsTabByDest, line)
		if len(SecondEntry) > 1 {
			if SecondEntry == Desintation {
				siFound = true
				UMountBin := futils.FindProgram("umount")
				_, _ = futils.ExecuteShell(fmt.Sprintf("%v -l %v", UMountBin, Desintation))
				continue
			}
		}
		newLines = append(newLines, line)
	}
	if !siFound {
		return nil
	}
	file, err = os.OpenFile(fstabPath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("error opening /etc/fstab for writing: %v", err)
	}

	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range newLines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("error writing to /etc/fstab: %v", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("error flushing /etc/fstab: %v", err)
	}

	log.Info().Msgf("%v Entry %v removed from /etc/fstab successfully", futils.GetCalleRuntime(), Desintation)
	return nil

}

func RemoveFstabContains(filestring string) error {

	file, err := os.Open(fstabPath)
	if err != nil {
		return fmt.Errorf("error opening /etc/fstab: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading /etc/fstab: %v", err)
	}

	var newLines []string
	for _, line := range lines {
		if !strings.Contains(strings.TrimSpace(line), filestring) {
			newLines = append(newLines, line)
		}
	}
	file, err = os.OpenFile(fstabPath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("error opening /etc/fstab for writing: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	writer := bufio.NewWriter(file)
	for _, line := range newLines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("error writing to /etc/fstab: %v", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("error flushing /etc/fstab: %v", err)
	}

	fmt.Println("Entry removed from /etc/fstab successfully")
	return nil
}

func RemoveFstabEntry(source string) error {

	file, err := os.Open(fstabPath)
	if err != nil {
		return fmt.Errorf("error opening /etc/fstab: %v", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading /etc/fstab: %v", err)
	}

	var newLines []string
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), source) {
			newLines = append(newLines, line)
		}
	}
	file, err = os.OpenFile(fstabPath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("error opening /etc/fstab for writing: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range newLines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("error writing to /etc/fstab: %v", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("error flushing /etc/fstab: %v", err)
	}

	fmt.Println("Entry removed from /etc/fstab successfully")
	return nil
}

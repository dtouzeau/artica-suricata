package futils

/*
#include <unistd.h>
*/
import "C"
import (
	"CacheMem"
	"DNSMem"
	"bufio"
	"bytes"
	"compressor"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"html"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sockets"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/elliotchance/phpserialize"
	"github.com/jsgilmore/mount"
	. "github.com/klauspost/cpuid/v2"
	"github.com/leeqvip/gophp"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/process"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/sys/unix"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

const kiloByte = int64(1 << 10) // 1 KiB

const (
	FS_IMMUTABLE_FL = 0x00000010 // from <linux/fs.h>
	FS_IOC_SETFLAGS = 0x40086602 // from <linux/fs.h>
	FS_IOC_GETFLAGS = 0x80086601 // Ioctl command to get file flags from <linux/fs.h>
)

type ProcessInfo struct {
	PID        int
	AccessType string
	Cmdline    string
}

// FuserOutput represents the entire parsed line from the fuser command.
type FuserOutput struct {
	FilePath  string
	Processes []ProcessInfo
}

var tcpPattern = regexp.MustCompile(`^[a-z]+\s+[0-9]+\s+[0-9]+\s+.*?:([0-9]+)\s+.+?:.*?\s+LISTEN\s+([0-9]+)/`)
var replacePattern = regexp.MustCompile(`&([a-zA-Z])(uml|acute|grave|circ|tilde|cedil|ring);`)
var futilsPattern1 = regexp.MustCompile(`size=([0-9]+)k`)
var futilsPattern2 = regexp.MustCompile(`^regex:(.+)`)
var futilsPattern3 = regexp.MustCompile(`^\*-(.+)`)
var futilsPattern4 = regexp.MustCompile(`^(.+?)\*$`)
var futilsPattern5 = regexp.MustCompile(`^\*\\.(.+)`)
var futilsPattern6 = regexp.MustCompile(`^\*(.+)`)
var futilsDotPrefix = regexp.MustCompile(`^\.(.+)`)

type ParseURL struct {
	Protocol string
	Hostname string
	Path     string
	Port     int
	Query    string
}
type OpenFile struct {
	PID     int
	User    string
	Command string
	FD      string // e.g. "3", "10"
	Target  string // resolved target of the FD symlink
}

type ProcStatus struct {
	Name                       string
	Umask                      string
	State                      string
	Tgid                       int
	Ngid                       int
	Pid                        int
	PPid                       int
	TracerPid                  int
	Uid                        [4]int
	Gid                        [4]int
	FDSize                     int
	Groups                     string
	NStgid                     int
	NSpid                      int
	NSpgid                     int
	NSsid                      int
	VmPeak                     string
	VmSize                     string
	VmLck                      string
	VmPin                      string
	VmHWM                      string
	VmRSS                      string
	RssAnon                    string
	RssFile                    string
	RssShmem                   string
	VmData                     string
	VmStk                      string
	VmExe                      string
	VmLib                      string
	VmPTE                      string
	VmSwap                     string
	HugetlbPages               string
	CoreDumping                int
	Threads                    int
	SigQ                       string
	SigPnd                     string
	ShdPnd                     string
	SigBlk                     string
	SigIgn                     string
	SigCgt                     string
	CapInh                     string
	CapPrm                     string
	CapEff                     string
	CapBnd                     string
	CapAmb                     string
	NoNewPrivs                 int
	Seccomp                    int
	Speculation_Store_Bypass   string
	Cpus_allowed               string
	Cpus_allowed_list          string
	Mems_allowed               string
	Mems_allowed_list          string
	Voluntary_ctxt_switches    int
	Nonvoluntary_ctxt_switches int
}

type DateCompose struct {
	Year  int
	Month int
	Day   int
	Hour  int
	Min   int
	Unix  int64
}
type File struct {
	os.FileInfo
	Path string
}

type MountStr struct {
	Path   string // Device path or label
	Target string // Mount point
	Type   string // Filesystem type
}

type ProcFdCount struct {
	PID     int
	FdCount int
	CmdLine string
}

func Lsof(paths ...string) ([]OpenFile, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no paths provided")
	}

	// Normalize input paths
	want := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		abs := p
		if !filepath.IsAbs(p) {
			var err error
			abs, err = filepath.Abs(p)
			if err != nil {
				abs = filepath.Clean(p)
			}
		}
		want[filepath.Clean(abs)] = struct{}{}
	}

	var results []OpenFile

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // skip non-PID entries
		}

		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fdents, err := os.ReadDir(fdDir)
		if err != nil {
			// permission denied for this process? skip
			continue
		}

		// Best-effort cmd + user
		cmd := readOneLine(filepath.Join("/proc", e.Name(), "comm"))
		uid := readUID(filepath.Join("/proc", e.Name(), "status"))
		usr := uidToName(uid)

		for _, fde := range fdents {
			fdname := fde.Name()
			link := filepath.Join(fdDir, fdname)

			// Resolve the symlink target of the FD
			target, err := os.Readlink(link)
			if err != nil {
				continue
			}
			// Strip " (deleted)" suffix if present
			targetNoDel := strings.TrimSuffix(target, " (deleted)")

			// Make absolute and clean if it looks like a real path
			if strings.HasPrefix(targetNoDel, "/") {
				targetNoDel = filepath.Clean(targetNoDel)
			}

			// Compare against requested paths
			if _, ok := want[targetNoDel]; ok {
				results = append(results, OpenFile{
					PID:     pid,
					User:    usr,
					Command: cmd,
					FD:      fdname,
					Target:  target,
				})
			}
		}
	}
	return results, nil
}
func readOneLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
func readUID(statusPath string) int {
	b, err := os.ReadFile(statusPath)
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		// Format: "Uid:\tReal\tEff\tSaved\tFS"
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if uid, err := strconv.Atoi(f[1]); err == nil {
					return uid
				}
			}
			break
		}
	}
	return -1
}
func uidToName(uid int) string {
	if uid < 0 {
		return ""
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return strconv.Itoa(uid)
	}
	return u.Username
}

func ProcessFuser(filePath string) (FuserOutput, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fuser := FindProgram("fuser")
	if len(fuser) < 3 {
		return FuserOutput{}, fmt.Errorf("fuser, no such binary")
	}
	cmd := exec.CommandContext(ctx, fuser, "-a", filePath)
	cmd.Env = ExecEnv()
	output, err := cmd.CombinedOutput()

	// 4. Handle errors and exit codes.
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return FuserOutput{}, fmt.Errorf("fuser command timed out for path: %s", filePath)
		}

		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return FuserOutput{FilePath: filePath, Processes: []ProcessInfo{}}, nil
		}
		return FuserOutput{}, fmt.Errorf("fuser command failed: %w\nOutput: %s", err, string(output))
	}

	// 5. If successful, parse the output string.
	return parseFuserOutput(string(output))
}
func parseFuserOutput(output string) (FuserOutput, error) {
	parts := strings.SplitN(strings.TrimSpace(output), ":", 2)
	if len(parts) != 2 {
		return FuserOutput{}, fmt.Errorf("invalid fuser output format: missing colon separator")
	}

	result := FuserOutput{
		FilePath:  parts[0],
		Processes: []ProcessInfo{},
	}

	processEntries := strings.Fields(strings.TrimSpace(parts[1]))
	if len(processEntries) == 0 {
		return result, nil
	}

	for _, entry := range processEntries {
		if len(entry) < 2 {
			continue // Skip malformed entries
		}
		accessType := entry[len(entry)-1:]
		pidStr := entry[:len(entry)-1]
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			// Skip entries where PID is not a number
			continue
		}
		cmdline := ProcessCommandLine(pid)
		result.Processes = append(result.Processes, ProcessInfo{PID: pid, AccessType: accessType, Cmdline: cmdline})
	}

	return result, nil
}

func MachineType() {
	fmt.Println("cpuid.CPU.VendorID", CPU.VendorID.String())
	fmt.Println("checkVirtioDevices", checkVirtioDevices())
	fmt.Println("cpuid.HYPERVISOR", HYPERVISOR.String())
	fmt.Println("Name:", CPU.BrandName)
	fmt.Println("PhysicalCores:", CPU.PhysicalCores)
	fmt.Println("ThreadsPerCore:", CPU.ThreadsPerCore)
	fmt.Println("LogicalCores:", CPU.LogicalCores)
	fmt.Println("Family", CPU.Family, "Model:", CPU.Model, "Vendor ID:", CPU.VendorID)
	fmt.Println("Features:", strings.Join(CPU.FeatureSet(), ","))
	fmt.Println("Cacheline bytes:", CPU.CacheLine)
	fmt.Println("L1 Data Cache:", CPU.Cache.L1D, "bytes")
	fmt.Println("L1 Instruction Cache:", CPU.Cache.L1I, "bytes")
	fmt.Println("L2 Cache:", CPU.Cache.L2, "bytes")
	fmt.Println("L3 Cache:", CPU.Cache.L3, "bytes")
	fmt.Println("Frequency", CPU.Hz, "hz")

	// Test if we have these specific features:
	if CPU.Supports(SSE, SSE2) {
		fmt.Println("We have Streaming SIMD 2 Extensions")
	}

}
func checkVirtioDevices() bool {
	// Check for virtio network devices
	netDevs, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return false
	}

	for _, dev := range netDevs {
		if strings.HasPrefix(dev.Name(), "eth") || strings.HasPrefix(dev.Name(), "ens") {
			path := "/sys/class/net/" + dev.Name() + "/device"
			link, err := os.Readlink(path)
			if err == nil && strings.Contains(link, "virtio") {
				return true
			}
		}
	}

	// Check for virtio block devices
	blockDevs, err := os.ReadDir("/sys/class/block")
	if err != nil {
		return false
	}

	for _, dev := range blockDevs {
		path := "/sys/class/block/" + dev.Name() + "/device"
		link, err := os.Readlink(path)
		if err == nil && strings.Contains(link, "virtio") {
			return true
		}
	}

	return false
}

func ReadProcCmdLine(pid int) string {
	content, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	if len(content) > 0 {
		zcontent := strings.ReplaceAll(string(content), "\x00", " ")
		return strings.TrimSpace(zcontent)
	}
	return ""
}
func GetProcStatus(pid int) (*ProcStatus, error) {
	filePath := fmt.Sprintf("/proc/%d/status", pid)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	var proc ProcStatus
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Name":
			proc.Name = value
		case "Umask":
			proc.Umask = value
		case "State":
			proc.State = value
		case "Tgid":
			proc.Tgid, _ = strconv.Atoi(value)
		case "Ngid":
			proc.Ngid, _ = strconv.Atoi(value)
		case "Pid":
			proc.Pid, _ = strconv.Atoi(value)
		case "PPid":
			proc.PPid, _ = strconv.Atoi(value)
		case "TracerPid":
			proc.TracerPid, _ = strconv.Atoi(value)
		case "Uid":
			_, _ = fmt.Sscanf(value, "%d %d %d %d", &proc.Uid[0], &proc.Uid[1], &proc.Uid[2], &proc.Uid[3])
		case "Gid":
			_, _ = fmt.Sscanf(value, "%d %d %d %d", &proc.Gid[0], &proc.Gid[1], &proc.Gid[2], &proc.Gid[3])
		case "FDSize":
			proc.FDSize, _ = strconv.Atoi(value)
		case "Groups":
			proc.Groups = value
		case "NStgid":
			proc.NStgid, _ = strconv.Atoi(value)
		case "NSpid":
			proc.NSpid, _ = strconv.Atoi(value)
		case "NSpgid":
			proc.NSpgid, _ = strconv.Atoi(value)
		case "NSsid":
			proc.NSsid, _ = strconv.Atoi(value)
		case "VmPeak":
			proc.VmPeak = value
		case "VmSize":
			proc.VmSize = value
		case "VmLck":
			proc.VmLck = value
		case "VmPin":
			proc.VmPin = value
		case "VmHWM":
			proc.VmHWM = value
		case "VmRSS":
			proc.VmRSS = value
		case "RssAnon":
			proc.RssAnon = value
		case "RssFile":
			proc.RssFile = value
		case "RssShmem":
			proc.RssShmem = value
		case "VmData":
			proc.VmData = value
		case "VmStk":
			proc.VmStk = value
		case "VmExe":
			proc.VmExe = value
		case "VmLib":
			proc.VmLib = value
		case "VmPTE":
			proc.VmPTE = value
		case "VmSwap":
			proc.VmSwap = value
		case "HugetlbPages":
			proc.HugetlbPages = value
		case "CoreDumping":
			proc.CoreDumping, _ = strconv.Atoi(value)
		case "Threads":
			proc.Threads, _ = strconv.Atoi(value)
		case "SigQ":
			proc.SigQ = value
		case "SigPnd":
			proc.SigPnd = value
		case "ShdPnd":
			proc.ShdPnd = value
		case "SigBlk":
			proc.SigBlk = value
		case "SigIgn":
			proc.SigIgn = value
		case "SigCgt":
			proc.SigCgt = value
		case "CapInh":
			proc.CapInh = value
		case "CapPrm":
			proc.CapPrm = value
		case "CapEff":
			proc.CapEff = value
		case "CapBnd":
			proc.CapBnd = value
		case "CapAmb":
			proc.CapAmb = value
		case "NoNewPrivs":
			proc.NoNewPrivs, _ = strconv.Atoi(value)
		case "Seccomp":
			proc.Seccomp, _ = strconv.Atoi(value)
		case "Speculation_Store_Bypass":
			proc.Speculation_Store_Bypass = value
		case "Cpus_allowed":
			proc.Cpus_allowed = value
		case "Cpus_allowed_list":
			proc.Cpus_allowed_list = value
		case "Mems_allowed":
			proc.Mems_allowed = value
		case "Mems_allowed_list":
			proc.Mems_allowed_list = value
		case "voluntary_ctxt_switches":
			proc.Voluntary_ctxt_switches, _ = strconv.Atoi(value)
		case "nonvoluntary_ctxt_switches":
			proc.Nonvoluntary_ctxt_switches, _ = strconv.Atoi(value)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &proc, nil
}

func ReadFileNr() (int, int, int) {
	content, err := os.ReadFile("/proc/sys/fs/file-nr")
	if err != nil {
		return 0, 0, 0
	}

	// Convert the content to a string and split by whitespace
	fields := strings.Fields(string(content))
	if len(fields) < 3 {
		return 0, 0, 0
	}

	// Convert the split string values to integers
	totalAllocated, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, 0
	}
	totalFree, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, 0
	}
	maximum, err := strconv.Atoi(fields[2])
	if err != nil {
		return 0, 0, 0
	}

	return totalAllocated, totalFree, maximum
}

func FileDescriptorsPerProcess() []ProcFdCount {
	procs, err := os.ReadDir("/proc")
	var fdCounts []ProcFdCount

	if err != nil {
		return fdCounts
	}
	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue // Not a PID directory
		}
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		fcmdline := ReadProcCmdLine(pid)
		fdCounts = append(fdCounts, ProcFdCount{PID: pid, FdCount: len(fds), CmdLine: fcmdline})
	}

	if len(fdCounts) == 0 {
		return fdCounts
	}

	sort.Slice(fdCounts, func(i, j int) bool {
		return fdCounts[i].FdCount > fdCounts[j].FdCount
	})

	return fdCounts
}
func TimeStampDecompose(timestampStr string) DateCompose {
	var Cur DateCompose
	if strings.Contains(timestampStr, ".") {
		rb := strings.Split(timestampStr, ".")
		timestampStr = rb[0]
	}

	timestampInt, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return Cur
	}
	Cur.Unix = timestampInt
	dateTime := time.Unix(timestampInt, 0)
	year, month, day := dateTime.Date()
	hour := dateTime.Hour()
	Cur.Min = dateTime.Minute()
	Cur.Year = year
	Cur.Month = StrToInt(fmt.Sprintf("%d", month))
	Cur.Day = day
	Cur.Hour = hour
	return Cur

}
func ContainsSlice(s []string, searchterm string) bool {
	i := sort.SearchStrings(s, searchterm)
	return i < len(s) && s[i] == searchterm
}
func NotInArray(value string, array []string) bool {
	for _, v := range array {
		v = Trim(v)
		if strings.ToLower(v) == strings.ToLower(value) {
			return false
		}
	}
	return true
}

func IsPartitionTmpfs(Path string) bool {
	mnts, _ := mount.Mounts()
	for _, smount := range mnts {
		if smount.Path != Path {
			continue
		}
		if mount.IsTmpfs(smount.Path) {
			return true
		}
		return false
	}
	return false
}
func DisMount(Path string) bool {
	mountBin := FindProgram("umount")
	err, content := ExecuteShell(fmt.Sprintf("%v -l %v", mountBin, Path))
	if err != nil {
		log.Error().Msg(fmt.Sprintf("Umount %v error %v %v", Path, err.Error(), content))
		return false
	}
	return true
}
func IsProductionTime() bool {
	now := time.Now()
	currentHour := now.Hour()
	startHour := 6
	endHour := 22

	if currentHour >= startHour && currentHour < endHour {
		return true
	}
	return false
}

func MountTMPFSCurSize(Path string) int {
	Info := ""
	mnts, _ := mount.Mounts()
	for _, smount := range mnts {
		if smount.Path == Path {
			Info = smount.Flags
			break
		}
	}
	if len(Info) == 0 {
		return 0
	}

	Matches := RegexGroup1(futilsPattern1, Info)
	if len(Matches) == 0 {
		return 0
	}
	KB := float64(StrToInt(Matches))
	MB := Round(KB/1024, 0)
	return int(MB)
}
func GidFromGroupName(groupName string) (int, error) {
	group, err := user.LookupGroup(groupName)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("GidFromGroupName(%v) Error looking up Group:%v", groupName, err.Error()))
		return 0, err
	}

	return StrToInt(fmt.Sprintf("%v", group.Gid)), nil
}
func GobFileGet(cacheFile string) map[string]string {
	var cacheArray map[string]string

	if !fileExists(cacheFile) {
		return cacheArray
	}

	file, err := os.Open(cacheFile)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("Error opening file: %v %v", cacheFile, err.Error()))
		DeleteFile(cacheFile)
	}

	defer func() {
		closeErr := file.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&cacheArray); err != nil {
		log.Error().Msg(fmt.Sprintf("Error decoding gob data from %v %v", cacheFile, err.Error()))
		DeleteFile(cacheFile)
		_ = file.Close()
		return cacheArray
	}
	_ = file.Close()
	return cacheArray
}
func ChownRecursive(path, username string, groupName string) error {

	u, err := user.Lookup(username)
	if err != nil {
		log.Error().Msgf("ChownFolder(%v) Error looking up user: %v %v", path, username, err.Error())
		return err
	}

	uid := StrToInt(u.Uid)
	gid, err := GidFromGroupName(groupName)

	if err != nil {
		log.Error().Msg(fmt.Sprintf("ChownFolder(%v) Error looking up Group: %v %v", path, groupName, err.Error()))
		return err
	}

	return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if IsLink(filePath) {
			return nil
		}

		if err := os.Chown(filePath, uid, gid); err != nil {
			return err
		}
		return nil
	})
}
func visitFilesDir(files *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			*files = append(*files, path)
		}
		return nil
	}
}

func DirFilesRecursive(path string) []string {

	if IsLink(path) {
		path = ReadLink(path)
	}

	var files []string
	err := filepath.Walk(path, visitFilesDir(&files))
	if err != nil {
		return files
	}
	return files
}

func StringToPRCE(pattern string) string {
	pattern = strings.ReplaceAll(pattern, "\\", `\\`)
	pattern = strings.ReplaceAll(pattern, "(", `\(`)
	pattern = strings.ReplaceAll(pattern, ")", `\)`)
	pattern = strings.ReplaceAll(pattern, "{", `\{`)
	pattern = strings.ReplaceAll(pattern, "}", `\}`)
	pattern = strings.ReplaceAll(pattern, "[", `\[`)
	pattern = strings.ReplaceAll(pattern, "]", `\]`)
	pattern = strings.ReplaceAll(pattern, "+", `\+`)
	pattern = strings.ReplaceAll(pattern, "^", `\^`)
	pattern = strings.ReplaceAll(pattern, ".", `\.`)
	pattern = strings.ReplaceAll(pattern, "?", `\?`)
	return strings.ReplaceAll(pattern, "*", ".*?")
}
func MountTMPFS(Path string, SizeMB int64) bool {
	SizeKB := SizeMB * 1024
	SizeBytes := SizeKB * 1024
	err := mount.MountTmpfs(Path, SizeBytes)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("LinuxMountTMPFS: Error while mounting tmpfs partition for %v %v", Path, err.Error()))
		return false
	}
	return true
}
func encryptPad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}
func decryptUnpad(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}
func EncryptString(plaintext string, key []byte) (string, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	data := []byte(plaintext)
	data = encryptPad(data, block.BlockSize())
	ciphertext := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	mode.CryptBlocks(ciphertext, data)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
func DecryptString(cryptoText string, key []byte) (string, error) {
	data, _ := base64.StdEncoding.DecodeString(cryptoText)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	mode.CryptBlocks(data, data)
	dec := decryptUnpad(data)
	return string(dec), nil
}

func InstallSoftwareFromDir(TempDir string) error {

	BLACKLISTS := make(map[string]bool)
	BLACKLISTS["/etc/squid3/PROXY.keytab"] = true
	BLACKLISTS["/etc/squid3/krb5.keytab"] = true
	BLACKLISTS["/etc/krb5.keytab"] = true

	TmpFile := "/home/artica/cluster/backup/blacklists"
	CreateDir(TmpFile)

	for SourceFile, _ := range BLACKLISTS {
		if !FileExists(SourceFile) {
			continue
		}
		Dirname := DirName(SourceFile)
		BaseName := BaseName(SourceFile)

		DestinationDir := fmt.Sprintf("%v/%v", TmpFile, Dirname)
		CreateDir(DestinationDir)
		DestinationFile := fmt.Sprintf("%v/%v", DestinationDir, BaseName)
		_ = CopyFile(SourceFile, DestinationFile)
	}

	List := DirFilesRecursive(TempDir)
	for _, file := range List {
		fileName := BaseName(file)
		OldDirname := DirName(file)
		NewDirname := strings.ReplaceAll(OldDirname, TempDir, "/")
		TargetFile := fmt.Sprintf("%v/%v", NewDirname, fileName)
		TargetFile = strings.ReplaceAll(TargetFile, `//`, "/")

		if BLACKLISTS[TargetFile] {
			continue
		}

		md5Src := FileChecksum(file)
		md5Dst := FileChecksum(TargetFile)
		if md5Src == md5Dst {
			continue
		}

		CreateDir(NewDirname)

		err := CopyFile(file, TargetFile)
		if err != nil {
			return fmt.Errorf(fmt.Sprintf("Failed to copy %v to %v err:%v", file, TargetFile, err.Error()))
		}
		if strings.HasSuffix(NewDirname, "/bin") {
			Chmod(TargetFile, 0755)
		}
		if strings.HasSuffix(NewDirname, "/sbin") {
			Chmod(TargetFile, 0755)
		}
	}

	for BackupFile, _ := range BLACKLISTS {
		Dirname := DirName(BackupFile)
		BaseName := BaseName(BackupFile)
		SourceDir := fmt.Sprintf("%v/%v", TmpFile, Dirname)
		SourceFile := fmt.Sprintf("%v/%v", SourceDir, BaseName)
		if !FileExists(SourceFile) {
			continue
		}
		_ = CopyFile(SourceFile, BackupFile)
	}

	return nil
}
func FileChecksum(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	checksum := hash.Sum(nil)
	return hex.EncodeToString(checksum)
}

func CopyInstallFiles(dirSrc, destinationDir string) (error, string) {

	if _, err := os.Stat(dirSrc); os.IsNotExist(err) {
		return fmt.Errorf("source directory does not exist: %s", dirSrc), ""
	}
	destinationDir = RemoveTrailingSlash(destinationDir)
	dirSrc = RemoveTrailingSlash(dirSrc)

	rsync := FindProgram("rsync")
	if len(rsync) > 3 {
		cmd := exec.Command(rsync, "-av", dirSrc+"/", destinationDir+"/")
		cmd.Env = append(cmd.Env, ExecEnv()...)
		output, err := cmd.CombinedOutput()
		return err, string(output)
	}
	cp := FindProgram("cp")
	bash := FindProgram("bash")
	cmdStr := fmt.Sprintf(`%s -rfva "%s"/* "%s/"`, cp, dirSrc, destinationDir)
	cmd := exec.Command(bash, "-c", cmdStr)
	cmd.Env = append(cmd.Env, ExecEnv()...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("copy failed: %v output", err), string(output)
	}
	return nil, ""

}

func RunLdconfig(Directory string) error {
	var args []string
	if len(Directory) > 3 {
		args = append(args, "-n")
		args = append(args, fmt.Sprintf("%v/", Directory))
	}
	ldconfig := FindProgram("ldconfig")
	cmd := exec.Command(ldconfig, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ldconfig failed: %v output: [%s]", err, string(output))
	}
	return nil
}

func RmRF(Directory string) error {

	if len(Directory) < 3 {
		return fmt.Errorf("Remove recusrively this base path %v is denied", Directory)
	}

	Denied := []string{"/root", "/home", "/var", "/lib", "/bin", "/usr", "/usr/lib", "/usr/share", "/etc",
		"/etc/init.d", "/opt", "/usr/local", "/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin",
		"/usr/libexec", "/lib64", "/lib/x86_64-linux-gnu", "/proc", "/tmp", "/home/artica",
	}

	DeniedSuffix := []string{"/lib/x86_64-linux-gnu/", "/lib/", "/bin/", "/usr/sbin/", "/lib64/", "/usr/bin/"}

	for _, deniedP := range Denied {

		if Directory == deniedP {
			return fmt.Errorf("Remove recusrively this base path %v is denied", Directory)
		}
		Denied2 := fmt.Sprintf("%v/", deniedP)
		if Directory == Denied2 {
			return fmt.Errorf("Remove recusrively this base path %v/ is denied", Directory)
		}
	}

	for _, deniedP := range DeniedSuffix {

		if strings.HasPrefix(Directory, deniedP) {
			return fmt.Errorf("RmRF(): Remove recusrively this base path %v recusrsively is denied", Directory)
		}
	}

	if !IsDirDirectory(Directory) {
		return nil
	}

	err := os.RemoveAll(Directory)
	if err != nil {
		return fmt.Errorf("RmRF(): Error while RemoveAll %v: %v", Directory, err)
	}
	return nil
}

func TimeMin(FromTimeSec int64) int {
	currentTime := time.Now()
	targetTime := time.Unix(FromTimeSec, 0)
	duration := currentTime.Sub(targetTime)
	return int(duration.Minutes())
}
func MinutesToDuration(minutes int64) time.Duration {
	return time.Duration(minutes) * time.Minute
}
func TimeSec(FromTimeSec int64) int {
	currentTime := time.Now()
	targetTime := time.Unix(FromTimeSec, 0)
	duration := currentTime.Sub(targetTime)
	return int(duration.Seconds())
}
func TimeDay(FromTimeSec int64) int {
	currentTime := time.Now()
	targetTime := time.Unix(FromTimeSec, 0)
	duration := currentTime.Sub(targetTime)
	HoursDiff := int(duration.Hours())
	Days := HoursDiff / 24
	return Days
}

func PIDsOnSocket(socketPath string) ([]int, error) {
	// 1. deadline-bound context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lsof := FindProgram("lsof")

	cmd := exec.CommandContext(ctx, lsof, "-t", socketPath)

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf // keep stderr for diagnostics too

	// 3. run it
	err := cmd.Run()
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("lsof timed out after 10 s: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w — %s", err, strings.TrimSpace(buf.String()))
	}

	// 4. parse PIDs
	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		pid, conv := strconv.Atoi(strings.TrimSpace(line))
		if conv != nil {
			return nil, fmt.Errorf("unexpected lsof output %q: %v", line, conv)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func FileTimeMin(filePath string) int {
	FileTimeStamp := FileTime(filePath)
	currentTime := time.Now()
	targetTime := time.Unix(FileTimeStamp, 0)
	duration := currentTime.Sub(targetTime)
	return int(duration.Minutes())

}
func FileTimeSec(filePath string) int {
	FileTimeStamp := FileTime(filePath)
	currentTime := time.Now()
	targetTime := time.Unix(FileTimeStamp, 0)
	duration := currentTime.Sub(targetTime)
	return int(duration.Seconds())

}
func FileTime(filePath string) int64 {
	if !fileExists(filePath) {
		return 10000000
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 10000000
	}
	modificationTime := fileInfo.ModTime()
	return modificationTime.Unix()
}
func fileExists(spath string) bool {
	if _, err := os.Stat(spath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}

func FileClear(filePath string) {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
}

func FileSizeHuman(filePath string) string {
	Unit := "bytes"
	size := FileSize(filePath)
	if size < 1024 {
		return fmt.Sprintf("%v %v", size, Unit)
	}
	Unit = "Kb"
	size = size / 1024
	if size < 1024 {
		return fmt.Sprintf("%v %v", size, Unit)
	}
	Unit = "Mb"
	size = size / 1024
	return fmt.Sprintf("%v %v", size, Unit)
}

func FileSize(filePath string) int64 {
	if !FileExists(filePath) {
		return 0
	}
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0
	}
	return fileInfo.Size()
}

func Filemtime(filepath string) int64 {
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return 0
	}
	return fileInfo.ModTime().Unix()
}

func ScanDir(directoryPath string) ([]string, error) {
	var files []string
	// Retourne le chemin complet
	if !IsDirDirectory(directoryPath) {
		return files, nil
	}

	err := filepath.Walk(directoryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err // return the error to stop the walk
		}
		if info == nil {
			log.Error().Msg(fmt.Sprintf("nil FileInfo for path: %s %v", path, GetCalleRuntime()))
			return fmt.Errorf("nil FileInfo for path: %s", path)
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return files, nil
}

func FileSizeMB(filePath string) int64 {
	fileSizeInBytes := FileSize(filePath)
	if fileSizeInBytes == 0 {
		return 0
	}
	return fileSizeInBytes / (1024 * 1024)
}
func FileSizeKB(filePath string) int64 {
	fileSizeInBytes := FileSize(filePath)
	if fileSizeInBytes == 0 {
		return 0
	}
	return fileSizeInBytes / 1024
}
func MoveFile(sourceFilePath string, destinationFilePath string) error {
	err := os.Rename(sourceFilePath, destinationFilePath)
	if err != nil {
		if linkErr, ok := err.(*os.LinkError); ok && linkErr.Err == syscall.EXDEV {
			var srcFd *os.File
			srcFd, err = os.Open(sourceFilePath)
			if err != nil {
				return err
			}
			defer func(srcFd *os.File) {
				err := srcFd.Close()
				if err != nil {

				}
			}(srcFd)

			var dstFd *os.File
			dstFd, err = os.Create(destinationFilePath)
			if err != nil {
				return err
			}
			defer func(dstFd *os.File) {
				err := dstFd.Close()
				if err != nil {

				}
			}(dstFd)

			_, err = io.Copy(dstFd, srcFd)
			if err != nil {
				return err
			}

			err = os.Remove(sourceFilePath)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

func FileHead10(TargetPath string) []string {

	if strings.HasSuffix(TargetPath, ".gz") {
		return compressor.ReadFirstLinesGz(TargetPath, 15)
	}

	var f []string
	file, err := os.Open(TargetPath)
	if err != nil {
		return f
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	scanner := bufio.NewScanner(file)
	lineCount := 0

	for scanner.Scan() {
		f = append(f, scanner.Text())
		lineCount++
		if lineCount == 15 {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return f
	}
	_ = file.Close()
	return f
}
func FileTail10(TargetPath string) []string {

	if strings.HasSuffix(TargetPath, ".gz") {
		return compressor.ReadLastLinesGz(TargetPath, 15)
	}

	var lines []string
	file, err := os.Open(TargetPath)
	if err != nil {
		return lines
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > 15 {
			lines = lines[1:] // Keep only the last 10 lines in the slice
		}
	}

	if err := scanner.Err(); err != nil {
		_ = file.Close()
		return lines
	}
	_ = file.Close()
	return lines
}

func FileGetContentsBytes(filename string) ([]byte, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return content, nil
}
func FilePutContentsBytes(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}
func FileGobGetStandard(cacheFile string) []string {
	var cacheArray []string

	if !fileExists(cacheFile) {
		return cacheArray
	}

	file, err := os.Open(cacheFile)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("Error opening file: %v %v", cacheFile, err.Error()))
		DeleteFile(cacheFile)
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&cacheArray); err != nil {
		log.Error().Msg(fmt.Sprintf("Error decoding gob data from %v %v", cacheFile, err.Error()))
		DeleteFile(cacheFile)
		return cacheArray
	}
	return cacheArray
}
func FileGobGetInt(cacheFile string) map[string]int {
	cacheArray := make(map[string]int)

	if !fileExists(cacheFile) {
		return cacheArray
	}

	file, err := os.Open(cacheFile)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("Error opening file: %v %v", cacheFile, err.Error()))
		DeleteFile(cacheFile)
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&cacheArray); err != nil {
		log.Error().Msg(fmt.Sprintf("Error decoding gob data from %v %v", cacheFile, err.Error()))
		DeleteFile(cacheFile)
		return cacheArray
	}
	return cacheArray
}
func FileGobSaveInt(filename string, data map[string]int) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	encoder := gob.NewEncoder(file)
	err = encoder.Encode(data)
	_ = file.Close()
	if err != nil {
		return err
	}
	return nil
}
func FileGobSaveStandard(filename string, data []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	encoder := gob.NewEncoder(file)
	err = encoder.Encode(data)
	_ = file.Close()
	if err != nil {
		return err
	}
	return nil
}

func FileGetContents(filename string) string {
	if !fileExists(filename) {
		return ""
	}
	tk, err := os.ReadFile(filename)
	if err != nil {
		return ""
	}
	tk = bytes.TrimSpace(tk)
	return string(tk)
}
func UrlEncode(Str string) string {
	return url.QueryEscape(Str)
}

func LockedInstall() bool {

	if FileExists("/etc/artica-postfix/artica-as-rebooted") {
		return false
	}

	if FileExists("/etc/artica-postfix/WIZARD_INSTALL_EXECUTED") {
		TouchFileLock("/etc/artica-postfix/artica-as-rebooted")
		return false
	}
	if IsDirDirectory("/opt/artica/iso/lock") {
		TouchFileLock("/etc/artica-postfix/artica-as-rebooted")
		return false
	}
	if FileExists("/etc/artica-postfix/artica-iso-setup-launched") {
		sTime := FileTime("/etc/artica-postfix/artica-iso-setup-launched")
		if sTime > 7200 {
			TouchFileLock("/etc/artica-postfix/artica-as-rebooted")
			return false
		}
	}

	log.Warn().Msgf("%v Locked installation...[missing artica-as-rebooted]", GetCalleRuntime())
	return true

}
func GobFileSave(cacheFile string, Array map[string]string) {

	file, err := os.Create(cacheFile)
	if err != nil {
		log.Error().Msgf("%v Error creating file %v for gob encoding %v", GetCalleRuntime(), cacheFile, err.Error())

	}
	defer func() {
		closeErr := file.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(Array); err != nil {
		log.Error().Msgf("%v Error encoding map to gob %v: %v", GetCalleRuntime(), cacheFile, err.Error())

	}
	_ = file.Close()
}

func TableDeleteDoublons(table []string) []string {
	ztable := make(map[string]string)
	for _, v := range table {
		ztable[v] = v
	}

	var t []string
	for s, _ := range ztable {
		t = append(t, s)
	}
	return t
}
func SocketExists(path string) bool {
	info, err := os.Lstat(path) // do not follow a possible symlink
	if err != nil {
		if os.IsNotExist(err) {
			return false // clean “doesn’t exist” case
		}
		return false // real error: propagate
	}
	return info.Mode()&os.ModeSocket != 0
}
func ExecuteSysctl(param, value string) {
	sysctlBin := FindProgram("sysctl")
	cmd := exec.Command(sysctlBin, "-w", fmt.Sprintf("%s=%s", param, value))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Error().Msgf("%v failed to execute sysctl -w %s=%s: %v, stderr: %s", GetCalleRuntime(), param, value, err, stderr.String())
	}
}

func FileExists(spath string) bool {
	spath = strings.TrimSpace(spath)
	if IsLink(spath) {
		return true
	}

	if _, err := os.Stat(spath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}
func StripLeadingSlash(value string) string {
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "\\") {
		return value[1:]
	}
	value = strings.ReplaceAll(value, `\`, "/")
	return value
}
func DirectoryMD5(dir string, Excludes map[string]bool) string {

	if !IsDirDirectory(dir) {
		return ""
	}
	fileHashes := make(map[string]string)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		if Excludes[info.Name()] == true {
			return nil
		}
		hash := MD5File(path)
		if err != nil {
			return err
		}
		relativePath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		fileHashes[relativePath] = hash
		return nil
	})
	var AllHash []string
	for _, hash := range fileHashes {
		AllHash = append(AllHash, hash)
	}
	if err != nil {
		log.Error().Msg("DirectoryMD5(" + dir + ") error " + err.Error())
		return ""
	}
	return Md5String(strings.Join(AllHash, ""))
}
func ArticaRestLocked() bool {
	if !FileExists("/etc/artica-postfix/articarest.lock") {
		return false
	}

	if FileTimeMin("/etc/artica-postfix/articarest.lock") < 30 {
		return true
	}
	DeleteFile("/etc/artica-postfix/articarest.lock")
	return false
}
func TouchFile(path string) {
	DeleteFile(path)
	_ = FilePutContents(path, "# "+TimeStampToString())
}
func LocatePHP5Bin() string {

	locations := []string{
		"/usr/bin/php",
		"/usr/bin/php7.4",
		"/usr/bin/php7.3",
		"/usr/bin/php7.2",
		"/usr/bin/php7.1",
		"/usr/bin/php8.1",
		"/usr/bin/php8.2",
		"/usr/bin/php8.3",
		"/usr/bin/php8.4",
		"/usr/bin/php8.5",
		"/usr/bin/php8.6",
		"/usr/bin/php8.7",
		"/usr/bin/php9.0",
		"/usr/bin/php9.1",
		"/usr/bin/php9.2",
	}

	for _, path := range locations {
		if fileExists(path) {
			return path
		}
	}

	phpPath := FindProgram("php")
	if fileExists(phpPath) {
		return phpPath
	}

	php5Path := FindProgram("php5")
	if fileExists(php5Path) {
		return php5Path
	}

	log.Error().Msgf("%v Unable to locate php binary!", GetCalleRuntime())
	return ""
}

func TouchFileLock(path string) {
	err := FilePutContents(path, TimeStampToString())
	if err != nil {
		log.Error().Msgf("%v: unable to create file %v %v", GetCalleRuntime(), path, err.Error())
		return
	}
	err = ChattrPLusI(path)
	if err != nil {
		log.Error().Msgf("%v: unable to set Immutable file %v %v", GetCalleRuntime(), path, err.Error())
		return
	}
}

func ChattrMinusI(filePath string) error {
	chattr := FindProgram("chattr")
	err, out := ExecuteShell(fmt.Sprintf("%v -i %v", chattr, filePath))
	if err != nil {
		return fmt.Errorf("%v: unable to chattr %v %v", GetCalleRuntime(), filePath, out)
	}
	return nil
}

func ChattrPLusI(path string) error {
	// Open the file
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	// Get the file descriptor
	fd := file.Fd()

	// Get the current file flags
	var flags int
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, FS_IOC_GETFLAGS, uintptr(unsafe.Pointer(&flags))); errno != 0 {
		return fmt.Errorf("failed to get file flags: %v", errno)
	}

	// Add the immutable flag
	flags |= FS_IMMUTABLE_FL

	// Set the file flags
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, FS_IOC_SETFLAGS, uintptr(unsafe.Pointer(&flags))); errno != 0 {
		return fmt.Errorf("failed to set file flags: %v", errno)
	}

	return nil
}

func FuserFile(Target string) []int {
	ArticaRestPID := int(StrToInt64(FileGetContents("/run/active-directory-rest.pid")))
	MyPID := os.Getpid()
	var spids []int

	if strings.HasSuffix(Target, ".sock") {
		if !IsUnixSocketAvailable(Target) {
			return []int{}
		}
	}

	fuser := FindProgram("fuser")
	if len(fuser) == 0 {
		log.Error().Msg("fuser binary not found")
		return spids
	}

	cmdline := fmt.Sprintf("%v \"%v\"", fuser, Target)
	err, res := ExecuteShell(cmdline)
	if err != nil {
		return spids
	}
	tb := strings.Split(res, "\n")
	for _, line := range tb {
		if !strings.Contains(line, ":") {
			continue
		}
		DoubleDots := strings.Split(line, ":")
		if len(DoubleDots) != 2 {
			continue
		}
		ListOfPids := strings.Split(DoubleDots[1], " ")
		for _, pid := range ListOfPids {
			pid = strings.TrimSpace(pid)
			if len(pid) < 2 {
				continue
			}
			RealPid := StrToInt(pid)
			if RealPid == ArticaRestPID {
				continue
			}
			if RealPid < 10 {
				continue
			}
			if RealPid == MyPID {
				continue
			}
			spids = append(spids, RealPid)
		}
	}
	return spids
}

func IsArticaService(InitPath string) bool {
	if !FileExists(InitPath) {
		return true
	}
	tp := strings.Split(FileGetContents(InitPath), "\n")
	for _, line := range tp {
		if strings.Contains(line, "Modified by: Artica") {
			return true
		}
	}
	return false
}
func Basename(path string) string {
	return filepath.Base(path)
}
func DiffMins(unixTimestamp int64) int {
	timestamp := time.Unix(unixTimestamp, 0)
	currentTime := time.Now()
	diff := currentTime.Sub(timestamp)
	diffInMinutes := diff.Minutes()
	return Float64ToInt(diffInMinutes)
}
func Float64ToInt(num float64) int {
	return int(math.Round(num))
}
func SetImmutable(filePath string) error {
	chattr := FindProgram("chattr")
	cmd := exec.Command(chattr, "+i", filePath)
	return cmd.Run()
}
func ClearImmutable(filePath string) error {
	chattr := FindProgram("chattr")
	cmd := exec.Command(chattr, "-i", filePath)
	return cmd.Run()
}

func RemoveDirectoryIfEmpty(dirPath string) error {
	// Read the contents of the directory
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read directory: %v", err)
	}

	// Check if the directory is empty
	if len(entries) > 0 {
		return fmt.Errorf("%v Directory is not empty", dirPath)
	}

	// Remove the directory
	err = os.Remove(dirPath)
	if err != nil {
		return fmt.Errorf("failed to remove directory %v: %v", dirPath, err)
	}
	return nil
}

func DirDirs(DirectoryPath string) []string {
	var f []string
	if !IsDirDirectory(DirectoryPath) {
		return f
	}

	files, err := os.ReadDir(DirectoryPath)
	if err != nil {
		return f
	}
	for _, file := range files {
		if file.Name() == "." {
			continue
		}
		if file.Name() == ".." {
			continue
		}
		if !file.IsDir() {
			continue
		}
		f = append(f, file.Name())
	}
	return f
}
func EqualStringSets(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}

	// Build a set from `a`.
	set := make(map[string]struct{}, len(a))
	for _, s := range a {
		set[s] = struct{}{}
	}

	// Walk through `b`, deleting any matches.
	for _, s := range b {
		if _, ok := set[s]; !ok {
			return false // b had something a didn't
		}
		delete(set, s)
	}

	// If the map is empty, every element appeared in both.
	return len(set) == 0
}
func ProcessUptime(pid int) string {
	_, Duration := ProcessAgeInSeconds(pid)
	total := int64(Duration.Seconds())
	// Compute days, hours, minutes, and seconds
	days := total / (60 * 60 * 24)
	hours := (total % (60 * 60 * 24)) / (60 * 60)
	minutes := (total % (60 * 60)) / 60
	seconds := total % 60
	return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
}

func ProcessAgeInMinutes(pid int) int {
	_, Duration := ProcessAgeInSeconds(pid)
	return int(Duration.Minutes())
}

func ProcessAgeInSeconds(pid int) (int64, time.Duration) {
	// Read the system uptime
	uptimeBytes, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, 0
	}
	uptimeFields := strings.Fields(string(uptimeBytes))
	uptimeSecs, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil {
		return 0, 0
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0
	}
	parts := strings.Fields(string(stat))
	if len(parts) < 22 {
		return 0, 0
	}
	startTimeTicks, err := strconv.ParseInt(parts[21], 10, 64)
	if err != nil {
		return 0, 0
	}
	ticksPerSecond, err := getTicksPerSecond()
	if err != nil {
		return 0, 0
	}
	startTimeSecs := float64(startTimeTicks) / float64(ticksPerSecond)
	processAgeSeconds := int64(uptimeSecs) - int64(startTimeSecs)

	return processAgeSeconds, time.Duration(processAgeSeconds) * time.Second
}
func getTicksPerSecond() (int64, error) {
	const CLK_TCK int64 = 100
	return CLK_TCK, nil
}
func FiletoArray(sPath string) []string {

	var vals []string
	if !FileExists(sPath) {
		return vals
	}
	data := FileGetContents(sPath)
	return strings.Split(data, "\n")
}
func GetFamilySites(domain string) (string, error) {
	if domain == "" {
		return "", nil
	}
	if isIPAddress(domain) {
		return domain, nil
	}
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		log.Error().Msgf("%v Error parsing domain %s: %v", GetCalleRuntime(), domain, err)
		return domain, fmt.Errorf("error parsing domain %s: %v", domain, err)
	}
	return eTLDPlusOne, nil
}
func isIPAddress(s string) bool {
	if s == "-" {
		return false
	}
	if s == "!nil" {
		return false
	}
	if s == "" {
		return false
	}
	if s == "0.0.0.0" {
		return false
	}
	if s == "127.0.0.1" {
		return true
	}
	return isValidIP(s)
}
func isValidIP(ip string) bool {
	if ip == "" {
		return false
	}
	if len(ip) < 3 {
		return false
	}
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}

func GetHostnameFqdn() (string, error) {
	if FileExists("/etc/artica-postfix/settings/Daemons/myhostname") {
		host := sockets.GET_INFO_STR("myhostname")
		if len(host) > 2 {
			return host, nil
		}
	}
	cmd := exec.Command("/bin/hostname", "-f")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error when GetHostnameFqdn: %v", err)
	}
	fqdn := out.String()
	fqdn = fqdn[:len(fqdn)-1] // removing EOL
	return fqdn, nil
}
func matchesPattern(text, pattern string) bool {
	re := regexp.MustCompile(pattern)
	return re.MatchString(text)
}
func LinuxCodeName() string {
	f := sockets.GET_INFO_STR("LinuxDistributionCodeName")
	if strings.TrimSpace(f) != "" {
		return strings.TrimSpace(f)
	}

	distriName := LinuxDistribution()
	if matchesPattern(distriName, "(?i)Ubuntu") {
		return "UBUNTU"
	}
	if matchesPattern(distriName, "(?i)debian") {
		return "DEBIAN"
	}
	if matchesPattern(distriName, "(?i)suse") {
		return "SUSE"
	}
	if matchesPattern(distriName, "(?i)Fedora") {
		return "FEDORA"
	}
	if matchesPattern(distriName, "(?i)CentOS") {
		return "CENTOS"
	}

	return ""
}
func LinuxDistribution() string {
	f := sockets.GET_INFO_STR("LinuxDistributionFullName")
	if strings.TrimSpace(f) != "" {
		return f
	}

	if fileExists("/etc/SuSE-release") {
		content, _ := os.ReadFile("/etc/SuSE-release")
		re := regexp.MustCompile(`([0-9]+)\.([0-9]+)`)
		matches := re.FindStringSubmatch(string(content))
		if len(matches) > 0 {
			return fmt.Sprintf("openSUSE %s.%s", strings.TrimSpace(matches[1]), strings.TrimSpace(matches[2]))
		}
	}

	if fileExists("/etc/lsb-release") && !fileExists("/etc/redhat-release") {
		content, _ := os.ReadFile("/etc/lsb-release")
		lines := strings.Split(string(content), "\n")
		var distriProvider, distriVer, distriName string
		for _, val := range lines {
			if re := regexp.MustCompile(`DISTRIB_ID=(.+)`); re.MatchString(val) {
				distriProvider = strings.TrimSpace(re.FindStringSubmatch(val)[1])
			}
			if re := regexp.MustCompile(`DISTRIB_RELEASE=([0-9\.]+)`); re.MatchString(val) {
				distriVer = strings.TrimSpace(re.FindStringSubmatch(val)[1])
			}
			if re := regexp.MustCompile(`DISTRIB_CODENAME=(.+)`); re.MatchString(val) {
				distriName = strings.TrimSpace(re.FindStringSubmatch(val)[1])
			}
		}
		return fmt.Sprintf("%s %s %s", distriProvider, distriVer, distriName)
	}

	if fileExists("/etc/debian_version") {
		content, _ := os.ReadFile("/etc/debian_version")
		lines := strings.Split(string(content), "\n")
		for _, val := range lines {
			if re := regexp.MustCompile(`([0-9\.]+)`); re.MatchString(val) {
				return fmt.Sprintf("Debian %s Gnu-linux", strings.TrimSpace(re.FindStringSubmatch(val)[1]))
			}
			if strings.Contains(val, "squeeze/sid") {
				return "Debian 6.0 Gnu-linux"
			}
		}
	}

	if fileExists("/etc/redhat-release") {
		content, _ := os.ReadFile("/etc/redhat-release")
		lines := strings.Split(string(content), "\n")
		for _, val := range lines {
			if re := regexp.MustCompile(`Fedora Core release\s+([0-9]+)`); re.MatchString(val) {
				return fmt.Sprintf("Fedora Core release %s", strings.TrimSpace(re.FindStringSubmatch(val)[1]))
			}
			if re := regexp.MustCompile(`Fedora release\s+([0-9]+)`); re.MatchString(val) {
				return fmt.Sprintf("Fedora release %s", strings.TrimSpace(re.FindStringSubmatch(val)[1]))
			}
			if re := regexp.MustCompile(`Scientific Linux release\s+([0-9\.]+)`); re.MatchString(val) {
				return fmt.Sprintf("Scientific Linux release %s", strings.TrimSpace(re.FindStringSubmatch(val)[1]))
			}
			if re := regexp.MustCompile(`Mandriva Linux release\s+([0-9\.]+)`); re.MatchString(val) {
				return fmt.Sprintf("Mandriva Linux release %s", strings.TrimSpace(re.FindStringSubmatch(val)[1]))
			}
			if re := regexp.MustCompile(`CentOS\s+.*?release\s+([0-9\.]+)`); re.MatchString(val) {
				return fmt.Sprintf("CentOS release %s", strings.TrimSpace(re.FindStringSubmatch(val)[1]))
			}
		}
	}

	return ""
}

func CompareKernelVersions(version1, version2 string) int {
	// Regular expression to match numbers in version strings
	re := regexp.MustCompile(`\d+`)
	parts1 := re.FindAllString(version1, -1)
	parts2 := re.FindAllString(version2, -1)

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var num1, num2 int
		if i < len(parts1) {
			num1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			num2, _ = strconv.Atoi(parts2[i])
		}

		if num1 < num2 {
			return -1
		} else if num1 > num2 {
			return 1
		}
	}
	return 0
}

func KernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}
	parts := strings.Fields(string(data))
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}
func ConvertToSlice(input string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return []string{}
	}
	Final := []string{}
	ALREADY := make(map[string]bool)
	tb := strings.Split(input, ",")
	for _, line := range tb {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if ALREADY[line] {
			continue
		}
		Final = append(Final, line)
		ALREADY[line] = true
	}
	return Final
}

func ConvertInt64(t interface{}) int64 {

	if t == nil {
		return int64(0)
	}
	if str, ok := t.(string); ok && str == "" {
		return int64(0)
	}

	switch t := t.(type) {
	case int64:
		log.Debug().Msgf("%v Value %v converted to int64", GetCalleRuntime(), t)
		return t
	case int:
		log.Debug().Msg(fmt.Sprintf("Value %v converted to int64 line %s", t, GetCalleRuntime()))
		return int64(t)
	case string:
		i64, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error %s while converting value %v converted to int64 line %s", err, t, GetCalleRuntime()))
			return 0
		}
		log.Debug().Msg(fmt.Sprintf("Value %v converted to int64 line %s", t, GetCalleRuntime()))
		return i64
	default:
		log.Debug().Msg(fmt.Sprintf("Unable to cast value %v to int64, return 0 line %s", t, GetCalleRuntime()))
		return 0
	}
}
func TimeBetweenDays(d int64) float64 {
	now := time.Now().Unix()
	return math.Round(float64(d-now) / (60 * 60 * 24))
}
func HumanizeBytes(size int64) string {
	if size < 10 { // Handle very small bytes separately
		return fmt.Sprintf("%d B", size)
	}

	units := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	exp := int(math.Log10(float64(size)) / math.Log10(1000))
	val := float64(size) / math.Pow(1000, float64(exp))
	return fmt.Sprintf("%.2f %s", val, units[exp])
}

func RemoveTrailingDot(domain string) string {
	return strings.TrimSuffix(domain, ".")
}
func RemoveTrailingSlash(path string) string {
	return strings.TrimSuffix(path, "/")
}
func RemoveFirstSlash(path string) string {
	if strings.HasPrefix(path, "/") {
		return path[1:]
	}
	return path
}
func RemoveFirstDot(domain string) string {
	if strings.HasPrefix(domain, ".") {
		return domain[1:]
	}
	return domain
}
func DeleteFileAndTouch(filePath string) {
	if !FileExists(filePath) {
		return
	}
	_ = os.Remove(filePath)
	TouchFile(filePath)
}
func DeleteFile(filePath string) {
	if !FileExists(filePath) {
		return
	}
	_ = os.Remove(filePath)
}

func StampFile(filecache string) {
	DeleteFile(filecache)
	err := os.WriteFile(filecache, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0644)
	if err != nil {
		log.Error().Msgf("%v %v", GetCalleRuntime(), err.Error())
	}
}
func DnsLookup(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resultChan := make(chan []string, 1)
	errChan := make(chan error, 1)
	go func() {
		ips, err := net.LookupHost(domain)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- ips
	}()
	select {
	case ips := <-resultChan:
		return ips, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("DNS lookup timed out after 3 seconds")
	}
}
func CountLinesOfFile(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
	}
	return count
}
func CountLinesOfFilesNomarks(FilePath string) int {
	file, err := os.Open(FilePath)
	if err != nil {
		return 0
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	scanner := bufio.NewScanner(file)
	lines := 0
	for scanner.Scan() {
		adline := Trim(scanner.Text())
		if len(adline) < 2 {
			continue
		}
		if strings.HasPrefix(adline, "#") {
			continue
		}
		lines++
	}
	if err := scanner.Err(); err != nil {
		return lines
	}
	return lines
}

func KeepLastNFiles(dir string, keep int) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var fileInfos []File
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			return err
		}
		fileInfos = append(fileInfos, File{FileInfo: info, Path: dir + "/" + file.Name()})
	}
	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].ModTime().After(fileInfos[j].ModTime())
	})
	if len(fileInfos) > keep {
		for _, file := range fileInfos[keep:] {
			log.Debug().Msgf("%v %v [REMOVE]", GetCalleRuntime(), file.Path)
			err := os.Remove(file.Path)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
func SymLinkCreate(RealBinary string, SymLinkPath string) error {
	if SymlinkExists(SymLinkPath) {
		SimTarget := ReadLink(SymLinkPath)
		if SimTarget == RealBinary {
			return nil
		}
		err := os.Remove(SymLinkPath)
		if err != nil {
			return fmt.Errorf("Remove symbolic link %s failed: %s", SymLinkPath, err)
		}
	}
	err := os.Symlink(RealBinary, SymLinkPath)
	if err != nil {

		return err
	}
	return nil
}
func SymlinkExists(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}

func Uint64ToInt64(u64 uint64) int64 {
	if u64 > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(u64)
}

func IsLink(path string) bool {

	info, err := os.Lstat(path)
	if err != nil {
		return false
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return false
}
func UnixSocketCheck(socketPath string) bool {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return false
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)
	_ = conn.Close()
	return true
}

func SocketCheck(socketPath string) error {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return err
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)
	_ = conn.Close()
	return nil
}
func ProcessCommandLine(pid int) string {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	finale := strings.Replace(string(content), "\x00", " ", -1)
	return strings.TrimSpace(finale)
}
func IsMounted(spath string) bool {
	Mounts := parseMounts()
	return keyExistsInMounts(Mounts, spath)

}
func IsPortInUse(Addr string, port int) bool {
	addr := fmt.Sprintf("%v:%d", Addr, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}
func keyExistsInMounts(arr map[string]MountStr, key string) bool {
	for Dest, _ := range arr {
		if Dest == key {
			return true
		}
	}
	return false
}

func parseMounts() map[string]MountStr {
	Res := make(map[string]MountStr)
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return Res
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue // Skip lines that don't have at least three parts
		}
		var mount MountStr
		mount.Target = parts[1]
		mount.Type = parts[2]
		mount.Path = parts[0]

		Res[parts[1]] = mount
	}

	if err := scanner.Err(); err != nil {
		return Res
	}
	return Res
}
func RoundToNearest10Minutes(timestamp int64) int64 {
	t := time.Unix(timestamp, 0)
	roundInterval := time.Duration(10) * time.Minute
	remainder := t.Minute() % 10
	if remainder < 5 {
		return t.Add(time.Duration(-remainder) * time.Minute).Truncate(roundInterval).Unix()
	}
	return t.Add(time.Duration(10-remainder) * time.Minute).Truncate(roundInterval).Unix()
}
func FileAppendContents(filePath string, text string) error {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()                     // Ensure the file is closed when done
	_, err = file.WriteString(text + "\n") // Add a newline after the text
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}
	return nil
}

func FilePutContents(filename string, data string) error {
	filename = strings.TrimSpace(filename)
	return os.WriteFile(filename, []byte(data), 0644)
}
func Trim(sval string) string {
	return strings.TrimSpace(sval)
}
func TrimAllSpaces(sval string) string {
	re := regexp.MustCompile(`\s+`)
	output := strings.TrimSpace(re.ReplaceAllString(sval, " "))
	return output
}
func StripSpecialChars(s string) string {
	var builder strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}
func ArrayUnshift(slice []string, element string) []string {
	return append([]string{element}, slice...)
}
func ReplaceBadChars(Str string) string {
	var specials = map[rune]struct{}{
		'\'': {}, '"': {}, '(': {}, ')': {}, '[': {}, ']': {},
		'=': {}, '+': {}, '!': {}, '*': {}, '£': {}, '$': {},
		',': {}, '<': {}, '>': {}, '~': {}, '#': {}, '{': {},
		'}': {}, '°': {}, '^': {}, '`': {}, '|': {}, '&': {},
		'/': {}, '\\': {}, ':': {}, ';': {}, '?': {}, '%': {},
		'ù': {}, '¨': {}, '¤': {}, '²': {},
	}
	return strings.Map(func(r rune) rune {
		if _, drop := specials[r]; drop {
			return -1
		}
		return r
	}, Str)

}
func StrToInt(svalue string) int {
	svalue = strings.TrimSpace(svalue)

	if svalue == "true" {
		return 1
	}
	if svalue == "false" {
		return 0
	}
	if svalue == "1" {
		return 1
	}
	if svalue == "0" {
		return 0
	}

	svalue = strings.Replace(svalue, ",", ".", 1)

	if strings.Contains(svalue, ".") {
		parts := strings.Split(svalue, ".")
		svalue = parts[0]
	}

	if len(svalue) == 0 {
		return 0
	}
	tkint, err := strconv.Atoi(string(svalue))
	if err == nil {
		return tkint
	}
	return 0
}
func StrToInt32(Str string) uint32 {
	value, err := strconv.ParseUint(Str, 10, 32)
	if err != nil {
		return uint32(0)
	}
	return uint32(value)
}
func Uint32ToStr(val uint32) string {
	return strconv.FormatUint(uint64(val), 10)
}

func IsStringHasProto(url string) bool {
	prefixes := []string{"http://", "https://", "ftps://", "ftp://"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(url, prefix) {

			return true
		}
	}
	return false

}

func URLGetIPandPort(rawURL string) (string, int) {

	if !IsStringHasProto(rawURL) {
		rawURL = "http://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", 0
	}
	hostname := parsedURL.Hostname()
	port := StrToInt(parsedURL.Port())
	return hostname, port
}

func IfKeyExistsStr(key string, myMap map[string]string) bool {
	if _, ok := myMap[key]; ok {
		return true
	}
	return false
}
func IfKeyExistsBool(key string, myMap map[string]bool) bool {
	if _, ok := myMap[key]; ok {
		return true
	}
	return false
}
func FQdn() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}

	addrs, err := net.LookupIP(host)
	if err != nil {
		return ""
	}

	var fqdn string
	for _, addr := range addrs {
		names, err := net.LookupAddr(addr.String())
		if err != nil {
			continue
		}
		if len(names) > 0 {
			fqdn = names[0]
			break
		}
	}

	return fqdn

}

func RemoveAllFilesInDir(directory string) error {
	if !IsDirDirectory(directory) {
		return nil
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		filePath := filepath.Join(directory, entry.Name())
		if entry.Type().IsRegular() {
			err := os.Remove(filePath)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func StrToInt64(svalue string) int64 {
	svalue = strings.TrimSpace(svalue)
	if strings.Contains(svalue, ".") {
		floatValue, err := strconv.ParseFloat(svalue, 64)
		if err != nil {
			return 0
		}
		return int64(math.Floor(floatValue))
	}
	n, err := strconv.ParseInt(svalue, 10, 64)
	if err == nil {
		return n
	}
	return 0
}
func ServerRunSince() int {
	// Get uptime in seconds
	up, err := host.Uptime()
	if err != nil {
		return 0
	}

	return int(up) / 60
}
func ServerRunSinceSeconds() int64 {
	// Get uptime in seconds
	up, err := host.Uptime()
	if err != nil {
		return 0
	}
	return int64(up)
}

func Int64ToString(svalue int64) string {
	return strconv.FormatInt(svalue, 10)
}
func IntToString(svalue int) string {
	return strconv.Itoa(svalue)
}
func Int32NilToBool(svalue sql.NullInt32) bool {
	if !svalue.Valid {
		return false
	}
	if svalue.Int32 == 1 {
		return true
	}
	return false
}
func Int32NilToInt(svalue sql.NullInt32) int {
	if !svalue.Valid {
		return 0
	}
	if svalue.Int32 == 1 {
		return 1
	}
	return 0
}
func BinaryToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
func ArticaGetFullVersion() string {

	if FileExists("/usr/share/artica-postfix/VERSION") {
		ARTICAVER := FileGetContents("/usr/share/artica-postfix/VERSION")
		SERVICEPACK := FileGetContents("/usr/share/artica-postfix/SP/" + ARTICAVER)
		if len(SERVICEPACK) == 0 {
			SERVICEPACK = "0"
		}
		HOTFIX := ArticaHotFixVersion()
		var f []string
		f = append(f, ARTICAVER)
		if StrToInt(SERVICEPACK) > 0 {
			f = append(f, fmt.Sprintf("Service Pack %v", SERVICEPACK))
		}
		if len(HOTFIX) > 0 {
			f = append(f, fmt.Sprintf("Hotfix %v", HOTFIX))
		}
		return strings.Join(f, " ")
	}
	return FileGetContents("/etc/artica-postfix/settings/Daemons/ARTICAREST_VERSION")
}
func ArticaHotFixVersion() string {
	var regexPattern = `HOTFIX.*?\].*?([0-9\-]+)`
	var re = regexp.MustCompile(regexPattern)
	srcfile := "/usr/share/artica-postfix/fw.updates.php"

	file, err := os.Open(srcfile)
	if err != nil {
		return ""
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) > 0 {
			_ = file.Close()
			return matches[1]
		}
	}
	if err := scanner.Err(); err != nil {
		return ""
	}
	_ = file.Close()
	return ""
}
func RoundToNearest5Minutes(timestamp int64) int64 {
	const interval = int64(300) // 300 seconds = 5 minutes
	halfInterval := interval / 2
	remainder := timestamp % interval
	if remainder >= halfInterval {
		return timestamp + interval - remainder
	}
	return timestamp - remainder
}

func Round(value float64, precision int) float64 {
	p := math.Pow10(precision)
	return math.Trunc((value+0.5/p)*p) / p
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
func WritePIDFile(path string) {
	DeleteFile(path)
	_ = FilePutContents(path, IntToString(os.Getpid()))
}

func getProcessStartTime(pid int) (uint64, error) {
	statFile := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statFile)
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 22 {
		return 0, fmt.Errorf("unexpected format in stat file")
	}

	startTimeTicks, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		return 0, err
	}

	return startTimeTicks, nil
}
func getUptime() (float64, error) {
	uptimeData, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}

	uptimeFields := strings.Fields(string(uptimeData))
	uptimeSeconds, err := strconv.ParseFloat(uptimeFields[0], 64)
	if err != nil {
		return 0, err
	}

	return uptimeSeconds, nil
}
func getClockTicksPerSecond() float64 {
	return float64(C.sysconf(C._SC_CLK_TCK))
}

func GetProcessTimeMin(pid int) int {

	startTimeTicks, err := getProcessStartTime(pid)
	if err != nil {
		fmt.Printf("Error getting process start time: %v\n", err)
		return 0
	}
	uptimeSeconds, err := getUptime()
	if err != nil {
		fmt.Printf("Error getting system uptime: %v\n", err)
		return 0
	}
	ticksPerSecond := getClockTicksPerSecond()
	startTimeSeconds := float64(startTimeTicks) / ticksPerSecond
	elapsedTimeSeconds := uptimeSeconds - startTimeSeconds
	elapsedTimeMinutes := elapsedTimeSeconds / 60
	return int(Round(elapsedTimeMinutes, 0))
}
func CheckGhosts(commands []string) {
	MyPID := os.Getpid()
	for _, zcommand := range commands {

		pid := PIDOFPattern(fmt.Sprintf("artica-phpfpm-service -%v", zcommand))
		log.Debug().Msgf("%v [%v]=%d", GetCalleRuntime(), zcommand, pid)
		if pid == MyPID {
			continue
		}
		if !ProcessExists(pid) {
			continue
		}

		ztime, _ := ProcessAgeInSeconds(pid)
		log.Debug().Msgf("%v [%v]=%d (%d seconds)", GetCalleRuntime(), zcommand, pid, ztime)
		if ztime > 60 {
			log.Warn().Msgf("%v KILL BAD Process artica-phpfpm-service %v that run more than 60s (%d seconds)", GetCalleRuntime(), zcommand, ztime)
			KillProcess(pid)
		}

	}
}
func CheckPID(commands []string, sleep bool) {
	if sleep {
		time.Sleep(1 * time.Second)
	}
	var command string
	if len(os.Args) > 1 {
		// Get the first argument
		command = os.Args[1]
		command = strings.TrimPrefix(command, "-")
	}

	MyPID := os.Getpid()

	for _, zcommand := range commands {

		if command == zcommand {
			log.Debug().Msgf("%v Executed command [%v] with PID:%d", GetCalleRuntime(), command, MyPID)
			pid := PIDOFPattern(fmt.Sprintf("artica-phpfpm-service -%v", zcommand))
			if pid > 0 {
				if pid != MyPID {
					log.Warn().Msgf("%v cannot run [%v] command, an already task [%v] command pid %d is running, aborting", GetCalleRuntime(), command, command, pid)
					os.Exit(0)
				}
				return
			}
		}
		pid := PIDOFPattern(fmt.Sprintf("artica-phpfpm-service -%v", zcommand))
		if ProcessExists(pid) {
			log.Warn().Msgf("%v cannot run [%v] command, an already task [%v] command pid %d is running, aborting", GetCalleRuntime(), command, zcommand, pid)
			os.Exit(0)
		}
	}
}

func ProcessNSpgid(pid int) int {
	pgid, err := unix.Getpgid(pid)
	if err != nil {
		return 0
	}
	return pgid
}

func ProcessExists(pid int) bool {
	if pid == 0 {
		return false
	}
	if pid == 1 {
		return false
	}
	if isProcessZombie(pid) {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil
}

func ExecProcessWhithoutWait(Process string) {
	Chmod(Process, 0755)
	cmd := exec.Command(Process)

	go func() {
		err := cmd.Start()
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Error starting command: %v", err))
			return
		}
	}()

}
func RunWithNohup(bin string, logPath string, args ...string) (int, error) {
	// Resolve nohup
	nohupPath := FindProgram("nohup")

	// Prepare log file (equivalent to `>/tmp/start.log 2>&1`)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open log file: %w", err)
	}
	defer func(logFile *os.File) {
		_ = logFile.Close()
	}(logFile)

	// /dev/null as stdin (what shells typically do for background daemons)
	nullIn, err := os.OpenFile("/dev/null", os.O_RDONLY, 0)
	if err != nil {
		return 0, fmt.Errorf("open /dev/null: %w", err)
	}
	defer func(nullIn *os.File) {
		_ = nullIn.Close()
	}(nullIn)

	// Build: nohup <bin> <args...>
	cmd := exec.Command(nohupPath, append([]string{bin}, args...)...)
	cmd.Stdin = nullIn
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = ExecEnv() // preserve environment like a normal shell call

	// Optional but helpful: detach from controlling TTY/session.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start with nohup: %w", err)
	}

	// Background: don't wait (equivalent to '&')
	if err := cmd.Process.Release(); err != nil {
		return cmd.Process.Pid, fmt.Errorf("started but failed to release: %w", err)
	}

	return cmd.Process.Pid, nil
}

func StopProcess(pid int) bool {
	if !ProcessExists(pid) {
		return true
	}
	cmdline := ProcessCommandLine(pid)
	logKillProc(fmt.Sprintf("KILL SIGTERM %d [%v]", pid, cmdline))
	err := syscall.Kill(pid, syscall.SIGTERM)
	if err != nil {
		return false
	}
	return true
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

func ContainsI(content string, search string) bool {

	if strings.ToLower(content) == strings.ToLower(search) {
		return true
	}

	return strings.Contains(
		strings.ToLower(content),
		strings.ToLower(search),
	)
}
func KillSmoothProcess(pid int) bool {

	if !ProcessExists(pid) {
		return true
	}

	cmdline := ProcessCommandLine(pid)
	logKillProc(fmt.Sprintf("KILL SIGTERM %d [%v]", pid, cmdline))
	err := syscall.Kill(pid, syscall.SIGTERM)
	if err != nil {
		return false
	}
	return true
}

func KillProcess(pid int) bool {
	if !ProcessExists(pid) {
		return true
	}
	cmdline := ProcessCommandLine(pid)
	logKillProc(fmt.Sprintf("KILL SIGKILL %d [%v]", pid, cmdline))
	err := syscall.Kill(pid, syscall.SIGKILL)
	if err != nil {
		return false
	}
	return true
}
func KillProcessHUP(pid int) bool {
	if !ProcessExists(pid) {
		return true
	}
	cmdline := ProcessCommandLine(pid)
	logKillProc(fmt.Sprintf("KILL HUP %d [%v]", pid, cmdline))
	err := syscall.Kill(pid, syscall.SIGHUP)
	if err != nil {
		return false
	}
	return true
}
func KillProcessUSR1(pid int) bool {

	if !ProcessExists(pid) {
		return true
	}
	cmdline := ProcessCommandLine(pid)
	logKillProc(fmt.Sprintf("KILL SIGUSR1 %d [%v]", pid, cmdline))
	err := syscall.Kill(pid, syscall.SIGUSR1)
	if err != nil {
		return false
	}
	return true
}
func KillProcessUSR2(pid int) bool {
	if !ProcessExists(pid) {
		return true
	}
	err := syscall.Kill(pid, syscall.SIGUSR2)
	if err != nil {
		return false
	}
	return true
}
func KillReloadProcess(pid int) bool {
	if !ProcessExists(pid) {
		return true
	}
	cmdline := ProcessCommandLine(pid)
	logKillProc(fmt.Sprintf("KILL SIGHUP %d [%v]", pid, cmdline))
	err := syscall.Kill(pid, syscall.SIGHUP)

	if err != nil {
		return false
	}
	return true
}

func RemoveDuplicateRows(array []string) []string {

	uniqueRows := make(map[string]bool)
	var Cleaned []string

	for _, rowStr := range array {
		rowStr = Trim(rowStr)
		if len(rowStr) == 0 {
			continue
		}

		if _, exists := uniqueRows[rowStr]; !exists {
			uniqueRows[rowStr] = true
			Cleaned = append(Cleaned, rowStr)
		}
	}
	return Cleaned
}

func isProcessZombie(pid int) bool {
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	content, err := os.ReadFile(statusFile)
	if err != nil {
		return false
	}

	// Parse the status file
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "State:") {
			return strings.Contains(line, "zombie") || strings.Contains(line, "Z")
		}
	}

	return false
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
		if RegexFind(regexp.MustCompile(PnameRegex), zcmdline) {
			//fmt.Println(PnameRegex, "matches", zcmdline)
			return int(pid)
		}

	}
	return 0
}
func PIDOFPatternALL(PnameRegex string) []int {
	processes, err := process.Processes()
	var pids []int
	if err != nil {
		return pids
	}

	for _, p := range processes {
		zcmdline, _ := p.Cmdline()
		if len(zcmdline) == 0 {
			zcmdline, _ = p.Name()
		}
		pid := p.Pid
		if RegexFind(regexp.MustCompile(PnameRegex), zcmdline) {
			pids = append(pids, int(pid))
		}

	}
	return pids
}
func PIDisZombie(pid int) bool {
	statusFilePath := fmt.Sprintf("/proc/%d/status", pid)
	content, err := os.ReadFile(statusFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		return false
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "State:") {
			if strings.Contains(line, "Z (zombie)") {
				return true
			}
			break
		}
	}

	return false
}

func GetPPID(childPID int32) int {

	proc, err := process.NewProcess(childPID)
	if err != nil {
		return 0
	}

	ppid, err := proc.Ppid()
	if err != nil {
		return 0
	}

	return int(ppid)
}

func UpdateArticaBin() {
	SrcPath := "/usr/share/artica-postfix/bin/articarest"
	if !fileExists(SrcPath) {
		return
	}

	Md51 := MD5File(SrcPath)

	md53 := MD5File("/usr/sbin/artica-phpfpm-service")
	if md53 == Md51 {
		return
	}
	_ = CopyFile(SrcPath, "/usr/sbin/artica-phpfpm-service")
	Chmod("/usr/sbin/artica-phpfpm-service", 0755)
}

func DateToPostGreSQLMinute() string {
	location, _ := time.LoadLocation("Local")
	currentTime := time.Now().In(location)
	roundedTime := currentTime.Round(time.Minute)
	return roundedTime.Format("2006-01-02 15:04:05")
}

func PPIDof(childPID int32) int {

	proc, err := process.NewProcess(childPID)
	if err != nil {
		return 0
	}

	ppid, err := proc.Ppid()
	if err != nil {
		return 0
	}

	return int(ppid)
}
func HasDotPrefixRemove(originalString string) string {
	if !strings.HasPrefix(originalString, ".") {
		return originalString
	}
	find := RegexGroup1(futilsDotPrefix, originalString)
	if len(find) > 0 {
		return find
	}
	return originalString
}
func HasHatPrefixRemove(originalString string) string {
	if !strings.HasPrefix(originalString, "^") {
		return strings.TrimPrefix(originalString, "^")
	}
	return originalString
}
func RegexFind(pattern *regexp.Regexp, data string) bool {
	matched := pattern.MatchString(data)
	return matched
}

func RegexFindInfile(filepath string, pattern *regexp.Regexp) bool {

	if !FileExists(filepath) {
		return false
	}

	file2, err := os.Open(filepath)
	if err != nil {
		return false
	}
	defer func(file2 *os.File) {
		err := file2.Close()
		if err != nil {

		}
	}(file2)
	scanner2 := bufio.NewScanner(file2)

	for scanner2.Scan() {
		line := scanner2.Text()
		if RegexFind(pattern, line) {
			return true
		}
	}
	return false
}

func StringToRegex(pattern string) string {
	// Perform replacements similar to str_replace in PHP
	pattern = strings.ReplaceAll(pattern, ".", `\.`)
	pattern = strings.ReplaceAll(pattern, "(", `\(`)
	pattern = strings.ReplaceAll(pattern, ")", `\)`)
	pattern = strings.ReplaceAll(pattern, "+", `\+`)
	pattern = strings.ReplaceAll(pattern, "?", `\?`)
	pattern = strings.ReplaceAll(pattern, "[", `\[`)
	pattern = strings.ReplaceAll(pattern, "]", `\]`)
	pattern = strings.ReplaceAll(pattern, "*", ".*")

	return pattern
}
func StringToRegexSquid(pattern string) string {
	if len(pattern) < 3 {
		return ""
	}

	trap := RegexGroup1(futilsPattern2, pattern)
	if len(trap) > 1 {
		return trap
	}
	pattern = strings.ReplaceAll(pattern, `.`, `\.`)
	pattern = strings.ReplaceAll(pattern, `(`, `\(`)
	pattern = strings.ReplaceAll(pattern, `)`, `\)`)
	pattern = strings.ReplaceAll(pattern, `+`, `\+`)
	pattern = strings.ReplaceAll(pattern, `|`, `\|`)
	pattern = strings.ReplaceAll(pattern, `{`, `\{`)
	pattern = strings.ReplaceAll(pattern, `}`, `\}`)
	pattern = strings.ReplaceAll(pattern, `?`, `\?`)
	pattern = strings.ReplaceAll(pattern, `http://`, `^http://`)
	pattern = strings.ReplaceAll(pattern, `https://`, `^https://`)
	pattern = strings.ReplaceAll(pattern, `ftp://`, `^ftp://`)

	trap = RegexGroup1(futilsPattern3, pattern)
	if len(trap) > 1 {
		pattern = fmt.Sprintf("-%v", trap)
	}

	trap = RegexGroup1(futilsPattern4, pattern)
	if len(trap) > 1 {
		pattern = trap
	}

	trap = RegexGroup1(futilsPattern5, pattern)
	if len(trap) > 1 {
		pattern = fmt.Sprintf("(^|\\.)%v", trap)
	}

	trap = RegexGroup1(futilsPattern6, pattern)
	if len(trap) > 1 {
		pattern = fmt.Sprintf("(^|\\.)%v", trap)
	}
	pattern = strings.ReplaceAll(pattern, `(^|\.)\.`, `(^|\.)`)
	pattern = strings.ReplaceAll(pattern, `ftps://`, `^ftps://`)
	pattern = strings.ReplaceAll(pattern, `*`, `[0-9a-z_\-\.]+`)
	return pattern
}
func ExecuteDetachArray(commandStr []string) (error, string) {
	cmd := exec.Command(commandStr[0], commandStr[1:]...)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open /dev/null: %w", err), ""
	}
	defer func(devNull *os.File) {
		_ = devNull.Close()
	}(devNull)

	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err), ""
	}
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("failed to release process: %w", err), ""
	}

	return nil, ""
}
func ExecuteDetach(commandStr string) (error, string) {
	args := strings.Fields(commandStr)
	if len(args) == 0 {
		return fmt.Errorf("empty command"), "empty command"
	}
	return ExecuteDetachArray(args)
}

func ExecuteShellNoWait(CommandLine, TempFile string) error {
	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)
	if ok {
		file := Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s.%v.%d", file, fn.Name(), line)
		TheCall = strings.ReplaceAll(TheCall, "/", ".")
	}
	tempDir := TEMPDIR() + "/exec"
	CreateDir(tempDir)
	Chmod(tempDir, 0755)
	CmdMD5 := Md5String(CommandLine)
	ScriptP := fmt.Sprintf("%v/%v.%v.sh", tempDir, TheCall, CmdMD5)
	if len(TempFile) == 0 {
		TempFile = "/dev/null"
	}
	var sh []string
	sh = append(sh, "#!/bin/sh")
	sh = append(sh, "export  PATH=\"/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin\"")
	ex := ExecEnv()
	for _, zEnv := range ex {
		sh = append(sh, fmt.Sprintf("export %v", zEnv))
	}
	sh = append(sh, "")
	nohup := FindProgram("nohup")
	executeLogging(fmt.Sprintf("%v [%v %v >%v 2>&1 &]->ExecuteShellNoWait (0.0 seconds)", TheCall, nohup, CommandLine, TempFile))
	sh = append(sh, fmt.Sprintf("%v %v >%v 2>&1 &", nohup, CommandLine, TempFile))
	sh = append(sh, "")
	sh = append(sh, "")
	err := FilePutContents(ScriptP, strings.Join(sh, "\n"))
	if err != nil {
		log.Error().Msgf("%v %v", GetCalleRuntime(), err.Error())
	}
	Chmod(ScriptP, 0755)
	err, out := ExecuteShell(ScriptP)
	if err != nil {
		return fmt.Errorf("%v %v", err.Error(), out)
	}
	return nil

}
func Gethostbyname(host string) string {

	Key := fmt.Sprintf("Gethostbyname:%v", host)
	cachedData, found := DNSMem.Get(Key)
	if found {
		return cachedData.(string)
	}
	Hostsz := parseHostsFile()
	if len(Hostsz[host]) > 3 {
		DNSMem.Set(Key, Hostsz[host])
		return Hostsz[host]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		log.Error().Msgf("%v %v %v", GetCalleRuntime(), host, err)
		DNSMem.Set(Key, host)
		return host
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip.To4() != nil {
			DNSMem.Set(Key, ip.String())
			return ip.String()
		}
	}
	DNSMem.Set(Key, host)
	return host
}
func parseHostsFile() map[string]string {
	hostsFile := "/etc/hosts"

	file, err := os.Open(hostsFile)
	if err != nil {
		log.Error().Msgf("%v %v", GetCalleRuntime(), err.Error())
		return make(map[string]string)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	entries := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		ip := parts[0]
		// Map each host to its IP address
		for _, zhost := range parts[1:] {
			entries[zhost] = ip
		}
	}

	if err := scanner.Err(); err != nil {
		log.Error().Msgf("%v %v", GetCalleRuntime(), err.Error())
		return entries
	}

	return entries
}
func GethostbyIP(IpStr string) string {
	hostnames, err := net.LookupAddr(IpStr)
	if err != nil {
		return IpStr
	}
	for _, hostname := range hostnames {
		return hostname
	}

	return IpStr
}
func CheckPort(address string, port int, timeoutSeconds time.Duration) error {
	connAddress := fmt.Sprintf("%s:%d", address, port)
	conn, err := net.DialTimeout("tcp", connAddress, timeoutSeconds*time.Second)
	if err != nil {
		return fmt.Errorf("%s:%d Error: %s", address, port, err)
	}
	_ = conn.Close()
	return nil
}
func CheckUDPPort(address string, port int, timeoutSeconds time.Duration) error {
	addr := fmt.Sprintf("%s:%d", address, port)
	conn, err := net.DialTimeout("udp", addr, timeoutSeconds*time.Second)
	if err != nil {

		var opErr *net.OpError
		if errors.As(err, &opErr) {
			if opErr.Timeout() {
				return fmt.Errorf("remote UDP port %s:%d timed out, likely closed or filtered", address, port)
			}
			if strings.Contains(opErr.Error(), "connection refused") || strings.Contains(opErr.Error(), "port unreachable") {
				return fmt.Errorf("remote UDP port %s:%d is closed", address, port)
			}
		}
		msg := fmt.Sprintf("failed to check remote UDP port %s:%d: %v", address, port, err)
		return fmt.Errorf("%v", msg)
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)
	_, err = conn.Write([]byte("ping"))
	if err != nil {
		return fmt.Errorf("failed to send packet to %s:%d: %v, port may be open but unresponsive", address, port, err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return fmt.Errorf("failed to set read deadline for %s:%d: %v", address, port, err)
	}
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
			return nil
		}
		return nil
	}

	return nil

}

func CheckLocalPort(address string, port int, timeoutSeconds time.Duration) error {
	dialer := net.Dialer{
		Timeout:   timeoutSeconds * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")},
	}
	connAddress := fmt.Sprintf("%s:%d", address, port)
	conn, err := dialer.Dial("tcp", connAddress)
	if err != nil {
		return fmt.Errorf("%s:%d Error: %s", address, port, err)
	}
	_ = conn.Close()
	return nil
}
func ExecuteMe(Params string) (error, string) {
	possible := []string{"/usr/sbin/artica-phpfpm-service", "/usr/share/artica-postfix/bin/articarest", "/usr/sbin/articarest"}
	Me := ""
	for _, sPath := range possible {
		if FileExists(sPath) {
			Me = sPath
			break
		}
	}

	if !FileExists(Me) {
		log.Error().Msgf("%v Unable to find my program...", GetCalleRuntime())
		return fmt.Errorf("unable to find my program"), ""
	}

	cmd := exec.Command(Me, Params)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Error().Msgf("%v %v %v %v", GetCalleRuntime(), Me, Params, err.Error())
		return err, out.String()
	}
	return nil, out.String()
}

func dskspace_bytes(path string) int64 {
	var totalSize int64

	_ = filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		size := info.Size()
		totalSize += size

		return nil
	})

	return totalSize
}
func DirectorySizeKiB(directory string) int64 {
	if IsLink(directory) {
		directory = ReadLink(directory)
	}

	if !IsDirDirectory(directory) {
		return 0
	}
	size := dskspace_bytes(directory)
	result := size / 1024
	return result
}

func FormatBytes(sizeKB int64) string {
	const (
		KB = 1 << (10 * iota)
		MB
		GB
		TB
	)

	var value float64
	var unit string

	switch {
	case sizeKB >= TB:
		value = float64(sizeKB) / TB
		unit = "TB"
	case sizeKB >= GB:
		value = float64(sizeKB) / GB
		unit = "GB"
	case sizeKB >= MB:
		value = float64(sizeKB) / MB
		unit = "MB"
	default:
		value = float64(sizeKB)
		unit = "KB"
	}

	return fmt.Sprintf("%.2f %s", value, unit)
}

func BytesToKB(size int64) int64 {
	if size == 0 {
		return 0
	}
	Convert := float64(size) / float64(1024)
	return int64(Round(Convert, 0))
}

func roundUp(x int64) int64 {
	if x == 0 {
		return 0
	}
	return (x + kiloByte - 1) / kiloByte
}

func CommandLineExitIfRun(sValue string) {
	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)
	if ok {
		file := Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s.%v.%d", file, fn.Name(), line)
		TheCall = strings.ReplaceAll(TheCall, "/", ".")
	}
	PidPath := fmt.Sprintf("/etc/artica-postfix/pids/%v.pid", sValue)
	if FileExists(PidPath) {
		pid := GetPIDFromFile(PidPath)
		if ProcessExists(pid) {
			log.Warn().Msgf("%v Already pid %d (%v) exists called by [%v]", GetCalleRuntime(), pid, ProcessCommandLine(pid), TheCall)
			os.Exit(0)
		}
	}
	_ = FilePutContents(PidPath, IntToString(os.Getpid()))

}

func ExecEnv() []string {

	localeEnv := []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin:/usr/share/artica-postfix/bin:/lib/squid3",
		"NO_PROXY=" + nOprlist(),
		"DEBIAN_FRONTEND=noninteractive",
		"http_proxy=",
		"all_proxy=",
		"LANG=en_US.UTF-8",
		"USER=root",
		"LOGNAME=root",
		"HOME=/home/artica",
		"LANGUAGE=",
		"LC_CTYPE=C",
		"LC_NUMERIC=C",
		"LC_TIME=C",
		"LC_COLLATE=C",
		"LC_MONETARY=C",
		"LC_MESSAGES=C",
		"LC_PAPER=C",
		"LC_NAME=C",
		"LC_ADDRESS=C",
		"LC_TELEPHONE=C",
		"LC_MEASUREMENT=C",
		"LC_IDENTIFICATION=C",
		"LC_ALL=C",
	}
	return localeEnv
}
func executeLogging(msg string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	output := fmt.Sprintf("%s %s\n", timestamp, msg)
	file, _ := os.OpenFile("/var/log/executor.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer func(file *os.File) {
		_ = file.Close()

	}(file)
	_, _ = file.Write([]byte(output))

}
func ExecuteSettings(function string, params string, duration string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	output := fmt.Sprintf("%s %s [%v] (%v)\n", timestamp, function, params, duration)
	file, _ := os.OpenFile("/var/log/artica-settings.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer func(file *os.File) {
		_ = file.Close()

	}(file)
	_, _ = file.Write([]byte(output))

}

func ExecuteShellArray(CommandLines []string) (error, string) {
	start := time.Now()

	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)

	if ok {
		file := Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s[%v:%d]: ", file, fn.Name(), line)
	}

	rmBin := FindProgram("rm")
	TmpFile := TempFileName() + ".exec.sh"

	file, err := os.OpenFile(TmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		return err, ""
	}
	defer func(file *os.File, TmpFile string) {
		DeleteFile(TmpFile)
		_ = file.Close()

	}(file, TmpFile)

	writer := bufio.NewWriter(file)
	_, _ = writer.WriteString("#!/bin/sh\n")

	for _, a := range ExecEnv() {
		_, _ = writer.WriteString("export " + a + "\n")
	}
	for _, cmd := range CommandLines {
		_, _ = writer.WriteString(fmt.Sprintf("%v\n", cmd))
	}
	_, _ = writer.WriteString("STATUS=$?\n")
	_, _ = writer.WriteString(fmt.Sprintf("%v -f %v", rmBin, TmpFile))
	_, _ = writer.WriteString("exit $STATUS\n")
	err = writer.Flush()
	_ = file.Close()

	if err != nil {
		log.Error().Msgf("%v %v", GetCalleRuntime(), err.Error())
	}
	//log.Info().Msgf("%v [%v] -> %v %dbytes", GetCalleRuntime(), CommandLine, TmpFile, FileSize(TmpFile))

	Chmod(TmpFile, 0755)
	var cmd *exec.Cmd
	cmd = exec.Command(TmpFile)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		log.Debug().Msgf("%v %v", GetCalleRuntime(), err.Error())
		return err, ""
	}

	outBytes, _ := io.ReadAll(stdout)
	errBytes, _ := io.ReadAll(stderr)
	err = cmd.Wait()

	var t []string
	if len(string(outBytes)) > 0 {
		t = append(t, string(outBytes))
	}
	if len(string(errBytes)) > 0 {
		t = append(t, string(errBytes))
	}
	duration := time.Since(start).Seconds()
	executeLogging(fmt.Sprintf("%v [%v] (%.3f seconds)", TheCall, strings.Join(CommandLines, " AND "), duration))

	output := strings.Join(t, "\n")
	return err, output
}
func ExecCommandEnv(command string, env string) (string, error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", errors.New("empty command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Env = ExecEnv()

	cmd.Env = append(cmd.Env, env)
	// Execute command and capture output
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", context.DeadlineExceeded
	}
	if err != nil {
		return string(output), err
	}

	return string(output), nil
}

func ExecCommand(command string) (string, error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", errors.New("empty command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Env = ExecEnv()
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", context.DeadlineExceeded
	}
	if err != nil {
		return string(output), err
	}
	return string(output), nil
}
func ExecCommandViaShell(command string) (string, error) {

	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)
	if ok {
		file := Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s[%v:%d]: ", file, fn.Name(), line)
	}

	if strings.Contains(command, "/rrdtool ") {
		if SocketExists("/run/rrdcached.sock") {
			if !strings.Contains(command, "openvpn-clients") {
				command = strings.ReplaceAll(command, "rrdtool update", "rrdtool update --daemon unix:/run/rrdcached.sock")
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sh := FindProgram("sh")
	cmd := exec.CommandContext(ctx, sh, "-c", command)
	cmd.Env = ExecEnv()
	start := time.Now()
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", context.DeadlineExceeded
	}
	if err != nil {
		duration := time.Since(start).Seconds()
		executeLogging(fmt.Sprintf("%v ERROR [%v]->ExecCommandViaShell [%v] (%v) (%.3f seconds)", TheCall, command, err.Error(), string(output), duration))
		return string(output), err
	}
	duration := time.Since(start).Seconds()
	executeLogging(fmt.Sprintf("%v [%v]->ExecCommandViaShell  (%.3f seconds)", TheCall, command, duration))
	return string(output), nil
}
func GetSyncCred(Username string, GroupName string) (int, int) {
	u, err := user.Lookup(Username)
	if err != nil {
		log.Error().Msgf("%v failed to lookup user %s: %v", GetCalleRuntime(), Username, err)
		return 0, 0
	}
	g, err := user.LookupGroup(GroupName)
	if err != nil {
		log.Error().Msgf("%v failed to lookup group %s: %v", GetCalleRuntime(), GroupName, err)
		return 0, 0
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		log.Error().Msgf("%v invalid UID for user %s: %v", GetCalleRuntime(), Username, err)
		return 0, 0
	}

	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		log.Error().Msgf("%v invalid GID for group %s: %v", GetCalleRuntime(), GroupName, err)
		return 0, 0
	}
	return uid, gid

}
func CreateDBCmdLine(database string) (string, error) {
	uid, gid := GetSyncCredArticaStats()
	Binary := "/usr/local/ArticaStats/bin/createdb"
	cmd := exec.Command(Binary, "--owner=ArticaStats", "--host=/run/ArticaStats", database)
	cmd.Env = ExecEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}
	// Run the command and capture both stdout and stderr.
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Msgf("%v %v %v [%v]", GetCalleRuntime(), Binary, strings.Join(cmd.Args, " "), string(outBytes))
	}
	return string(outBytes), err
}
func GetSyncCredArticaStats() (int, int) {
	return GetSyncCred("ArticaStats", "ArticaStats")
}
func GetTimeZone() string {
	if b, err := os.ReadFile("/etc/timezone"); err == nil {
		tz := strings.TrimSpace(string(b))
		if tz != "" {
			if _, err := time.LoadLocation(tz); err == nil {
				return tz
			}
		}
	}

	// 3) /etc/localtime symlink into .../zoneinfo/Region/City
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		p := target
		if !strings.HasPrefix(p, "/") { // relative link
			p = filepath.Join("/etc", p)
		}
		p = filepath.Clean(p)
		if i := strings.Index(p, "/zoneinfo/"); i >= 0 {
			tz := strings.TrimPrefix(p[i+len("/zoneinfo/"):], "/")
			if _, err := time.LoadLocation(tz); err == nil {
				return tz
			}
		}
	}

	// 4) Last resort
	return "UTC"
}
func ExecuteShell(CommandLine string) (error, string) {
	start := time.Now()

	// Get caller information for logging.
	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)
	if ok {
		file := Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s[%v:%d]: ", file, fn.Name(), line)
	}

	// Handle special cases for /rrdtool and /useradd.
	if strings.Contains(CommandLine, "/rrdtool ") {
		//executeLogging(fmt.Sprintf("%v [%v]->ExecCommand [WAIT]", TheCall, CommandLine))
		out, err := ExecCommandViaShell(CommandLine)
		return err, out
	}
	if strings.Contains(CommandLine, "/useradd") {
		out, err := ExecCommand(CommandLine)
		duration := time.Since(start).Seconds()
		executeLogging(fmt.Sprintf("%v [%v]->ExecCommand (%.3f seconds)", TheCall, CommandLine, duration))
		return err, out
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel() // Ensure the context is canceled to release resources
	var outputBuf bytes.Buffer
	bash := FindProgram("bash")
	cmd := exec.CommandContext(ctx, bash, "-c", CommandLine)
	cmd.Env = ExecEnv()
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf

	if err := cmd.Start(); err != nil {
		executeLogging(fmt.Sprintf("%v failed to start command:[%v] %v", TheCall, CommandLine, err.Error()))
		return fmt.Errorf("%v from %v failed to start [%v]: %v", GetCalleRuntime(), TheCall, CommandLine, err), ""
	}

	err := cmd.Wait()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			executeLogging(fmt.Sprintf("%v timeout to start command:[%v] %v", TheCall, CommandLine, err.Error()))
			return fmt.Errorf("[%v] timed out after 40 seconds", CommandLine), outputBuf.String()
		}
		return fmt.Errorf("[%v] failed: %v", CommandLine, err), outputBuf.String()
	}
	duration := time.Since(start).Seconds()
	executeLogging(fmt.Sprintf("%v [%v] (%.3f seconds)", TheCall, CommandLine, duration))

	return nil, outputBuf.String()

}
func nOprlist() string {
	NoPr := []string{"127.0.0.1", "localhost", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"}
	return strings.Join(NoPr, ",")
}
func ExecuteShellAsUser(CommandLine string, targetUser string, targetGroup string, detach bool) (error, string) {

	shbin := FindProgram("sh")
	u, err := user.Lookup(targetUser)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %v", targetUser, err), ""
	}
	g, err := user.LookupGroup(targetGroup)
	if err != nil {
		return fmt.Errorf("failed to lookup group %s: %v", targetGroup, err), ""
	}

	// Convert UID and GID to integers
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("invalid UID for user %s: %v", targetUser, err), ""
	}

	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("invalid GID for group %s: %v", targetGroup, err), ""
	}

	_ = os.Unsetenv("http_proxy")
	_ = os.Unsetenv("https_proxy")
	_ = os.Unsetenv("all_proxy")

	cmd := exec.Command(shbin, "-c", CommandLine)
	zEnv := ExecEnv()
	for _, a := range zEnv {
		cmd.Env = append(os.Environ(), a)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}
	if detach {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true, // Detach from the controlling terminal
			Credential: &syscall.Credential{
				Uid: uint32(uid),
				Gid: uint32(gid),
			},
		}
	}

	for _, a := range zEnv {
		cmd.Env = append(os.Environ(), a)
	}

	if detach {
		devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("failed to open /dev/null: %v", err), ""
		}
		defer func(devNull *os.File) {
			err := devNull.Close()
			if err != nil {

			}
		}(devNull)

		cmd.Stdin = devNull
		cmd.Stdout = devNull
		cmd.Stderr = devNull

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start command: %v", err), ""
		}
		return nil, ""
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return err, string(output)
	}
	return nil, string(output)

}
func LoadAvg1min() float64 {
	avg, err := load.Avg()
	if err != nil {
		log.Error().Msgf("%v Unable to get the current machine load: %v", GetCalleRuntime(), err.Error())
		return 0
	}
	return avg.Load1
}
func DirectoryLastModifiedFileTime(directory string) int64 {
	// Read the directory
	if !IsDirDirectory(directory) {
		return 0
	}
	files, err := os.ReadDir(directory)
	if err != nil {
		return 0
	}

	var lastModifiedTime int64

	// Loop through the files
	for _, file := range files {
		if !file.IsDir() { // Only consider files, skip directories
			// Get the file modification time
			filePath := filepath.Join(directory, file.Name())
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				return 0
			}

			// Compare modification time
			modTime := fileInfo.ModTime().Unix() // Get modification time as int64 (Unix timestamp)
			if modTime > lastModifiedTime {
				lastModifiedTime = modTime
			}
		}
	}
	if lastModifiedTime == 0 {
		return 0
	}

	return lastModifiedTime
}
func IsSystemOverloaded() bool {
	Mnload := LoadAvg1min()
	numCPU := float64(runtime.NumCPU())
	return Mnload > numCPU
}

func CreateDir(directoryPath string) {
	directoryPath = strings.TrimSpace(directoryPath)
	if directoryPath == "" {
		return
	}
	tb := strings.Split(directoryPath, "/")
	if len(tb) < 2 || !strings.Contains(directoryPath, "/") {
		for skip := 0; ; skip++ {
			pc, file, line, ok := runtime.Caller(skip)
			if !ok {
				break
			}
			funcName := runtime.FuncForPC(pc).Name()
			funcName = strings.ReplaceAll(funcName, "/home/dtouzeau/go/src/github.com/dtouzeau/", "")
			file = strings.ReplaceAll(file, "/home/dtouzeau/go/src/github.com/dtouzeau/", "")
			funcName = strings.ReplaceAll(funcName, "github.com/dtouzeau/articarest/", "")
			funcName = strings.ReplaceAll(funcName, "articarest/dnsdist/", "")
			log.Warn().Msgf("%v --> %v", GetCalleRuntime(), fmt.Sprintf("%s:%d %s", file, line, funcName))
		}

		log.Warn().Msgf("%v Create Directory suspicious [%v]", GetCalleRuntime(), directoryPath)
	}
	directoryPath = strings.TrimSpace(directoryPath)
	directoryPath = strings.ReplaceAll(directoryPath, `'`, "")
	directoryPath = strings.ReplaceAll(directoryPath, `"`, "")
	directoryPath = strings.TrimSpace(directoryPath)
	_, err := os.Stat(directoryPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(directoryPath, 0755)
		if err != nil {
			return
		}
		return
	}
}

// Check if the patch is a Symbolic Link, if yes, return the real path
func ReadLink(SymbolicPath string) string {
	fileInfo, err := os.Lstat(SymbolicPath)
	if err != nil {
		return SymbolicPath
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		resolvedPath, err := filepath.EvalSymlinks(SymbolicPath)
		if err != nil {
			return SymbolicPath
		}
		return resolvedPath
	}

	return SymbolicPath
}

func CRC32File(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	hasher := crc32.NewIEEE()

	if _, err := io.Copy(hasher, file); err != nil {
		log.Error().Msg(fmt.Sprintf("[ERROR]: CRC32File(%v) to copy file content to hasher: %v", filePath, err.Error()))
		return ""
	}
	checksum := hasher.Sum32()
	return fmt.Sprintf("%x", checksum)
}

func BuilSHForExec(cmdline string, logfile string) string {
	var sh []string
	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)
	if ok {
		file := Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s.%v.%d", file, fn.Name(), line)
		TheCall = strings.ReplaceAll(TheCall, "/", ".")
	}
	tempDir := TEMPDIR() + "/exec"
	CreateDir(tempDir)
	Chmod(tempDir, 0755)
	CmdMD5 := Md5String(cmdline)
	Prog := fmt.Sprintf("%v/%v.%v.sh", tempDir, TheCall, CmdMD5)
	sh = append(sh, "#!/bin/sh")
	nohup := FindProgram("nohup")
	sh = append(sh, fmt.Sprintf("%v %v >%v 2>&1 &", nohup, cmdline, logfile))
	sh = append(sh, "\n")
	_ = FilePutContents(Prog, strings.Join(sh, "\n"))
	Chmod(Prog, 0755)
	return Prog
}

func ChmodRecursive(path string, mode os.FileMode) error {
	return filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chmod(path, mode)
	})
}

func RsyncCopyDir(src, dst string) error {
	rsync := FindProgram("rsync")
	if !FileExists(rsync) {
		log.Error().Msgf("%v rsync program not found", GetCalleRuntime())
		return fmt.Errorf("rsync program not found")
	}
	cmd := fmt.Sprintf("%v --ignore-missing-args -qra %v/* %v/", rsync, src, dst)
	log.Info().Msgf("%v [%v]", GetCalleRuntime(), cmd)
	err, out := ExecuteShell(cmd)
	if err != nil {
		log.Error().Msgf("%v Failed to run command [%s] %v: [%v]", GetCalleRuntime(), cmd, err, out)
		return fmt.Errorf("%v failed to run command [%s] %v [%v]", GetCalleRuntime(), cmd, err, out)
	}
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		log.Info().Msgf("%v [%v]", GetCalleRuntime(), line)
	}
	return nil
}

func Chmod(TargetPath string, desiredMode os.FileMode) {
	if !fileExists(TargetPath) {
		return
	}
	/*var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)
	if ok {
		file := Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s.%v.%d", file, fn.Name(), line)
		TheCall = strings.ReplaceAll(TheCall, "/", ".")
	}

	log.Debug().Msgf("%v [%v]->%v (%v)", GetCalleRuntime(), TargetPath, desiredMode, TheCall)

	*/
	_ = os.Chmod(TargetPath, desiredMode)
}
func getGroupIDByName(groupName string) (int, error) {
	if groupName == "root" {
		return 0, nil
	}
	file, err := os.Open("/etc/group")
	if err != nil {
		return -1, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[0] == groupName {
			var gid int
			_, _ = fmt.Sscanf(fields[2], "%d", &gid)
			return gid, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return -1, err
	}

	return -1, fmt.Errorf("group %s not found", groupName)
}

func ChmodFolder(path string, desiredMode os.FileMode) {
	if len(path) < 3 {
		return
	}
	if !IsDirDirectory(path) {
		return
	}

	if strings.HasSuffix(path, "*") {
		path = path[:len(path)-1]
	}

	_ = os.Chmod(path, desiredMode)

	Files := DirectoryScan(path)
	for _, spath := range Files {
		full := fmt.Sprintf("%v/%v", path, spath)
		full = strings.ReplaceAll(full, "//", "/")
		_ = os.Chmod(full, desiredMode)
	}
}

func ChomdRemoveOthers(path string) {

	info, err := os.Stat(path)
	if err != nil {
		return
	}
	mode := info.Mode()
	newMode := mode &^ 0o005

	err = os.Chmod(path, newMode)
	if err != nil {
		log.Error().Msgf("%v Error changing permissions: %v", GetCalleRuntime(), err.Error())
		return
	}

	log.Debug().Msgf("%v Successfully updated permissions for %s", GetCalleRuntime(), path)

}

func ChownFolder(folder string, username string, group string) {
	PrimaryGroupInt := 0
	groupid := -1
	Uid := -1
	if len(folder) < 3 {
		log.Debug().Msgf("%v [%v] folder too short", GetCalleRuntime(), folder)
		return
	}

	ScanIT := false
	if strings.HasSuffix(folder, "*") {
		ScanIT = true
		folder = folder[:len(folder)-1]
	}
	if !IsDirDirectory(folder) {
		log.Debug().Msgf("%v %v not a directory", GetCalleRuntime(), folder)
		return
	}

	if !IsNumeric(username) {
		u, err := user.Lookup(username)
		if err != nil {
			log.Debug().Msgf("%v lookup %v %v", GetCalleRuntime(), username, err.Error())
			return
		}
		Uid = StrToInt(u.Uid)
		groupid, err = getGroupIDByName(group)
		PrimaryGroupInt = StrToInt(u.Gid)
		if err != nil {
			groupid = PrimaryGroupInt
			log.Debug().Msgf("%v lookup %v %v", GetCalleRuntime(), group, err.Error())
		}
	} else {
		log.Debug().Msgf("%v lookup isNumeric:%v/%v", GetCalleRuntime(), Uid, group)
		Uid = StrToInt(username)
		groupid = StrToInt(group)
	}

	folder = strings.ReplaceAll(folder, "//", "/")
	log.Debug().Msgf("%v chown %v %d:%d", GetCalleRuntime(), folder, Uid, groupid)
	err := os.Chown(folder, Uid, groupid)
	if err != nil {
		log.Debug().Msgf("%v %v", GetCalleRuntime(), err.Error())
		return
	}
	if !ScanIT {
		return
	}
	Files := DirectoryScan(folder)
	for _, spath := range Files {
		full := fmt.Sprintf("%v/%v", folder, spath)
		full = strings.ReplaceAll(full, "//", "/")
		//log.Debug().Msgf("%v os.Chown(%v, %d,%d)", GetCalleRuntime(), full, StrToInt(u.Uid), groupid)
		err = os.Chown(full, Uid, groupid)
		if err != nil {
			log.Error().Msgf("%v chowning %v failed with %v", GetCalleRuntime(), full, err)
			return
		}
	}
}
func IsSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func IsUnixSocketAvailable(socketPath string) bool {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
func CopyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}
		return CopyFile(path, dstPath)
	})
	return err
}
func EXEC_NICE() string {

	useIonice := sockets.GET_INFO_INT("useIonice")
	useNice := sockets.GET_INFO_INT("useNice")
	ProcessNice := sockets.GET_INFO_INT("ProcessNice")
	ionice := ""
	nice := ""
	cgroupsEnabled := 0
	if IsDirDirectory("/cgroup/blkio/php") {
		cgroupsEnabled = 1
	}
	if cgroupsEnabled == 1 {
		if !FileExists("/usr/bin/cgexec") {
			cgroupsEnabled = 0
		}
	}
	if cgroupsEnabled == 1 {
		return "/usr/bin/cgexec -g cpu,cpuset,blkio:php "
	}
	if ProcessNice == 0 {
		ProcessNice = 19
	}
	if useIonice == 1 {
		if FileExists("/usr/bin/ionice") {
			ionice = "/usr/bin/ionice -c2 -n7 "
		}
	}

	if useNice == 1 {
		if FileExists("/usr/bin/nice") {
			nice = fmt.Sprintf("/usr/bin/nice --adjustment=%d ", ProcessNice)
		}
	}
	return fmt.Sprintf("%v%v", ionice, nice)

}

func PopuplateCronMake(cronfile string, schedule string, phpprocess string) {
	if len(schedule) < 5 {
		return
	}
	tfile := fmt.Sprintf("/etc/cron.d/%v", cronfile)
	md51 := CRC32File(tfile)

	PATH := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/X11R6/bin:/usr/share/artica-postfix/bin"

	nice := EXEC_NICE()
	var CRON []string
	CRON = append(CRON, fmt.Sprintf("PATH=%v", PATH))
	CRON = append(CRON, "MAILTO=\"\"")
	DevNull := " >/dev/null 2>&1"
	NOPHP := false
	if strings.Contains(phpprocess, "dev/null") {
		DevNull = ""
	}

	if strings.Contains(phpprocess, "artica-phpfpm-service") || strings.Contains(phpprocess, "usr/bin") {
		CRON = append(CRON, fmt.Sprintf("%v\troot\t%v %v%v", schedule, nice, phpprocess, DevNull))
		NOPHP = true
	}

	if !NOPHP {
		if strings.Contains(phpprocess, "/") {
			CRON = append(CRON, fmt.Sprintf("%v\troot\t%v %v%v", schedule, nice, phpprocess, DevNull))
		} else {
			php5 := FindProgram("php")
			if !FileExists(php5) {
				DeleteFile(tfile)
				return
			}
			CRON = append(CRON, fmt.Sprintf("%v\troot\t%v %v /usr/share/artica-postfix/%v%v", schedule, nice, php5, phpprocess, DevNull))
		}
	}

	CRON = append(CRON, "")
	_ = FilePutContents(tfile, strings.Join(CRON, "\n"))
	Chmod(tfile, 0640)
	ChownFile(tfile, "root", "root")

	md52 := CRC32File(tfile)
	if md51 == md52 {
		return
	}
	go func() {
		_, _ = ExecuteShell("/etc/init.d/cron reload")
	}()

}
func StrToHex(input string) string {
	return hex.EncodeToString([]byte(input))
}

func PopuplateCronDelete(cronfile string) {
	tfile := fmt.Sprintf("/etc/cron.d/%v", cronfile)
	if !FileExists(tfile) {
		return
	}
	DeleteFile(tfile)
	go func() {
		err, _ := ExecuteShell("/etc/init.d/cron reload")
		if err != nil {

		}
	}()
}
func GetMimeType(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil {
		return "", err
	}
	mimeType := http.DetectContentType(buffer)
	return mimeType, nil
}
func RenameWithRetry(oldPath, newPath string, retries int) error {
	const Duration = 1 * time.Second
	for i := 0; i < retries; i++ {
		err := os.Rename(oldPath, newPath)
		if err == nil {
			return nil
		}
		time.Sleep(Duration)
	}
	return fmt.Errorf("failed to rename after %d retries", retries)
}

func IsDirDirectory(directoryPath string) bool {
	directoryPath = strings.TrimSpace(directoryPath)
	if directoryPath == "" {
		return false
	}
	if !strings.HasPrefix(directoryPath, "/") {
		return false
	}

	if IsLink(directoryPath) {
		link, err := os.Readlink(directoryPath)
		if err != nil {
			return false
		}
		directoryPath = strings.TrimSpace(link)
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

func OrderMapInt64ToString(myMap map[int64]string) []string {
	var Res []string
	keys := make([]int64, 0, len(myMap))
	for k := range myMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		Res = append(Res, myMap[k])
	}
	return Res
}

func MD5File(filename string) string {
	if !fileExists(filename) {
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

func ChownFile(FilePath string, username string, group string) {

	if !fileExists(FilePath) {
		return
	}

	u, err := user.Lookup(username)
	if err != nil {
		return
	}
	groupid, err := getGroupIDByName(group)
	if err != nil {
		log.Error().Msgf("%v chowning group %v failed with %v %v", GetCalleRuntime(), FilePath, groupid, err)
		return
	}

	err = os.Chown(FilePath, StrToInt(u.Uid), groupid)
	if err != nil {
		return
	}
}
func ChownFileDetails(FilePath string, username string) error {

	if !fileExists(FilePath) {
		return fmt.Errorf(FilePath + " no such file")
	}
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf(FilePath + " " + username + " " + err.Error())

	}
	err = os.Chown(FilePath, StrToInt(u.Uid), StrToInt(u.Gid))
	if err != nil {

		return fmt.Errorf(FilePath + " Chown(" + username + ") " + err.Error())
	}
	return nil
}
func CurrentHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost.localdomain"
	}
	return hostname
}
func CurrentTimeStr() string {
	location, _ := time.LoadLocation("Local")
	currentTime := time.Now().In(location)
	return currentTime.Format("2006-01-02 15:04:05") // Use the desired format layout

}

func StrToTimeMinusDays(Days int) int64 {
	loc, err := time.LoadLocation("Local")
	if err != nil {
		return 0
	}
	now := time.Now().In(loc)
	sevenDaysAgo := now.AddDate(0, 0, -Days)
	return sevenDaysAgo.Unix()
}

func TimesTampSubstractDays(TimeStart int64, days int) int64 {
	location, _ := time.LoadLocation("Local")
	t := time.Unix(TimeStart, 0).In(location)
	tMinusDays := t.AddDate(0, 0, -days)
	return tMinusDays.Unix()
}

func HTTPTimeToTimeStamp(dateString string) int64 {
	layout := "Mon, 02 Jan 2006 15:04:05 MST"

	location, _ := time.LoadLocation("Local")
	parsedTime, err := time.ParseInLocation(layout, dateString, location)
	if err != nil {
		return int64(0)
	}
	return parsedTime.Unix()
}

func IsBase64(s string) bool {
	if len(s) == 0 {
		return false
	}
	if len(s)%4 != 0 {
		return false
	}
	if matched, _ := regexp.MatchString(`^[A-Za-z0-9+/]*={0,2}$`, s); !matched {
		return false
	}
	data, err := base64.StdEncoding.DecodeString(s)
	if len(data) == 0 {
		return false
	}
	return err == nil
}
func IsNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	if err == nil {
		return true
	}
	return false
}

func UrlDecode(s string) string {

	decodedStr, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return decodedStr
}

func Base64Decode(content string) string {
	decodedBytes, err := base64.StdEncoding.DecodeString(content)
	if err != nil {

		return ""
	}
	return string(decodedBytes)
}
func UnserializeArray(serializedData string) map[int]string {
	data := make(map[int]string)
	if len(serializedData) == 0 {
		return data
	}
	if !strings.Contains(serializedData, ":") {
		return data
	}

	phpData, err := gophp.Unserialize([]byte(serializedData))
	if err != nil {
		log.Error().Msgf("%v %v [%v]", GetCalleRuntime(), err.Error(), serializedData)
		return data
	}

	xarray, _ := phpData.(map[int]interface{})
	log.Info().Msgf("%v %v [%v]", GetCalleRuntime(), len(xarray), serializedData)
	for key, value := range xarray {
		data[key] = fmt.Sprintf("%v", value)
	}

	return data
}

func UnserializeMap1(serializedData string) map[string]string {
	data := make(map[string]string)
	if len(serializedData) == 0 {
		return data
	}
	if !strings.Contains(serializedData, ":") {
		return data
	}

	phpData, err := gophp.Unserialize([]byte(serializedData))
	if err != nil {
		log.Error().Msgf("%v %v [%v]", GetCalleRuntime(), err.Error(), serializedData)
		return data
	}

	xarray, _ := phpData.(map[string]interface{})

	for key, value := range xarray {
		data[key] = fmt.Sprintf("%v", value)
	}

	return data
}
func UnserializeMap2(serializedData string) map[string]map[string]string {
	data := make(map[string]map[string]string)
	if len(serializedData) == 0 {
		return data
	}

	var genericData map[interface{}]interface{}
	err := phpserialize.Unmarshal([]byte(serializedData), &genericData)
	if err != nil {
		log.Error().Msgf("%v %v [%v]", GetCalleRuntime(), err.Error(), serializedData)
		return data
	}
	return convertToTypedMap(genericData)
}
func convertToTypedMap(input map[interface{}]interface{}) map[string]map[string]string {
	result := make(map[string]map[string]string)

	for key, value := range input {
		//fmt.Println("+++++++++++++>", key, value)
		keyStr, ok := key.(string)
		if !ok {
			return result
		}

		valueMap, ok := value.(map[interface{}]interface{})
		if !ok {
			continue
		}
		result[keyStr] = make(map[string]string)

		for keyL2, value2 := range valueMap {
			result[keyStr][fmt.Sprintf("%v", keyL2)] = fmt.Sprintf("%v", value2)

		}

	}

	return result
}
func StripSpecialsChars(pattern string, asEmail bool) string {
	// Normalize accents
	pattern = ReplaceAccents(pattern)

	// Remove spaces
	pattern = strings.ReplaceAll(pattern, " ", "")

	// Remove dots and hyphens if not email
	if !asEmail {
		pattern = strings.ReplaceAll(pattern, ".", "")
		pattern = strings.ReplaceAll(pattern, "-", "")
	}
	specialChars := []string{"&", ",", ";", "%", "*", "ø", "$", "/", "\\", "?", "µ", "£", ")", "(", "[", "]", "#", "'", "\""}
	for _, char := range specialChars {
		pattern = strings.ReplaceAll(pattern, char, "")
	}
	pattern = strings.ReplaceAll(pattern, "+", "_")
	if utf8.RuneCountInString(pattern) > 20 {
		pattern = string([]rune(pattern)[:20])
	}

	return pattern
}

func ReplaceAccents(s string) string {
	if len(s) < 1 {
		return s
	}
	source := s
	s = html.EscapeString(s)
	if len(s) == 0 {
		s = source
		s = Utf8Encode(s)
		s = html.EscapeString(s)
	}
	s = replacePattern.ReplaceAllString(s, "$1")
	s = strings.ReplaceAll(s, `&Ntilde;`, `N`)
	s = strings.ReplaceAll(s, `&ntilde;`, `n`)
	s = strings.ReplaceAll(s, `&Oacute;`, `O`)
	s = strings.ReplaceAll(s, `&oacute;`, `O`)
	s = strings.ReplaceAll(s, `&Ograve;`, `O`)
	s = strings.ReplaceAll(s, `&ograve;`, `o`)
	s = strings.ReplaceAll(s, `&Ocirc;`, `O`)
	s = strings.ReplaceAll(s, `&ocirc;`, `o`)
	s = strings.ReplaceAll(s, `&Ouml;`, `O`)
	s = strings.ReplaceAll(s, `&ouml;`, `o`)
	s = strings.ReplaceAll(s, `&Otilde;`, `O`)
	s = strings.ReplaceAll(s, `&otilde;`, `o`)
	s = strings.ReplaceAll(s, `&Oslash;`, `O`)
	s = strings.ReplaceAll(s, `&oslash;`, `o`)
	s = strings.ReplaceAll(s, `&szlig;`, `b`)
	s = strings.ReplaceAll(s, `&Thorn;`, `T`)
	s = strings.ReplaceAll(s, `&thorn;`, `t`)
	s = strings.ReplaceAll(s, `&Uacute;`, `U`)
	s = strings.ReplaceAll(s, `&uacute;`, `u`)
	s = strings.ReplaceAll(s, `&Ugrave;`, `U`)
	s = strings.ReplaceAll(s, `&ugrave;`, `u`)
	s = strings.ReplaceAll(s, `&Ucirc;`, `U`)
	s = strings.ReplaceAll(s, `&ucirc;`, `u`)
	s = strings.ReplaceAll(s, `&Uuml;`, `U`)
	s = strings.ReplaceAll(s, `&uuml;`, `u`)
	s = strings.ReplaceAll(s, `&Yacute;`, `Y`)
	s = strings.ReplaceAll(s, `&yacute;`, `y`)
	s = strings.ReplaceAll(s, `&yuml;`, `y`)
	s = strings.ReplaceAll(s, `&Icirc;`, `I`)
	s = strings.ReplaceAll(s, `&icirc;`, `i`)
	s = html.UnescapeString(s)
	return s
}
func Latin1ToUTF8(b []byte) string {
	r := transform.NewReader(bytes.NewReader(b), charmap.ISO8859_1.NewDecoder())
	out, _ := io.ReadAll(r)
	return string(out)
}

func Utf8Encode(s string) string {
	iso8859_1 := []byte{
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
		0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
		0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
		0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
		0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
		0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
	} // äöüÄÖÜ in ISO-8859-1
	reader := transform.NewReader(bytes.NewReader(iso8859_1), charmap.ISO8859_1.NewEncoder())
	utf8, err := io.ReadAll(reader)
	if err != nil {
		return s
	}

	return string(utf8)
}

func Utf8Decode(s string) string {
	// Pre-allocate a byte slice with len(s) as an upper bound
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r <= 0xFF {
			b = append(b, byte(r))
		} else {
			b = append(b, '?')
		}
	}
	return string(b)
}
func MapEqualStringBoolSets(a, b map[string]bool) bool {

	if len(a) != len(b) {
		return false
	}

	for k, av := range a {
		if av && !b[k] {
			return false
		}
	}
	// And b must not have extra trues
	for k, bv := range b {
		if bv && !a[k] {
			return false
		}
	}
	return true
}

func ExecutePHP(phpfilenameandcommand string) (error, string) {
	ArticaPath := "/usr/share/artica-postfix"
	phpBin := "/usr/bin/php"
	if !IsDirDirectory(ArticaPath) {
		return errors.New(fmt.Sprintf("%v:: %v no such directory", GetCalleRuntime(), ArticaPath)), ""
	}
	tb := strings.Fields(phpfilenameandcommand)
	if len(tb) == 0 {
		return fmt.Errorf("%v empty command string [%v]", GetCalleRuntime(), phpfilenameandcommand), ""
	}
	script := ""
	var args []string
	for i, val := range tb {
		val = strings.TrimSpace(val)
		if strings.HasSuffix(val, ".php") {
			script = val
			args = tb[i+1:]
			break
		}
	}

	if script == "" {
		return fmt.Errorf("%v no PHP script found in input: %s", GetCalleRuntime(), phpfilenameandcommand), ""
	}

	phpScriptPath := fmt.Sprintf("%s/%s", ArticaPath, script)
	cmd := exec.Command(phpBin, phpScriptPath)
	cmd.Args = append([]string{phpBin, phpScriptPath}, args...)
	cmd.Env = ExecEnv()
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Msgf("%v [%v] %v", GetCalleRuntime(), phpfilenameandcommand, err.Error())
		return fmt.Errorf("[%v] err:[%v]", cmd.String(), err), string(output)
	}
	return nil, string(output)
}
func ExecuteBash(CommandLine string) (error, string) {
	bash := FindProgram("bash")
	cmd := exec.Command(bash, "-c", CommandLine)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return err, string(output)
	}
	return nil, string(output)
}
func ExecutePHPNoHUP(phpfilenameandcommand string) (error, string) {
	ArticaPath := "/usr/share/artica-postfix"
	phpBin := "/usr/bin/php"
	nohup := FindProgram("nohup")
	if !IsDirDirectory(ArticaPath) {
		return errors.New(fmt.Sprintf("LinuxExecutePHP:: %v no such directory", ArticaPath)), ""
	}
	bash := FindProgram("bash")
	CommandLine := fmt.Sprintf("%v %v %v/%v >/dev/null 2>&1 &", nohup, phpBin, ArticaPath, phpfilenameandcommand)
	cmd := exec.Command(bash, "-c", CommandLine)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return err, string(output)
	}
	return nil, string(output)
}
func BaseName(fullPath string) string {
	return filepath.Base(fullPath)
}

func SetFileDescriptorLimit(pid int, soft, hard uint64) error {
	var rlim unix.Rlimit
	rlim.Cur = soft
	rlim.Max = hard

	return unix.Prlimit(pid, unix.RLIMIT_NOFILE, &rlim, nil)
}

func DetectSpecialCharacters(input string) bool {
	specialCharacters := []string{"[", "]", "(", ")", "+", "\"", "~", "&", "'", "|",
		"\\", "/", ":", "!", "§", ",", "*", "£", "}", "{", "#", "²", "-", "=", ">", "<", "?"}
	for _, char := range specialCharacters {
		if strings.Contains(input, char) {
			return true // Special character detected
		}
	}
	return false // No special characters detected
}

func RegexGroup1(pattern *regexp.Regexp, str string) string {

	res := pattern.FindStringSubmatch(str)
	if len(res) < 2 {
		return ""
	}
	return res[1]
}

func RegexGroup1File(pattern *regexp.Regexp, FilePath string, SkipRemark bool) []string {
	if !FileExists(FilePath) {
		return []string{}
	}
	file, err := os.Open(FilePath)
	if err != nil {
		log.Error().Msgf("%v Failed to open file: %s", GetCalleRuntime(), err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	scanner := bufio.NewScanner(file)
	var l []string
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if SkipRemark {
			if strings.HasPrefix(line, "#") {
				continue
			}
		}
		portStr := RegexGroup1(pattern, line)
		if len(portStr) == 0 {
			continue
		}
		l = append(l, portStr)
	}
	if err := scanner.Err(); err != nil {
		log.Error().Msgf("%v Error reading file: %s", GetCalleRuntime(), err)
	}
	return l

}

func ReverseStringArray(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i] // Swap elements
	}
	return s
}

func RegexGroup2(pattern *regexp.Regexp, str string) (string, string) {
	res := pattern.FindStringSubmatch(str)
	if len(res) < 3 {
		return "", ""
	}
	return res[1], res[2]
}
func RegexGroup3(pattern *regexp.Regexp, str string) (string, string, string) {
	res := pattern.FindStringSubmatch(str)
	if len(res) < 4 {
		return "", "", ""
	}
	return res[1], res[2], res[3]
}

func RegexGroup4(pattern *regexp.Regexp, str string) (string, string, string, string) {
	res := pattern.FindStringSubmatch(str)
	if len(res) < 5 {
		return "", "", "", ""
	}
	return res[1], res[2], res[3], res[4]
}

func RegexGroup5(pattern *regexp.Regexp, str string) (string, string, string, string, string) {
	res := pattern.FindStringSubmatch(str)
	if len(res) < 6 {
		return "", "", "", "", ""
	}
	return res[1], res[2], res[3], res[4], res[5]
}
func RegexGroup7(pattern *regexp.Regexp, str string) (string, string, string, string, string, string, string) {
	res := pattern.FindStringSubmatch(str)
	if len(res) < 6 {
		return "", "", "", "", "", "", ""
	}
	return res[1], res[2], res[3], res[4], res[5], res[6], res[7]
}
func IsInteger(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

var ppidPattern = regexp.MustCompile(`^PPid:\s+([0-9]+)`)

func PPIDOf(pid int) int {
	if pid == 0 {
		return 0
	}

	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		match := ppidPattern.FindStringSubmatch(line)
		if match != nil {
			ppidStr := match[1]
			ppid, err := strconv.Atoi(ppidStr)
			if err != nil {
				return 0
			}
			return ppid
		}
	}
	return 0
}
func PIDOF_DOCKER(pid int) bool {
	if !FileExists("/etc/init.d/docker") {
		return false
	}
	PPID := PPIDOf(pid)
	cmdline := ProcessCommandLine(PPID)
	return strings.Contains(cmdline, "/containerd")

}

func PIDOFByPort(port int) []int {
	netstat := FindProgram("netstat")

	var pids []int
	cmd := exec.Command(netstat, "-tulnp")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return pids
	}

	tbs := strings.Split(string(out), "\n")
	for _, line := range tbs {
		match := tcpPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		DiscoveredPort := StrToInt(match[1])
		if DiscoveredPort != port {
			continue
		}
		pidStr := match[2]
		pid := StrToInt(pidStr)
		if pid < 5 {
			continue // Skip invalid or system PIDs
		}
		isDocker := PIDOF_DOCKER(pid)
		if isDocker {
			continue // Skip Docker container PIDs
		}

		pids = append(pids, pid)
	}
	return pids
}

func PIDOF_TCP_PORT(ipaddr string, port int64) int {
	netstat := FindProgram("netstat")
	_, out := ExecuteShell(fmt.Sprintf("%v -ltpn", netstat))
	ipaddr = strings.ReplaceAll(ipaddr, ".", `\.`)
	pattern := fmt.Sprintf("^tcp\\s+[0-9]+\\s+[0-9]+\\s+%v:%d\\s+.*?\\s+([0-9]+)\\/", ipaddr, port)
	var futilsPattern7 = regexp.MustCompile(pattern)
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line := Trim(line)
		if len(line) < 2 {
			continue
		}
		PidString := RegexGroup1(futilsPattern7, line)
		if len(PidString) > 1 {
			return StrToInt(PidString)
		}
	}

	return 0
}

func PidofUdpPort(ipaddr string, port int64) int {
	netstat := FindProgram("netstat")
	_, out := ExecuteShell(fmt.Sprintf("%v -lupn", netstat))
	ipaddr = strings.ReplaceAll(ipaddr, ".", `\.`)
	pattern := fmt.Sprintf("^udp\\s+[0-9]+\\s+[0-9]+\\s+%v:%d\\s+.*?\\s+([0-9]+)\\/", ipaddr, port)
	var futilsPattern8 = regexp.MustCompile(pattern)
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line := Trim(line)
		if len(line) < 2 {
			continue
		}
		PidString := RegexGroup1(futilsPattern8, line)
		if len(PidString) > 1 {
			return StrToInt(PidString)
		}
	}

	return 0
}

func TempFileName() string {
	tempDir := TEMPDIR()
	timestamp := time.Now().UnixNano()

	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)
	if ok {
		file := Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s.%v.%d", file, fn.Name(), line)
		TheCall = strings.ReplaceAll(TheCall, "/", ".")
	}

	path := fmt.Sprintf("%s/tempfile_%v_%d.tmp", tempDir, TheCall, timestamp)
	if FileExists(path) {
		timestamp = time.Now().UnixNano() + time.Now().UnixNano()*35
	}
	return fmt.Sprintf("%s/tempfile_%v_%d.tmp", tempDir, TheCall, timestamp)
}
func ArticaCurrentHotfix() int {
	PhpFile := "/usr/share/artica-postfix/fw.updates.php"
	if !FileExists(PhpFile) {
		return 0
	}
	f := strings.Split(FileGetContents(PhpFile), "\n")
	for _, line := range f {
		if strings.HasPrefix(line, `$GLOBALS["HOTFIX"]`) {
			line := strings.TrimSpace(line)
			tb := strings.Split(line, "=")
			hf := tb[1]
			hf = strings.ReplaceAll(hf, `"`, "")
			hf = strings.ReplaceAll(hf, `;`, "")
			hf = strings.ReplaceAll(hf, `-`, "")
			return StrToInt(hf)
		}
	}
	return 0
}

func Md5String(str string) string {
	h := md5.New()
	_, _ = io.WriteString(h, str)
	return fmt.Sprintf("%x", h.Sum(nil))
}
func CurDateAddDay(daysToAdd int) string {
	currentTime := time.Now()
	if daysToAdd == 0 {
		daysToAdd = 5
	}
	newTime := currentTime.AddDate(0, 0, daysToAdd)
	return newTime.Format("2006-01-02 15:04:05")
}
func SetStickyBit(dir string) error {
	// Get current file info
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("failed to stat directory %s: %v", dir, err)
	}

	// Get current permissions
	mode := info.Mode()

	// Add sticky bit to permissions
	newMode := mode | os.ModeSticky

	// Apply the new mode using chmod
	err = os.Chmod(dir, newMode.Perm())
	if err != nil {
		return fmt.Errorf("failed to set sticky bit on %s: %v", dir, err)
	}

	log.Debug().Msgf("%v Sticky bit set successfully on %s", GetCalleRuntime(), dir)
	return nil
}

func DirName(sFilepath string) string {
	return filepath.Dir(sFilepath)
}
func Crc32File(fname string) string {
	file, err := os.Open(fname)
	if err != nil {
		return ""
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	hash := crc32.NewIEEE()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}

	return fmt.Sprintf("%08x", hash.Sum32())
}
func DistanceOfTimeInWordsInterface(fromTime, toTime time.Time, showLessThanAMinute bool) string {
	distanceInSeconds := math.Abs(toTime.Sub(fromTime).Seconds())
	distanceInMinutes := math.Round(distanceInSeconds / 60)

	if distanceInMinutes <= 1 {
		if !showLessThanAMinute {
			if distanceInMinutes == 0 {
				return "{lessthanaminute}"
			}
			return "1 {minute}"
		} else {
			switch {
			case distanceInSeconds < 5:
				return fmt.Sprintf("{lessthan} 5 {seconds} (%.0fs)", distanceInSeconds)
			case distanceInSeconds < 10:
				return fmt.Sprintf("{lessthan} 10 {seconds} (%.0fs)", distanceInSeconds)
			case distanceInSeconds < 20:
				return fmt.Sprintf("{lessthan} 20 {seconds} (%.0fs)", distanceInSeconds)
			case distanceInSeconds < 40:
				return fmt.Sprintf("{abouttime} {halfaminute} (%.0fs)", distanceInSeconds)
			case distanceInSeconds < 60:
				return "{lessthanaminute}"
			default:
				return "1 {minute}"
			}
		}
	}
	if distanceInMinutes < 45 {
		return fmt.Sprintf("%.0f {minutes}", distanceInMinutes)
	}
	if distanceInMinutes < 90 {
		return "{abouttime} 1 {hour}"
	}
	if distanceInMinutes < 1440 {
		return fmt.Sprintf("{abouttime} %.0f {hours}", math.Round(distanceInMinutes/60))
	}
	if distanceInMinutes < 2880 {
		return "1 {day}"
	}
	if distanceInMinutes < 43200 {
		return fmt.Sprintf("{abouttime} %.0f {days}", math.Round(distanceInMinutes/1440))
	}
	if distanceInMinutes < 86400 {
		return "{abouttime} 1 {month}"
	}
	if distanceInMinutes < 525600 {
		return fmt.Sprintf("%.0f {months}", math.Round(distanceInMinutes/43200))
	}
	if distanceInMinutes < 1051199 {
		return "{abouttime} 1 {year}"
	}

	return fmt.Sprintf("over %.0f {years}", math.Round(distanceInMinutes/525600))
}
func DistanceOfTimeInWords(fromTime, toTime time.Time, showLessThanAMinute bool) string {
	distanceInSeconds := math.Abs(toTime.Sub(fromTime).Seconds())
	distanceInMinutes := math.Round(distanceInSeconds / 60)

	if distanceInMinutes <= 1 {
		if !showLessThanAMinute {
			if distanceInMinutes == 0 {
				return "less than a minute"
			}
			return "1 minute"
		} else {
			switch {
			case distanceInSeconds < 5:
				return fmt.Sprintf("less than 5 seconds (%.0fs)", distanceInSeconds)
			case distanceInSeconds < 10:
				return fmt.Sprintf("less than 10 seconds (%.0fs)", distanceInSeconds)
			case distanceInSeconds < 20:
				return fmt.Sprintf("less than 20 seconds (%.0fs)", distanceInSeconds)
			case distanceInSeconds < 40:
				return fmt.Sprintf("about half a minute (%.0fs)", distanceInSeconds)
			case distanceInSeconds < 60:
				return "less than a minute"
			default:
				return "1 minute"
			}
		}
	}
	if distanceInMinutes < 45 {
		return fmt.Sprintf("%.0f minutes", distanceInMinutes)
	}
	if distanceInMinutes < 90 {
		return "about 1 hour"
	}
	if distanceInMinutes < 1440 {
		return fmt.Sprintf("about %.0f hours", math.Round(distanceInMinutes/60))
	}
	if distanceInMinutes < 2880 {
		return "1 day"
	}
	if distanceInMinutes < 43200 {
		return fmt.Sprintf("about %.0f days", math.Round(distanceInMinutes/1440))
	}
	if distanceInMinutes < 86400 {
		return "about 1 month"
	}
	if distanceInMinutes < 525600 {
		return fmt.Sprintf("%.0f months", math.Round(distanceInMinutes/43200))
	}
	if distanceInMinutes < 1051199 {
		return "about 1 year"
	}
	return fmt.Sprintf("over %.0f years", math.Round(distanceInMinutes/525600))
}

func TempDirName() string {
	timestamp := time.Now().UnixNano()
	timeStamp2 := TimeStampToString()
	fName := Md5String(fmt.Sprintf("%v%v", timestamp, timeStamp2))
	return fmt.Sprintf("%v/%v", TEMPDIR(), fName)
}
func Base64Encode(input string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(input))
	return encoded
}

func Strtotime(datetime string) int64 {
	layout := "2006-01-02 15:04:05"
	location, _ := time.LoadLocation("Local")
	parsedTime, err := time.ParseInLocation(layout, datetime, location)
	if err != nil {
		return 0
	}
	return parsedTime.Unix()
}

func TEMPDIR() string {
	SysTmpDir := sockets.GET_INFO_STR("SysTmpDir")
	if SysTmpDir == "!nil" {
		SysTmpDir = ""
	}
	if len(SysTmpDir) < 4 {
		CreateDir("/home/artica/tmp")
		return "/home/artica/tmp"
	}
	if SysTmpDir == "/tmp" {
		return os.TempDir()
	}
	CreateDir(SysTmpDir)
	return SysTmpDir
}
func ExtractHostPort(input string) (hostname, port string, err error) {

	if strings.Contains(input, "http:") {
		if !strings.Contains(input, "://") {
			input = strings.ReplaceAll(input, "http:/", "http://")
		}
	}

	defaultPorts := map[string]string{
		"http":  "80",
		"https": "443",
		"ftp":   "21",
		"ldap":  "389",
		"ldaps": "636",
		"ssh":   "22",
		"sftp":  "22",
	}
	normalizedInput := input
	if !strings.Contains(normalizedInput, "://") {
		normalizedInput = "dummy://" + normalizedInput
	}

	u, err := url.Parse(normalizedInput)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse URL: %v", err)
	}
	hostname = u.Hostname()
	if hostname == "" {
		return "", "", fmt.Errorf("no hostname found in %s", input)
	}

	port = u.Port()
	if port == "" {
		scheme := strings.ToLower(u.Scheme)
		if scheme == "dummy" {
			if !strings.Contains(input, ":") {
				return "", "", fmt.Errorf("no port specified in scheme-less input %s", input)
			}
		} else if defaultPort, ok := defaultPorts[scheme]; ok {
			port = defaultPort
		} else {
			return "", "", fmt.Errorf("no port specified and unknown scheme %s in %s", scheme, input)
		}
	}
	return hostname, port, nil
}
func GetReleaseCodename() (string, error) {

	lsbRelease := FindProgram("lsb_release")
	cmd := exec.Command(lsbRelease, "-cs")

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("lsb_release failed: %v, stderr: %s", exitErr, stderr.String())
		}
		return "", fmt.Errorf("failed to execute lsb_release: %v", err)
	}

	codename := strings.TrimSpace(stdout.String())
	if codename == "" {
		return "", fmt.Errorf("no codename found in lsb_release output")
	}
	tb := strings.Split(codename, "\n")
	for _, line := range tb {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "modules are available") {
			continue
		}
		return line, nil
	}

	return "", fmt.Errorf("cannot found code release")
}

func ExtractURLComponents(rawURL string) ParseURL {

	if strings.Contains(rawURL, "http:") {
		if !strings.Contains(rawURL, "://") {
			rawURL = strings.ReplaceAll(rawURL, "http:/", "http://")
		}
	}

	parsedURL, err := url.Parse(rawURL)
	var u ParseURL
	if err != nil {
		return u
	}

	u.Protocol = parsedURL.Scheme
	u.Hostname = parsedURL.Hostname()

	u.Port = StrToInt(parsedURL.Port())
	u.Path = parsedURL.Path
	u.Query = parsedURL.RawQuery
	if u.Port == 0 {
		if u.Protocol == "https" {
			u.Port = 443
		}
		if u.Protocol == "http" {
			u.Port = 80
		}
		if u.Protocol == "ftp" {
			u.Port = 21
		}
		if u.Protocol == "ftps" {
			u.Port = 990
		}
	}

	return u
}

func TimeStampToString() string {
	return Int64ToString(TimeStamp())
}
func TruncateFile(filepath string) error {
	truncate := FindProgram("truncate")
	cmd := ""
	if len(truncate) < 4 {
		cat := FindProgram("cat")
		cmd = fmt.Sprintf("%v /dev/null > %v", cat, filepath)
	}
	cmd = fmt.Sprintf("%v -s 0 %v", truncate, filepath)
	err, out := ExecuteShell(cmd)
	if err != nil {
		return fmt.Errorf("%v %v", cmd, out)
	}
	return nil
}

func TimeStamp() int64 {
	location, _ := time.LoadLocation("Local")
	currentTime := time.Now().In(location)
	return currentTime.Unix()
}
func hourToHuman(xtime int64) string {
	// Convert the timestamp to a time.Time object
	t := time.Unix(xtime, 0)
	hour := t.Hour()
	min := t.Minute()
	sec := t.Second()

	// Handle special cases for midnight and midday
	if hour == 0 && min == 0 && sec == 0 {
		return "{midnight}"
	}
	if hour == 12 && min == 0 && sec == 0 {
		return "{midday}"
	}

	// Case for seconds not being zero
	if sec != 0 {
		if hour == 0 {
			return fmt.Sprintf("{midnight} %02d:%02d", min, sec)
		}
		if hour == 12 {
			return fmt.Sprintf("{midday} %02d:%02d", min, sec)
		}
		return fmt.Sprintf("%02d:%02d:%02d", hour, min, sec)
	}

	// Case for minutes being zero and seconds being zero
	if min == 0 {
		return fmt.Sprintf("%02dh", hour)
	}

	// Case for minutes not being zero and seconds being zero
	if min != 0 {
		if hour == 0 {
			return fmt.Sprintf("{midnight} %02dmn", min)
		}
		if hour == 12 {
			return fmt.Sprintf("{midday} %02dmn", min)
		}
		return fmt.Sprintf("%02dh %02dmn", hour, min)
	}

	return ""
}
func TimeToHumanDate(xtime int64, showTime bool) string {
	if xtime <= 0 {
		return "-"
	}

	t := time.Unix(xtime, 0)
	now := time.Now()
	yesterday := now.AddDate(0, 0, -1)

	if showTime {
		if t.Format("2006-01-02") == now.Format("2006-01-02") {
			return hourToHuman(xtime)
		}
		if t.Format("2006-01-02") == yesterday.Format("2006-01-02") {
			return "{yesterday} " + hourToHuman(xtime)
		}
	}

	dateFormat := "{Monday} {January} 02"
	if t.Year() != now.Year() {
		dateFormat = "2006 {Monday} {January} 02"
	}

	dateT := t.Format(dateFormat)

	if showTime {
		dateT = dateT + " " + hourToHuman(xtime)
	}
	return dateT
}

func TimeStampToDateStr(timestamp int64) string {
	t := time.Unix(timestamp, 0)
	return t.Format("2006-01-02 15:04:05")

}
func TimeStampToDateStrUTC(timestamp int64) string {
	t := time.Unix(timestamp, 0).UTC()
	return t.Format("2006-01-02 15:04:05")

}
func DateStrToTimeStamp(strDate string) int64 {
	layout := "2006-01-02 15:04:05"
	if strings.Contains(strDate, "T") {
		return timestrZToInt(strDate)
	}

	location, _ := time.LoadLocation("Local")
	t, err := time.ParseInLocation(layout, strDate, location)
	if err != nil {
		return 0
	}

	return t.Unix()

}
func timestrZToInt(strDate string) int64 {
	layout := time.RFC3339

	location, _ := time.LoadLocation("Local")
	t, err := time.ParseInLocation(layout, strDate, location)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func StringToFloat(sval string) float64 {
	f, err := strconv.ParseFloat(sval, 64)
	if err != nil {
		return 0
	}
	return f
}
func EtcEnvironment(Key string, value string) bool {

	var NewLine []string
	file, err := os.Open("/etc/environment")
	if err != nil {
		log.Error().Msg(fmt.Sprintf("etc_environment(): Error opening file: %v", err.Error()))
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if RegexFind(regexp.MustCompile(fmt.Sprintf("^LC_ALL", Key)), line) {
			continue
		}
		if RegexFind(regexp.MustCompile(fmt.Sprintf("^%v", Key)), line) {
			continue
		}

		NewLine = append(NewLine, line)

		if err := scanner.Err(); err != nil {
			log.Error().Msg(fmt.Sprintf("etc_environment() Error reading file: %v", err.Error()))
			return false
		}
	}

	if len(value) > 0 {
		NewLine = append(NewLine, fmt.Sprintf("%v=%v\n", Key, value))
	}

	AllFiles := []string{"/etc/wgetrc", "/root/.wgetrc", "/etc/profile.local", "/etc/environment"}

	for _, zfilepath := range AllFiles {
		_ = FilePutContents(zfilepath, strings.Join(NewLine, "\n"))
	}

	return true
}

func IsKVMSystem() int64 {

	fileInfo, err := os.Stat("/dev/kvm")
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		return 0
	}

	mode := fileInfo.Mode()
	if mode.IsRegular() && mode.Perm()&0400 != 0 && mode.Perm()&0200 != 0 {
		return 1
	}
	return 0
}
func Chmod04755(filepath string) error {
	// The permission mode is represented as an os.FileMode.
	// 0o4755 is the octal literal for the desired permissions.
	// In Go, octal literals start with 0o (or just 0 in older Go versions,
	// but 0o is clearer and preferred).
	mode := os.FileMode(0o4755)
	err := os.Chmod(filepath, mode)
	if err != nil {
		return fmt.Errorf("failed to set permissions for '%s': %w", filepath, err)
	}
	return nil
}

func CopyFile(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("%v stat src: %w", GetCalleRuntime(), err)
	}
	if !srcInfo.Mode().IsRegular() {
		return fmt.Errorf("%v not a regular file: %s", GetCalleRuntime(), src)
	}

	// Extract atime/mtime with ns precision from Stat_t
	atime, mtime := extractTimes(srcInfo)

	// Open files
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("%v open src: %w", GetCalleRuntime(), err)
	}
	defer func(in *os.File) {
		_ = in.Close()
	}(in)

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode().Perm())
	if err != nil {
		return fmt.Errorf("%v open dst: %w", GetCalleRuntime(), err)
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("%v copy: %w", GetCalleRuntime(), err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("%v sync: %w", GetCalleRuntime(), err)
	}
	if err := os.Chmod(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("%v chmod: %w", GetCalleRuntime(), err)
	}
	if err := os.Chtimes(dst, atime, mtime); err != nil {
		return fmt.Errorf("%v chtimes: %w", GetCalleRuntime(), err)
	}

	return nil
}
func extractTimes(fi os.FileInfo) (time.Time, time.Time) {
	// Best effort: read atime/mtime from Stat_t (Linux exposes Atim/Mtim)
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		at := time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec))
		mt := time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec))
		return at, mt
	}
	// Fallback: preserve mtime exactly, use it for atime too
	return fi.ModTime(), fi.ModTime()
}
func ListDirectories(path string) []string {
	// ne renvoit pas le chemin complet
	var directories []string

	dir, err := os.Open(path)
	if err != nil {
		return directories
	}
	defer dir.Close()

	// Read directory entries
	entries, err := dir.Readdir(-1)
	if err != nil {
		return directories
	}

	// Filter directories
	for _, entry := range entries {
		if entry.IsDir() {
			directories = append(directories, entry.Name())
		}
	}

	return directories
}
func MemoryPercentage(percentage float64) int64 {
	var info unix.Sysinfo_t
	err := unix.Sysinfo(&info)
	if err != nil {
		return 0
	}
	totalRAM := int64(info.Totalram) * int64(info.Unit)
	percentageRAM := totalRAM * int64(percentage) / 100
	percentageRAMMB := percentageRAM / (1024 * 1024)
	return percentageRAMMB
}
func GetStackSizeLimit() int64 {
	var rlim unix.Rlimit

	err := unix.Getrlimit(unix.RLIMIT_STACK, &rlim)
	if err != nil {
		fmt.Printf("Error retrieving stack size limit: %v\n", err)
		return 0
	}

	stackSizeMB := rlim.Cur / (1024 * 1024)
	return int64(stackSizeMB)
}

type FileInfoLinux struct {
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	ModTime    time.Time `json:"mod_time"`
	CreateTime time.Time `json:"create_time"`
	IsDir      bool      `json:"is_dir"`
}

// ListFilesByCreateTime lists files in a directory, sorted by creation time (descending).
// Linux-specific: Uses syscall.Stat_t to get creation time.
func DirectoryScanByModTime(dirPath string) []FileInfoLinux {
	// Validate directory
	dir, err := os.Open(dirPath)
	if err != nil {
		return []FileInfoLinux{}
	}
	defer func(dir *os.File) {
		_ = dir.Close()
	}(dir)

	// Check if it's a directory
	dirInfo, err := dir.Stat()
	if err != nil {
		return []FileInfoLinux{}
	}
	if !dirInfo.IsDir() {
		return []FileInfoLinux{}
	}

	// Read directory contents
	entries, err := dir.Readdir(-1)
	if err != nil {
		return []FileInfoLinux{}
	}

	// Collect file information
	var files []FileInfoLinux
	for _, entry := range entries {
		// Get syscall.Stat_t for creation time
		var createTime time.Time
		if sysInfo, ok := entry.Sys().(*syscall.Stat_t); ok {
			// Convert Ctim (creation time) to time.Time
			sec := sysInfo.Ctim.Sec
			nsec := sysInfo.Ctim.Nsec
			createTime = time.Unix(sec, nsec)
		} else {
			// Fallback to zero time if syscall data is unavailable
			createTime = time.Time{}
		}

		files = append(files, FileInfoLinux{
			Name:       entry.Name(),
			Size:       entry.Size(),
			ModTime:    entry.ModTime(),
			CreateTime: createTime,
			IsDir:      entry.IsDir(),
		})
	}

	// Sort by creation time (descending)
	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime.After(files[j].ModTime)
	})

	return files
}

func DirectoryScan(DirectoryPath string) []string {
	// Attention ne renvoi pas le chemin complet, Retourne uniquement les fichiers.
	var f []string

	if !IsDirDirectory(DirectoryPath) {
		return f
	}

	files, err := os.ReadDir(DirectoryPath)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("Error while scanning the directory %v %v", DirectoryPath, err.Error()))
		return f
	}

	for _, file := range files {
		if file.Name() == "." {
			continue
		}
		if file.Name() == ".." {
			continue
		}
		if file.IsDir() {
			continue
		}

		f = append(f, file.Name())
	}
	return f
}
func DirectoryScanOrdered(DirectoryPath string) []string {
	// Attention ne renvoi pas le chemin complet, Retourne uniquement les fichiers.
	var f []string
	type FileInfo struct {
		Name    string
		ModTime time.Time
	}
	var fileInfos []FileInfo
	if !IsDirDirectory(DirectoryPath) {
		return f
	}

	files, err := os.ReadDir(DirectoryPath)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("Error while scanning the directory %v %v", DirectoryPath, err.Error()))
		return f
	}

	for _, file := range files {
		if file.Name() == "." {
			continue
		}
		if file.Name() == ".." {
			continue
		}
		if file.IsDir() {
			continue
		}
		filePath := fmt.Sprintf("%v/%v", DirectoryPath, file.Name())
		info, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		fileInfos = append(fileInfos, FileInfo{
			Name:    file.Name(),
			ModTime: info.ModTime(),
		})
	}

	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].ModTime.After(fileInfos[j].ModTime)
	})

	for _, ffname := range fileInfos {
		f = append(f, ffname.Name)
	}

	return f
}

func IsCitrixXenHost() int64 {

	if FileExists("/etc/artica-postfix/XENSERVER_NOHOST") {
		DeleteFile("/etc/artica-postfix/XENSERVER_HOST")
		DeleteFile("/etc/artica-postfix/XENSERVER_NOHOST")
	}
	if FileExists("/etc/artica-postfix/XENSERVER_HOST") {
		xtime := FileTime("/etc/artica-postfix/XENSERVER_HOST")
		if xtime > 120 {
			DeleteFile("/etc/artica-postfix/XENSERVER_HOST")
		}
	}

	if FileExists("/etc/artica-postfix/XENSERVER_HOST") {
		data := FileGetContents("/etc/artica-postfix/XENSERVER_HOST")
		return StrToInt64(data)
	}

	if FileExists("/etc/artica-postfix/dmidecode-type-1.cache") {
		xtime := FileTime("/etc/artica-postfix/dmidecode-type-1.cache")
		if xtime > 480 {
			DeleteFile("/etc/artica-postfix/dmidecode-type-1.cache")
		}
	}
	var cacheData string
	if FileExists("/etc/artica-postfix/dmidecode-type-1.cache") {
		cacheData = FileGetContents("/etc/artica-postfix/dmidecode-type-1.cache")
	} else {
		dmidecode := FindProgram("dmidecode")
		if !FileExists(dmidecode) {
			return 0
		}
		_, cacheData := ExecuteShell(fmt.Sprintf("%v --type 1", dmidecode))

		_ = FilePutContents("/etc/artica-postfix/dmidecode-type-1.cache", cacheData)

	}
	results := strings.Split(cacheData, "\n")
	for _, line := range results {
		if matched, _ := regexp.MatchString("Manufacturer: Xen", line); matched {
			_ = FilePutContents("/etc/artica-postfix/XENSERVER_HOST", "1")
			return 1
		}

		if matched, _ := regexp.MatchString("Xen", line); matched {
			_ = FilePutContents("/etc/artica-postfix/XENSERVER_HOST", "1")
			return 1
		}
	}

	_ = FilePutContents("/etc/artica-postfix/XENSERVER_HOST", "0")
	return 0
}
func CreateSymlink(target, link string) error {

	if _, err := os.Lstat(link); err == nil {
		if err := os.Remove(link); err != nil {
			return fmt.Errorf("failed to remove existing link: %w", err)
		}
	}

	if err := os.Symlink(target, link); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}
	return nil
}
func BytesToMiB(bytes uint64) uint64 {
	const bytesPerMiB = 1024 * 1024
	return bytes / bytesPerMiB
}
func FindPIDByUDPPort(address string, port int) int {
	lsofbin := FindProgram("lsof")
	cmd := fmt.Sprintf("%v -i udp@%v:%d", lsofbin, address, port)

	err, output := ExecuteShell(cmd)
	if err != nil {
		log.Debug().Msgf("%v %v %v %v", GetCalleRuntime(), cmd, output, err.Error())
		return 0
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 1 {
		fields := strings.Fields(lines[1])
		if len(fields) > 1 {
			return StrToInt(fields[1])
		}
	}

	return 0
}

func DirFilesFilter(baseDir string, pattern string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(baseDir, "*"+pattern))
	if err != nil {
		return nil, err
	}
	return matches, nil
}
func IsChattrPlusI(filePath string) bool {
	f, err := os.OpenFile(filePath, os.O_WRONLY, 0644)
	if err != nil {
		if os.IsPermission(err) {
			return true
		}
		return false
	}
	_ = f.Close()
	return false
}
func AnonymFileSource(inputFile string) error {
	outputFile := fmt.Sprintf("%v.annonym", inputFile)
	err := AnonymFile(inputFile, outputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	_ = CopyFile(outputFile, inputFile)
	DeleteFile(outputFile)
	return nil
}

func AnonymFile(inputFile string, outputFile string) error {

	if IsLink(inputFile) {
		inputFile = ReadLink(inputFile)
	}

	in, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer func(in *os.File) {
		err := in.Close()
		if err != nil {

		}
	}(in)

	out, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer func(out *os.File) {
		err := out.Close()
		if err != nil {

		}
	}(out)

	scanner := bufio.NewScanner(in)
	writer := bufio.NewWriter(out)

	for scanner.Scan() {
		line := scanner.Text()
		newLine := replaceIPsAndMacs(line)
		_, _ = writer.WriteString(newLine + "\n")
	}
	_ = writer.Flush()

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading input: %v", err)
	}

	return nil
}
func isPrivateIP(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local
	}

	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
func replaceIPsAndMacs(line string) string {
	ipRegex := `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`
	ipRe := regexp.MustCompile(ipRegex)

	macRegex := `\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b`
	macRe := regexp.MustCompile(macRegex)

	// Replace IPs
	line = ipRe.ReplaceAllStringFunc(line, func(ipStr string) string {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return ipStr // ignore invalid
		}
		if isPrivateIP(ip) {
			return "1.2.3.4"
		}
		return ipStr
	})

	// Replace MACs
	line = macRe.ReplaceAllString(line, "00:00:00:00:00:00")

	return line
}
func RunModeProbe(driver string) error {
	if IsModulesLoaded(driver) {
		return nil
	}
	modprobePath := FindProgram("modprobe")
	cmd := exec.Command(modprobePath, driver)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v modprobe %v failed: %v", GetCalleRuntime(), driver, err)
	}
	return nil
}
func RunDepmod() error {
	modprobePath := FindProgram("depmod")
	cmd := exec.Command(modprobePath, "-a")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v depmod -a failed: %v", GetCalleRuntime(), err)
	}
	return nil
}
func RunModeProbeRM(driver string) error {
	if !IsModulesLoaded(driver) {
		return nil
	}
	modprobePath := FindProgram("modprobe")
	cmd := exec.Command(modprobePath, "-r", driver)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v modprobe %v failed: %v", GetCalleRuntime(), driver, err)
	}
	return nil
}
func DirFiles(dir, pattern string) map[string]struct{} {
	files := make(map[string]struct{})
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasPrefix(info.Name(), pattern) {
			files[info.Name()] = struct{}{}
		}
		return nil
	})
	if err != nil {
		log.Error().Msgf("%v Failed to read directory %s: %v", GetCalleRuntime(), dir, err)
	}
	return files
}
func GetPIDFromLocalPort(ip string, port int) int {
	hexPort := fmt.Sprintf("%04X", port)
	hexIP := func(ip net.IP) string {
		return fmt.Sprintf("%02X%02X%02X%02X", ip[3], ip[2], ip[1], ip[0])
	}

	target := hexIP(net.ParseIP(ip).To4()) + ":" + hexPort

	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		log.Error().Msgf("%v %v", GetCalleRuntime(), err.Error())
		return 0
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	var inode string
	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 10 && fields[1] == target {
			inode = fields[9]
			break
		}
	}
	if inode == "" {
		return 0
	}

	// search /proc/*/fd/ for the inode
	procDirs, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		log.Error().Msgf("%v %v", GetCalleRuntime(), err.Error())
		return 0
	}
	for _, fd := range procDirs {
		link, err := os.Readlink(fd)
		if err == nil && strings.Contains(link, "socket:["+inode+"]") {
			parts := strings.Split(fd, "/")
			if len(parts) >= 3 {
				return StrToInt(parts[2])
			}
		}
	}
	return 0
}
func UpdateInitRamFSKernel() (error, string) {
	masterBin := FindProgram("update-initramfs")
	if !FileExists(masterBin) {
		return fmt.Errorf("update-initramfs not found"), ""
	}
	Kernel := KernelVersion()
	Chmod(masterBin, 0755)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, masterBin, "-u", "-k", Kernel)
	cmd.Env = append(cmd.Env, ExecEnv()...)
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("timeout update-initramfs -u -k all took too long"), string(output)
	}
	if err != nil {
		return fmt.Errorf("update-initramfs -u -k all failed: %w", err), string(output)
	}
	return nil, string(output)
}
func UpdateInitRamFS() (error, string) {
	masterBin := FindProgram("update-initramfs")
	if !FileExists(masterBin) {
		return fmt.Errorf("update-initramfs not found"), ""
	}
	Chmod(masterBin, 0755)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, masterBin, "-u", "-k", "all")
	cmd.Env = append(cmd.Env, ExecEnv()...)
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("timeout update-initramfs -u -k all took too long"), string(output)
	}
	if err != nil {
		return fmt.Errorf("update-initramfs -u -k all failed: %w", err), string(output)
	}
	return nil, string(output)
}

func FindProgram(pname string) string {

	value := CacheMem.GetBinCache(pname)
	if len(value) > 1 {
		if FileExists(value) {
			return value
		}
	}

	PossibleDirs := []string{
		"/usr/bin", "/usr/sbin", "/usr/local/bin",
		"/usr/local/sbin", "/bin", "/sbin", "/usr/kerberos/bin", "/usr/libexec", "/usr/lib/openldap",
	}

	for _, dir := range PossibleDirs {
		tpath := fmt.Sprintf("%v/%v", dir, pname)
		if fileExists(tpath) {
			CacheMem.SetBin(pname, tpath)
			return tpath
		}

	}
	return ""
}
func IsModulesLoaded(modname string) bool {
	lsmod := FindProgram("lsmod")
	err, out := ExecuteShell(lsmod)
	if err != nil {
		log.Error().Msgf("%v %v %>v", GetCalleRuntime(), err.Error(), out)
	}
	re := regexp.MustCompile(`^` + modname + `\s+[0-9]+`)
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if RegexFind(re, line) {
			return true
		}
	}
	return false
}

func ShellEscapeChars(str string) string {
	str = strings.ReplaceAll(str, ` `, `\ `)
	str = strings.ReplaceAll(str, `$`, `\$`)
	str = strings.ReplaceAll(str, `&`, `\&`)
	str = strings.ReplaceAll(str, `?`, `\?`)
	str = strings.ReplaceAll(str, `#`, `\#`)
	str = strings.ReplaceAll(str, `[`, `\[`)
	str = strings.ReplaceAll(str, `]`, `\]`)
	str = strings.ReplaceAll(str, `{`, `\{`)
	str = strings.ReplaceAll(str, `}`, `\}`)
	str = strings.ReplaceAll(str, `'`, `\'`)
	str = strings.ReplaceAll(str, `"`, `\"`)
	str = strings.ReplaceAll(str, `(`, `\(`)
	str = strings.ReplaceAll(str, `)`, `\)`)
	str = strings.ReplaceAll(str, `<`, `\<`)
	str = strings.ReplaceAll(str, `>`, `\>`)
	str = strings.ReplaceAll(str, `!`, `\!`)
	str = strings.ReplaceAll(str, `+`, `\+`)
	str = strings.ReplaceAll(str, `;`, `\;`)
	str = strings.ReplaceAll(str, `|`, `\|`)
	str = strings.ReplaceAll(str, `%`, `\%`)
	return str
}
func FormatDuration(d time.Duration) string {
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	seconds := d / time.Second
	var tex []string
	Months := 0
	xDays := StrToInt64(fmt.Sprintf("%d", days))
	if xDays > 30 {
		Months = int(xDays) / 30
		DaysMonths := Months * 30
		xDays = xDays - int64(DaysMonths)
	}
	if Months > 0 {
		if Months == 1 {
			tex = append(tex, "1 month")
		} else {
			tex = append(tex, fmt.Sprintf("%d months", Months))
		}
	}

	if xDays > 0 {
		if xDays == 1 {
			tex = append(tex, "1 day")
		} else {
			tex = append(tex, fmt.Sprintf("%d days", xDays))
		}
	}
	if hours > 0 {
		if hours == 1 {
			tex = append(tex, "1 hour")
		} else {
			tex = append(tex, fmt.Sprintf("%d hours", hours))
		}
	}
	if minutes > 0 {
		if minutes == 1 {
			tex = append(tex, "1 minute")
		} else {
			tex = append(tex, fmt.Sprintf("%d minutes", minutes))
		}
	}

	if len(tex) == 0 {
		if seconds == 1 {
			tex = append(tex, "1 second")
		} else {
			tex = append(tex, fmt.Sprintf("%d seconds", seconds))
		}
	}

	return strings.Join(tex, ", ")
}

func ProcessMaxOpenFiles(pid int) int64 {
	limitsFile := fmt.Sprintf("/proc/%d/limits", pid)
	file, err := os.Open(limitsFile)
	if err != nil {
		return int64(0)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Max open files") {
			fields := strings.Fields(line)
			maxOpenFiles, err := strconv.Atoi(fields[3]) // The soft limit
			if err != nil {
				_ = file.Close()
				return 0
			}
			_ = file.Close()
			return int64(maxOpenFiles)
		}
	}
	_ = file.Close()
	return int64(0)
}
func ProccessCurOpenFiles(pid int) int64 {

	Dir := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := os.ReadDir(Dir)
	if err != nil {
		return int64(0)
	}
	return int64(len(fds))
}
func GetDomainFromUri(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	return parsedURL.Hostname()
}

func PrintStructFieldsAndValues(v interface{}) {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		fmt.Println("Not a struct!")
		return
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		value := val.Field(i)
		fmt.Printf("Key: %s, Value: %v\n", field.Name, value.Interface())
	}
}
func GetCalleRuntimeAll() string {
	var str []string
	if pc, file, line, ok := runtime.Caller(0); ok {
		file = file[strings.LastIndex(file, "/")+1:]
		funcName := runtime.FuncForPC(pc).Name()
		funcName = strings.ReplaceAll(funcName, "github.com/dtouzeau/articarest/", "")
		str = append(str, fmt.Sprintf("%s[%s:%d]", file, funcName, line))
	}
	return strings.Join(str, "\n")
}
func LocalFQDN() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "unknown"
	}

	addrs, err := net.LookupHost(hostname)
	if err != nil || len(addrs) == 0 {
		// No DNS record, return raw hostname
		return hostname
	}

	// Try reverse lookup to get full name
	names, err := net.LookupAddr(addrs[0])
	if err == nil && len(names) > 0 {
		fqdn := strings.TrimSuffix(names[0], ".")
		return fqdn
	}

	// Fallback to simple hostname if reverse lookup fails
	return hostname
}

func GetCalleRuntime() string {
	if pc, file, line, ok := runtime.Caller(1); ok {
		file = file[strings.LastIndex(file, "/")+1:]
		funcName := runtime.FuncForPC(pc).Name()
		funcName = strings.ReplaceAll(funcName, "github.com/dtouzeau/articarest/", "")
		funcName = strings.ReplaceAll(funcName, "articarest/dnsdist/", "")
		return fmt.Sprintf("%s[%s:%d]", file, funcName, line)
	}
	return ""
}
func CropString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	for i := length; i > 0; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i]
		}
	}
	return ""
}
func ExtractMainDomain(fqdn string) string {
	parts := strings.Split(fqdn, ".")
	if len(parts) >= 2 {
		domain := parts[len(parts)-2] + "." + parts[len(parts)-1]
		return domain
	}
	return fqdn // Return the original FQDN if it doesn't conform to expected structure
}
func FileCountLines(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	const bufSize = 32 * 1024 // 32 KB buffer (tweak as needed)
	buf := make([]byte, bufSize)
	var count int64

	for {
		n, err := f.Read(buf)
		if n > 0 {
			for _, b := range buf[:n] {
				if b == '\n' {
					count++
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}
	}
	return count, nil
}

func IsAnFQDN(fqdn string) bool {
	if !strings.Contains(fqdn, ".") {
		return false
	}
	parts := strings.Split(fqdn, ".")
	if len(parts[1]) < 2 {
		return false
	}
	return true
}

func MD5Dir(rootDir string) string {
	hash := md5.New() // Initialize a single MD5 hash for all files

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(hash, file)
		return err // This could be nil or an actual error
	})

	if err != nil {
		return ""
	}

	// Convert the hash to a string format
	return fmt.Sprintf("%x", hash.Sum(nil))

}

func GetFuncLine() (string, int) {
	if pc, file, line, ok := runtime.Caller(1); ok {
		//get the file name
		file = file[strings.LastIndex(file, "/")+1:]

		//get the function name
		funcName := runtime.FuncForPC(pc).Name()
		// export the logger
		return funcName, line
	}
	return "", 0
}

func Serialize(array map[string]interface{}) ([]byte, error) {
	serialize, err := gophp.Serialize(array)
	if err != nil {
		return nil, err
	}
	return serialize, nil
}

func Serialize2(array map[int]map[string]interface{}) ([]byte, error) {
	serialize, err := gophp.Serialize(array)
	if err != nil {
		return nil, err
	}
	return serialize, nil
}

func Unserialize(content string) (map[string]interface{}, error) {

	unserialize, err := gophp.Unserialize([]byte(content))
	if err != nil {
		return nil, err
	}

	if _, ok := unserialize.(map[string]interface{}); ok {
		return unserialize.(map[string]interface{}), nil
	}
	return nil, errors.New(GetCalleRuntime() + ": invalid data")
}

func SerializeB64Encode(array map[string]interface{}) (string, error) {
	a, err := Serialize(array)
	if err != nil {
		return "", err
	}
	b := Base64Encode(string(a))
	return b, nil
}

func B64DecodeUnserialize(content string) (map[string]interface{}, error) {
	a := Base64Decode(content)
	b, err := Unserialize(a)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func StringIsUrl(urlString string) bool {
	urlString = Trim(strings.ToLower(urlString))
	if strings.HasPrefix(urlString, "http://") {
		return true
	}
	if strings.HasPrefix(urlString, "https://") {
		return true
	}
	if strings.HasPrefix(urlString, "ftp://") {
		return true
	}
	if strings.HasPrefix(urlString, "ftps://") {
		return true
	}
	return false
}

func ExtractHostnameFromURL(urlString string) string {
	if !StringIsUrl(urlString) {
		if strings.Contains(urlString, ":") {
			tb := strings.Split(urlString, ":")
			return tb[0]
		}
		return urlString
	}

	parsedUrl, err := url.Parse(urlString)
	if err != nil {
		return ""
	}
	return parsedUrl.Hostname()
}

func FileEndsWithLF(filename string) bool {
	file, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer file.Close()
	_, err = file.Seek(-1, io.SeekEnd)
	if err != nil {
		return false
	}
	buf := make([]byte, 1)
	_, err = file.Read(buf)
	if err != nil {
		return false
	}
	return buf[0] == '\n'
}

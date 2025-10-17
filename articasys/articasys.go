package articasys

import (
	"SqliteConns"
	"bytes"
	"crypto/md5"
	"database/sql"
	"fmt"
	"futils"
	"github.com/google/uuid"
	"github.com/jaypipes/ghw"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"math"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sockets"
	"sort"
	"strconv"
	"strings"
	"time"
)

type MemoryInfo struct {
	TotalMB     uint64  `json:"total_mb"`
	UsedMB      uint64  `json:"used_mb"`
	UsedPercent float64 `json:"used_percent"`
	FreeMB      uint64  `json:"free_mb"`
}

var cpupercent float64

func CpuNumber() int {
	return runtime.NumCPU()
}

func MemoryMB() MemoryInfo {
	var v MemoryInfo
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return v
	}
	v.FreeMB = vmStat.Free / 1024 / 1024
	totalMB := vmStat.Total / 1024 / 1024
	usedMB := vmStat.Used / 1024 / 1024
	usedPercent := vmStat.UsedPercent

	v.TotalMB = totalMB
	v.UsedMB = usedMB
	v.UsedPercent = usedPercent
	return v
}

func TotalMemorymb() float64 {

	memory, err := mem.VirtualMemory()
	if err != nil {
		return 0
	}

	val := fmt.Sprintf("%.2f", float64(memory.Total)/(1024*1024))
	return StringToFloat(val)

}

func Getuuid() string {
	SYSTEMID := sockets.GET_INFO_STR("SYSTEMID")
	if len(SYSTEMID) == 0 {
		SYSTEMID = uuid.New().String()
		sockets.SET_INFO_STR("SYSTEMID", SYSTEMID)
	}
	return SYSTEMID
}

func DistributionName() string {

	if is_file("/etc/SuSE-release") {
		content := file_get_contents("/etc/SuSE-release")
		return "openSUSE " + content
	}

	if is_file("/etc/lsb-release") {
		if !is_file("/etc/redhat-release") {
			content := strings.Split(file_get_contents("/etc/lsb-release"), "\n")
			var distri_provider, distri_ver, distri_name string
			for _, line := range content {
				if strings.HasPrefix(line, "DISTRIB_ID=") {
					tb := strings.Split(line, "=")
					distri_provider = tb[1]
				}
				if strings.HasPrefix(line, "DISTRIB_RELEASE=") {
					tb := strings.Split(line, "=")
					distri_ver = tb[1]
				}
				if strings.HasPrefix(line, "DISTRIB_CODENAME=") {
					tb := strings.Split(line, "=")
					distri_name = tb[1]
				}
			}
			return fmt.Sprintf("%v %v %v", distri_provider, distri_ver, distri_name)
		}
	}

	if is_file("/etc/debian_version") {
		content := strings.TrimSpace(file_get_contents("/etc/debian_version"))
		return "Debian " + content + " Gnu-linux"
	}

	if is_file("/etc/redhat-release") {
		content := strings.TrimSpace(file_get_contents("/etc/redhat-release"))
		return content
	}
	return ""

}
func DiskExists(devname string) bool {

	Disks := GetDisks()
	for _, disk := range Disks {
		disk = strings.ToLower(disk)
		if disk == strings.ToLower(devname) {
			return true
		}
	}
	return false

}

func GetDisks() []string {
	var data []string
	block, err := ghw.Block()
	if err != nil {
		log.Error().Msgf("%v error %v", futils.GetCalleRuntime(), err.Error())
		return data
	}
	for _, disk := range block.Disks {
		sroot := fmt.Sprintf("/dev/%v", disk.Name)
		_, err := os.Stat(sroot)
		if err != nil {
			continue
		}
		data = append(data, fmt.Sprintf("/dev/%v", disk.Name))

	}
	return data
}

func TotalMemoryBytes() uint64 {

	vmem, err := mem.VirtualMemory()
	if err != nil {
		return 0
	}
	return vmem.Total
}
func TotalMemoryPercent() float64 {
	memory, err := mem.VirtualMemory()
	if err != nil {
		return 0
	}
	val := fmt.Sprintf("%.2f", memory.UsedPercent)
	return StringToFloat(val)

}

func CpuPercent() float64 {
	ps, err := cpu.Percent(0, true)
	if err == nil && len(ps) > 0 {
		for _, v := range ps {
			cpupercent += v
		}
		cpupercent /= float64(len(ps))
	}
	//https://github.com/syyongx/php2go
	return round(cpupercent, 2)
}

func CurrentHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost.localdomain"
	}
	return hostname
}

func KernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}
	versionString := string(data)
	lines := strings.Split(versionString, " ")
	if len(lines) >= 3 {
		kernelVersion := lines[2]
		return kernelVersion
	}

	return ""
}
func LoadAvg5min() float64 {
	avg, err := load.Avg()
	if err != nil {
		log.Error().Msgf("%v Unable to get the current machine load: %v", futils.GetCalleRuntime(), err.Error())
		return 0
	}
	return avg.Load5
}

func StringToFloat(sval string) float64 {
	f, err := strconv.ParseFloat(sval, 64)
	if err != nil {
		return 0
	}
	return f
}

func InterfacesReport() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var report []string

	avg, err := load.Avg()
	if err == nil {
		report = append(report, fmt.Sprintf("Current Load: %v  %v (5Min) %v (15Mins)", avg.Load1, avg.Load5, avg.Load15))

	}

	report = append(report, "------ Your server Network:")

	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addresses {
			var ip net.IP

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil {
				continue
			}

			if strings.HasPrefix(ip.String(), "127.0.") {
				continue
			}

			report = append(report, fmt.Sprintf("\t%s - %s", iface.Name, ip))
		}
	}
	return strings.Join(report, "\n")
}
func round(value float64, precision int) float64 {
	p := math.Pow10(precision)
	return math.Trunc((value+0.5/p)*p) / p
}
func is_file(spath string) bool {
	if _, err := os.Stat(spath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}
func file_get_contents(filename string) string {
	if !is_file(filename) {
		return ""
	}
	tk, err := os.ReadFile(filename)
	if err != nil {
		return ""
	}
	tk = bytes.TrimSpace(tk)
	return string(tk)
}
func UpdateLastBoot() {
	// Step 1: Find and execute 'last reboot' command
	lastCmd := futils.FindProgram("last")

	cmd := exec.Command(lastCmd, "reboot")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Msgf("%v failed to execute '%s reboot': %v", futils.GetCalleRuntime(), lastCmd, err)
		return
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 {
		log.Warn().Msgf("%v No output from 'last reboot'", futils.GetCalleRuntime())
		return
	}
	sort.Strings(lines)
	re, err := regexp.Compile(`reboot\s+(.+?)\s+([0-9]+).*?\s+(.+?)-\s+([0-9:]+)\s+`)
	if err != nil {
		log.Error().Msgf("%v failed to compile regex: %v", futils.GetCalleRuntime(), err)
		return
	}

	rarray := make(map[int64]string)
	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) != 5 {
			continue
		}
		timeStr := matches[3]
		parsedTime, err := time.Parse("Mon Jan 2 15:04 2006", timeStr+" "+strconv.Itoa(time.Now().Year()))
		if err != nil {
			log.Warn().Msgf("%v Failed to parse time '%s' from [%v] %v", futils.GetCalleRuntime(), timeStr, line, err)
			continue
		}

		rarray[parsedTime.Unix()] = line
	}

	if len(rarray) == 0 {
		log.Debug().Msgf("%v No valid reboot entries found", futils.GetCalleRuntime())
		return
	}

	// Step 3: Process entries in reverse chronological order
	times := make([]int64, 0, len(rarray))
	for t := range rarray {
		times = append(times, t)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] > times[j] }) // Equivalent to PHP krsort

	var linze []string
	var cmds []string
	lastTime := int64(0)

	for _, t := range times {
		line := rarray[t]
		matches := re.FindStringSubmatch(line)
		if len(matches) != 5 {
			continue
		}

		action := matches[1]
		dateStr := time.Unix(t, 0).Format("2006-01-02 15:04:05")
		md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(action+strconv.FormatInt(t, 10)+dateStr)))

		// Compute DIFF (time difference from previous reboot)
		diff := int64(0)
		if lastTime > 0 {
			diff = lastTime
		}
		lastTime = t

		// Prepare SQL statements
		cmds = append(cmds, fmt.Sprintf("DELETE FROM last_boot WHERE zmd5='%s'", md5Hash))
		yline := fmt.Sprintf("('%s','%s','%s',%d,%d)", md5Hash, action, dateStr, t, diff)
		linze = append(linze, yline)
	}

	if len(linze) == 0 {
		log.Debug().Msgf("%v No reboot entries to insert", futils.GetCalleRuntime())
		return
	}

	db, err := SqliteConns.SysDBConnectRW()
	if err != nil {
		log.Error().Msgf("%v failed to connect to sysdb: %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	// Step 6: Execute DELETE queries
	for _, sqlStmt := range cmds {
		_, err := db.Exec(sqlStmt)
		if err != nil {
			log.Warn().Msgf("%v Failed to execute SQL %s: %v", futils.GetCalleRuntime(), sqlStmt, err)
			continue
		}
	}

	// Step 7: Insert new entries
	sqlStmt := "INSERT OR IGNORE INTO last_boot (zmd5, subject, zDate, ztime, ztime2) VALUES " + strings.Join(linze, ",")
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Error().Msgf("%v failed to execute INSERT SQL: %v", futils.GetCalleRuntime(), err)
	}
}

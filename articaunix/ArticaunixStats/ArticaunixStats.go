package ArticaunixStats

import (
	"bufio"
	"fmt"
	"futils"
	"os"
	"rrd"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/process"
)

func DelRRD(MonitName string) {
	DatabasePath := fmt.Sprintf("%v/PPPROCESS_%v.rrd", rrd.ArticaRRDBase, MonitName)
	futils.DeleteFile(DatabasePath)
}

func RunRRD(MonitName string, pid int) {

	if pid == 0 {
		return
	}

	rrdtool := futils.FindProgram("rrdtool")
	if len(rrdtool) < 3 {
		log.Debug().Msgf("%v rrdtool not found", futils.GetCalleRuntime())
	}
	DatabasePath := fmt.Sprintf("%v/PPPROCESS_%v.rrd", rrd.ArticaRRDBase, MonitName)

	err := createRRD(rrdtool, DatabasePath)
	if err != nil {
		return
	}
	averageCPU, totalMemory, Memlock, err := getAverageCPUAndTotalMemory(int32(pid))
	if err != nil {
		log.Debug().Msgf("%v Error getting process stats(%v): %v", futils.GetCalleRuntime(), MonitName, err)
		return
	}

	cmd := fmt.Sprintf("%v update %v %v", rrdtool, DatabasePath, fmt.Sprintf("N:%.2f:%.2f:%d", averageCPU, totalMemory, Memlock))
	err, out := futils.ExecuteShell(cmd)

	if err != nil {
		if strings.Contains(out, "lock RRD") || strings.Contains(out, "minimum one second step") {
			return
		}
		log.Debug().Msgf("%v error updating RRD [%v]: %v", futils.GetCalleRuntime(), cmd, out)
		return
	}

}

func getAverageCPUAndTotalMemory(ppid int32) (float64, float64, int64, error) {
	// Find the parent process
	parentProc, err := process.NewProcess(ppid)
	if err != nil {
		return 0, 0, 0, fmt.Errorf(" process.NewProcess(ppid) error finding parent process of %d: %v", ppid, err)
	}

	// Variables to store CPU and memory statistics
	var totalCPU float64
	var totalMemory uint64
	var processCount int

	// Get CPU and memory usage of the parent process
	cpuPercent, memInfo := getProcessStats(parentProc)
	Memlock, _ := getLockedMemoryForProcess(int(parentProc.Pid))

	totalCPU += cpuPercent
	totalMemory += memInfo.RSS
	processCount++

	// Get all child processes
	children, err := parentProc.Children()
	if err != nil {
		return totalCPU, float64(totalMemory) / (1024 * 1024), int64(Memlock), nil
	}

	// Iterate over child processes
	for _, child := range children {
		cpuPercent, memInfo := getProcessStats(child)
		totalCPU += cpuPercent
		totalMemory += memInfo.RSS
		sMemlock, _ := getLockedMemoryForProcess(int(parentProc.Pid))
		Memlock = Memlock + sMemlock
		processCount++
	}

	// Calculate the average CPU usage
	averageCPU := totalCPU / float64(processCount)

	// Convert memory usage to MB
	totalMemoryMB := float64(totalMemory) / (1024 * 1024)

	return averageCPU, totalMemoryMB, int64(Memlock), nil
}

func createRRD(rrdtool string, DatabasePath string) error {

	// Define the time interval (3 minutes) and the duration (1 year)
	step := 180               // 3 minutes in seconds
	year := 365 * 24 * 60 / 3 // 3-minute intervals for a year

	if futils.FileExists(DatabasePath) {
		return nil
	}
	// Command to create the RRD database

	cmd := []string{rrdtool, "create", DatabasePath,
		"--step", fmt.Sprintf("%d", step),
		"DS:cpu:GAUGE:600:0:100",
		"DS:memory:GAUGE:600:0:U",
		"DS:memlock:GAUGE:600:0:U",
		fmt.Sprintf("RRA:AVERAGE:0.5:1:%d", year)}

	err, out := futils.ExecuteShell(strings.Join(cmd, " "))

	if err != nil {
		log.Error().Msgf("%v error creating RRD: %v", futils.GetCalleRuntime(), out)
		return err
	}
	return nil
}

// Helper function to print CPU and memory usage of a process
func getProcessStats(proc *process.Process) (float64, *process.MemoryInfoStat) {
	// Get CPU usage
	cpuPercent, err := proc.CPUPercent()
	if err != nil {
		log.Printf("Error getting CPU usage for PID %d: %v", proc.Pid, err)
		cpuPercent = 0
	}

	// Get memory usage
	memInfo, err := proc.MemoryInfo()
	if err != nil {
		log.Printf("Error getting memory usage for PID %d: %v", proc.Pid, err)
		memInfo = &process.MemoryInfoStat{}
	}

	return cpuPercent, memInfo
}
func getLockedMemoryForProcess(pid int) (int, error) {
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	file, err := os.Open(statusFile)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmLck:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memlock, err := strconv.Atoi(fields[1])
				if err != nil {
					return 0, err
				}
				return memlock, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return 0, nil
}

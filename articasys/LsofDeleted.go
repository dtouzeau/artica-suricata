package articasys

import (
	"context"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// LsofEntry represents a parsed lsof output line
type LsofEntry struct {
	Command string
	PID     int
	TID     int
	User    string
	FD      string
	Type    string
	Device  string
	Size    int64
	Node    int64
	Name    string
	TTL     float64
}

// executeLsofWithTimeout runs lsof with a timeout and parses (deleted) entries
func executeLsofWithTimeout(timeout time.Duration) ([]LsofEntry, error) {
	bootTime, err := getSystemBootTime()
	if err != nil {
		return []LsofEntry{}, fmt.Errorf("failed to get system boot time: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/bin/sh", "-c", "/usr/bin/lsof | /usr/bin/grep deleted")
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("lsof command timed out after %v", timeout)
		}
		return nil, fmt.Errorf("failed to execute lsof: %v", err)
	}
	return parseLsofOutput(string(output), bootTime)
}

// parseLsofOutput parses the lsof output into a slice of LsofEntry
func parseLsofOutput(input string, bootTime time.Time) ([]LsofEntry, error) {
	var entries []LsofEntry
	lines := strings.Split(input, "\n")
	seen := make(map[string]struct{}) // Deduplicate entries

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "(deleted)") {
			continue
		}

		// Split line into fields, handling variable number of fields due to optional TID
		fields := strings.Fields(line)
		if len(fields) < 9 { // Minimum fields for TID + extra command name
			log.Warn().Msgf("Skipping malformed line (too few fields, need at least 9): %s", line)
			continue
		}

		entry := LsofEntry{}
		fieldIdx := 0

		// Command
		entry.Command = fields[fieldIdx]
		fieldIdx++

		// PID
		pid, err := strconv.Atoi(fields[fieldIdx])
		if err != nil {
			log.Warn().Msgf("Invalid PID in line: %s, error: %v", line, err)
			continue
		}
		entry.PID = pid
		fieldIdx++

		// Check if next field is TID (numeric)
		if tid, err := strconv.Atoi(fields[fieldIdx]); err == nil {
			entry.TID = tid
			fieldIdx++
			// Check for extra command name (common with threads)
			if fieldIdx < len(fields) && (strings.Contains(fields[fieldIdx], entry.Command) || strings.Contains(fields[fieldIdx], ":")) {
				fieldIdx++ // Skip extra command name or thread name (e.g., "in:imuxso")
			}
		} else {
			entry.TID = 0
		}

		// User
		if fieldIdx >= len(fields) {
			log.Warn().Msgf("Missing user field in line: %s", line)
			continue
		}
		entry.User = fields[fieldIdx]
		fieldIdx++

		// FD
		if fieldIdx >= len(fields) {
			log.Warn().Msgf("Missing FD field in line: %s", line)
			continue
		}
		entry.FD = fields[fieldIdx]
		fieldIdx++

		// Type
		if fieldIdx >= len(fields) {
			log.Warn().Msgf("Missing type field in line: %s", line)
			continue
		}
		entry.Type = fields[fieldIdx]
		fieldIdx++

		// Device
		if fieldIdx >= len(fields) {
			log.Warn().Msgf("Missing device field in line: %s", line)
			continue
		}
		entry.Device = fields[fieldIdx]
		fieldIdx++

		// Size
		if fieldIdx >= len(fields) {
			log.Warn().Msgf("Missing size field in line: %s", line)
			continue
		}
		if entry.Type == "CHR" {
			// For CHR type, size is often "0t0" or non-numeric, set to 0
			entry.Size = 0
		} else {
			size, err := strconv.ParseInt(fields[fieldIdx], 10, 64)
			if err != nil {
				log.Warn().Msgf("Invalid size in line: %s, setting size to 0, error: %v", line, err)
				entry.Size = 0
			} else {
				entry.Size = size
			}
		}
		fieldIdx++

		// Node
		if fieldIdx >= len(fields) {
			log.Warn().Msgf("Missing node field in line: %s", line)
			continue
		}
		node, err := strconv.ParseInt(fields[fieldIdx], 10, 64)
		if err != nil {
			log.Warn().Msgf("Invalid node in line: %s, error: %v", line, err)
			continue
		}
		entry.Node = node
		fieldIdx++

		// Name (rest of the line)
		if fieldIdx >= len(fields) {
			log.Warn().Msgf("Missing name field in line: %s", line)
			continue
		}
		entry.Name = strings.Join(fields[fieldIdx:], " ")

		// Deduplicate based on PID, FD, and Name
		key := fmt.Sprintf("%d:%s:%s", entry.PID, entry.FD, entry.Name)
		if _, exists := seen[key]; exists {
			log.Warn().Msgf("Skipping duplicate entry for PID %d, FD %s, Name %s", entry.PID, entry.FD, entry.Name)
			continue
		}
		seen[key] = struct{}{}

		// Calculate TTL
		ttl, err := getFDTTL(entry.PID, entry.FD, bootTime)
		if err != nil {
			log.Error().Msgf("%v TTL failed for PID %d, FD %s: %v", futils.GetCalleRuntime(), entry.PID, entry.FD, err)
			continue
		}
		entry.TTL = ttl

		entries = append(entries, entry)
	}

	return entries, nil
}

// CleanFDDeleted processes and closes file descriptors for deleted files
func CleanFDDeleted() {
	entries, err := executeLsofWithTimeout(10 * time.Second)
	if err != nil {
		log.Error().Msgf("%v Failed to execute lsof: %v", futils.GetCalleRuntime(), err)
		return
	}

	c := 0
	for i, entry := range entries {
		if entry.FD == "txt" || entry.FD == "1w" || entry.FD == "2w" {
			fmt.Printf("Skipping FD(%d) %s for PID %d (command: %s, file: %s)\n", i, entry.FD, entry.PID, entry.Command, entry.Name)
			continue
		}
		if entry.TTL > 240 {
			log.Debug().Msgf("%v Closing(%d) %v %v (%vmn) for PID %d (%s)", futils.GetCalleRuntime(), i, entry.FD, entry.Name, entry.TTL, entry.PID, entry.Command)
			err := attemptFDClose(entry.PID, entry.FD)
			if err != nil {
				log.Error().Msgf("%v Error closing FD %s for PID %d (%s): %v", futils.GetCalleRuntime(), entry.FD, entry.PID, entry.Command, err)
				// Fallback: Send SIGHUP
				if err := sendSighup(entry.PID); err != nil {
					log.Error().Msgf("%v Error sending SIGHUP to PID %d (%s): %v", futils.GetCalleRuntime(), entry.PID, entry.Command, err)
				} else {
					log.Info().Msgf("%v Sent SIGHUP to PID %d (%s) for FD %s", futils.GetCalleRuntime(), entry.PID, entry.Command, entry.FD)
				}
				continue
			}
			c++
		}
	}
	if c > 0 {
		log.Info().Msgf("%v %d deleted file descriptors closed", futils.GetCalleRuntime(), c)
	}
}

// attemptFDClose tries to close an FD via /proc filesystem
func attemptFDClose(pid int, fd string) error {
	// Extract numeric part of FD (e.g., "3r" -> "3", "0u" -> "0")
	fdNum := strings.TrimRight(fd, "rwtu")
	if _, err := strconv.Atoi(fdNum); err != nil {
		return fmt.Errorf("invalid FD format: %s", fd)
	}
	fdPath := filepath.Join("/proc", strconv.Itoa(pid), "fd", fdNum)

	if _, err := os.Stat(fdPath); os.IsNotExist(err) {
		return fmt.Errorf("FD %s for PID %d does not exist", fd, pid)
	}

	err := os.Remove(fdPath)
	if err != nil {
		return fmt.Errorf("failed to unlink FD %s for PID %d: %v", fd, pid, err)
	}

	return nil
}

// sendSighup sends SIGHUP to the process to encourage FD release
func sendSighup(pid int) error {
	err := syscall.Kill(pid, syscall.SIGHUP)
	if err != nil {
		return fmt.Errorf("failed to send SIGHUP to PID %d: %v", pid, err)
	}
	return nil
}

// getFDTTL returns the TTL (in minutes) of an FD based on /proc/<pid>/fd/<fd> mtime or process start time
func getFDTTL(pid int, fd string, bootTime time.Time) (float64, error) {
	// Extract numeric part of FD (e.g., "3r" -> "3", "0u" -> "0")
	fdNum := strings.TrimRight(fd, "rwtu")
	if _, err := strconv.Atoi(fdNum); err != nil {
		return 0, fmt.Errorf("invalid FD format: %s", fd)
	}

	// Try to get mtime of /proc/<pid>/fd/<fd>
	fdPath := filepath.Join("/proc", strconv.Itoa(pid), "fd", fdNum)
	fdInfo, err := os.Stat(fdPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("FD %s for PID %d does not exist", fd, pid)
		}
		return 0, fmt.Errorf("failed to stat FD %s for PID %d: %v", fd, pid, err)
	}

	// Get mtime of the FD
	fdMtime := fdInfo.ModTime()

	// Fallback: Get process start time from /proc/<pid>/stat
	procStatPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	procData, err := os.ReadFile(procStatPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc/%d/stat: %v", pid, err)
	}

	// Parse /proc/<pid>/stat to get start time (field 22 is starttime in ticks since boot)
	fields := strings.Fields(string(procData))
	if len(fields) < 22 {
		return 0, fmt.Errorf("invalid /proc/%d/stat format", pid)
	}
	startTicks, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid starttime in /proc/%d/stat: %v", pid, err)
	}

	// Convert startTicks to time
	ticksPerSecond := int64(100) // Default value
	if clkTck := os.Getenv("CLK_TCK"); clkTck != "" {
		if val, err := strconv.ParseInt(clkTck, 10, 64); err == nil && val > 0 {
			ticksPerSecond = val
		} else {
			log.Warn().Msgf("%v Invalid CLK_TCK env var (%s), using default ticksPerSecond=100", futils.GetCalleRuntime(), clkTck)
		}
	}
	procStartTime := bootTime.Add(time.Duration(startTicks/ticksPerSecond) * time.Second)

	// Use the more recent of FD mtime and process start time
	fdOpenTime := fdMtime
	if procStartTime.After(fdMtime) {
		fdOpenTime = procStartTime
	}

	// Calculate TTL in minutes
	ttl := time.Since(fdOpenTime).Minutes()
	return ttl, nil
}

// getSystemBootTime reads /proc/stat to get system boot time
func getSystemBootTime() (time.Time, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read /proc/stat: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "btime ") {
			bootTimeSec, err := strconv.ParseInt(strings.Fields(line)[1], 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("invalid btime in /proc/stat: %v", err)
			}
			return time.Unix(bootTimeSec, 0), nil
		}
	}
	return time.Time{}, fmt.Errorf("btime not found in /proc/stat")
}

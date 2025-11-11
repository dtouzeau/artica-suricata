package CheckMem

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// MemoryInfo holds system memory information
type MemoryInfo struct {
	TotalMemoryMB     uint64
	AvailableMemoryMB uint64
	FreeMemoryMB      uint64
	BuffersMB         uint64
	CachedMB          uint64
}

// SuricataMemoryRequirements holds calculated memory requirements
type SuricataMemoryRequirements struct {
	MinimumMemoryMB        uint64 // Absolute minimum to run
	RecommendedMemoryMB    uint64 // Recommended for normal operation
	OptimalMemoryMB        uint64 // Optimal for high performance
	BaseMemoryMB           uint64 // Base Suricata process memory
	PerThreadMemoryMB      uint64 // Memory per worker thread
	FlowMemoryMB           uint64 // Memory for flow tracking
	StreamMemoryMB         uint64 // Memory for stream reassembly
	DefragMemoryMB         uint64 // Memory for defragmentation
	RingBufferMemoryMB     uint64 // Memory for packet capture ring buffers
	SafetyMarginMB         uint64 // Safety margin to avoid OOM
	NumberOfThreads        int    // Number of worker threads
	MaxFlows               uint64 // Maximum concurrent flows
	SystemReservedMB       uint64 // Memory reserved for system
	AvailableForSuricataMB uint64 // Available memory for Suricata
	WillAvoidOOM           bool   // True if configuration avoids OOM killer
	OOMRiskLevel           string // "low", "medium", "high", "critical"
}

// GetSystemMemoryInfo retrieves system memory information from /proc/meminfo
func GetSystemMemoryInfo() (*MemoryInfo, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/meminfo: %w", err)
	}
	defer file.Close()

	memInfo := &MemoryInfo{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		// Convert from KB to MB
		valueMB := value / 1024

		switch key {
		case "MemTotal":
			memInfo.TotalMemoryMB = valueMB
		case "MemAvailable":
			memInfo.AvailableMemoryMB = valueMB
		case "MemFree":
			memInfo.FreeMemoryMB = valueMB
		case "Buffers":
			memInfo.BuffersMB = valueMB
		case "Cached":
			memInfo.CachedMB = valueMB
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading /proc/meminfo: %w", err)
	}

	return memInfo, nil
}

// CalculateMinimalMemoryForSuricata calculates the minimal memory required
// to avoid OOM killer based on system resources and Suricata configuration
func CalculateMinimalMemoryForSuricata(threads int, maxFlows uint64, interfaceSpeed string) (*SuricataMemoryRequirements, error) {
	memInfo, err := GetSystemMemoryInfo()
	if err != nil {
		return nil, err
	}

	req := &SuricataMemoryRequirements{}

	// Auto-detect threads if not specified
	if threads == 0 {
		threads = runtime.NumCPU()
		// Limit to reasonable number
		if threads > 16 {
			threads = 16
		}
	}
	req.NumberOfThreads = threads

	// Auto-calculate max flows based on interface speed if not specified
	if maxFlows == 0 {
		switch strings.ToLower(interfaceSpeed) {
		case "100m", "100mbps":
			maxFlows = 65536 // 64K flows
		case "1g", "1gbps", "gigabit":
			maxFlows = 131072 // 128K flows
		case "10g", "10gbps":
			maxFlows = 524288 // 512K flows
		case "40g", "40gbps", "100g", "100gbps":
			maxFlows = 2097152 // 2M flows
		default:
			maxFlows = 131072 // Default to 1Gbps
		}
	}
	req.MaxFlows = maxFlows

	// Base memory for Suricata process (libraries, code, etc.)
	req.BaseMemoryMB = 256

	// Memory per worker thread (packet processing, detection engine)
	// Each thread needs memory for:
	// - Packet queue buffers
	// - Detection engine context
	// - Pattern matching structures
	req.PerThreadMemoryMB = uint64(threads) * 128

	// Flow tracking memory
	// Each flow entry is approximately 1KB (includes metadata, state, etc.)
	req.FlowMemoryMB = (maxFlows * 1024) / (1024 * 1024)
	if req.FlowMemoryMB < 128 {
		req.FlowMemoryMB = 128
	}

	// Stream reassembly memory
	// For TCP stream reassembly, approximately 50% of flow memory
	req.StreamMemoryMB = req.FlowMemoryMB / 2
	if req.StreamMemoryMB < 256 {
		req.StreamMemoryMB = 256
	}

	// IP defragmentation memory
	req.DefragMemoryMB = 64

	// Ring buffer memory (AF_PACKET or PF_RING)
	// Depends on ring buffer size and number of interfaces
	// Default: 2048 packets * 2KB per packet * number of threads
	ringBufferSizeKB := uint64(2048 * 2 * threads)
	req.RingBufferMemoryMB = ringBufferSizeKB / 1024
	if req.RingBufferMemoryMB < 128 {
		req.RingBufferMemoryMB = 128
	}

	// Calculate minimum memory (bare minimum to start)
	req.MinimumMemoryMB = req.BaseMemoryMB +
		req.PerThreadMemoryMB +
		(req.FlowMemoryMB / 4) + // Minimum flow table
		(req.StreamMemoryMB / 4) + // Minimum stream reassembly
		req.DefragMemoryMB +
		(req.RingBufferMemoryMB / 2)

	// Calculate recommended memory (normal operation)
	req.RecommendedMemoryMB = req.BaseMemoryMB +
		req.PerThreadMemoryMB +
		req.FlowMemoryMB +
		req.StreamMemoryMB +
		req.DefragMemoryMB +
		req.RingBufferMemoryMB

	// Calculate optimal memory (high performance, no memory pressure)
	req.OptimalMemoryMB = uint64(float64(req.RecommendedMemoryMB) * 1.5)

	// Safety margin to avoid OOM (20% of recommended memory)
	req.SafetyMarginMB = req.RecommendedMemoryMB / 5

	// System reserved memory (for OS, other processes)
	// Reserve at least 1GB or 25% of total memory, whichever is larger
	systemReserved1GB := uint64(1024)
	systemReserved25Pct := memInfo.TotalMemoryMB / 4
	if systemReserved25Pct > systemReserved1GB {
		req.SystemReservedMB = systemReserved25Pct
	} else {
		req.SystemReservedMB = systemReserved1GB
	}

	// Calculate available memory for Suricata
	if memInfo.AvailableMemoryMB > req.SystemReservedMB {
		req.AvailableForSuricataMB = memInfo.AvailableMemoryMB - req.SystemReservedMB
	} else {
		req.AvailableForSuricataMB = 0
	}

	// Determine if this will avoid OOM killer
	totalRequired := req.RecommendedMemoryMB + req.SafetyMarginMB
	req.WillAvoidOOM = req.AvailableForSuricataMB >= totalRequired

	// Assess OOM risk level
	if req.AvailableForSuricataMB < req.MinimumMemoryMB {
		req.OOMRiskLevel = "critical"
		req.WillAvoidOOM = false
	} else if req.AvailableForSuricataMB < req.RecommendedMemoryMB {
		req.OOMRiskLevel = "high"
		req.WillAvoidOOM = false
	} else if req.AvailableForSuricataMB < totalRequired {
		req.OOMRiskLevel = "medium"
		req.WillAvoidOOM = false
	} else if req.AvailableForSuricataMB >= req.OptimalMemoryMB {
		req.OOMRiskLevel = "low"
		req.WillAvoidOOM = true
	} else {
		req.OOMRiskLevel = "low"
		req.WillAvoidOOM = true
	}

	return req, nil
}

// GetMinimalSafeMemory returns the minimum memory in MB needed to safely run Suricata
// This is a convenience function that returns just the number
func GetMinimalSafeMemory(threads int, maxFlows uint64, interfaceSpeed string) (uint64, error) {
	req, err := CalculateMinimalMemoryForSuricata(threads, maxFlows, interfaceSpeed)
	if err != nil {
		return 0, err
	}

	// Return recommended + safety margin to avoid OOM
	return req.RecommendedMemoryMB + req.SafetyMarginMB, nil
}

// GenerateMemoryReport generates a human-readable report
func (req *SuricataMemoryRequirements) GenerateReport() string {
	var report strings.Builder

	report.WriteString("═══════════════════════════════════════════════════\n")
	report.WriteString("  Suricata Memory Requirements Analysis\n")
	report.WriteString("═══════════════════════════════════════════════════\n\n")

	// System Information
	memInfo, _ := GetSystemMemoryInfo()
	report.WriteString("System Memory:\n")
	report.WriteString(fmt.Sprintf("  Total Memory:            %d MB\n", memInfo.TotalMemoryMB))
	report.WriteString(fmt.Sprintf("  Available Memory:        %d MB\n", memInfo.AvailableMemoryMB))
	report.WriteString(fmt.Sprintf("  Free Memory:             %d MB\n", memInfo.FreeMemoryMB))
	report.WriteString(fmt.Sprintf("  System Reserved:         %d MB\n", req.SystemReservedMB))
	report.WriteString(fmt.Sprintf("  Available for Suricata:  %d MB\n\n", req.AvailableForSuricataMB))

	// Configuration
	report.WriteString("Suricata Configuration:\n")
	report.WriteString(fmt.Sprintf("  Worker Threads:          %d\n", req.NumberOfThreads))
	report.WriteString(fmt.Sprintf("  Max Flows:               %d\n\n", req.MaxFlows))

	// Memory Breakdown
	report.WriteString("Memory Requirements Breakdown:\n")
	report.WriteString(fmt.Sprintf("  Base Memory:             %d MB\n", req.BaseMemoryMB))
	report.WriteString(fmt.Sprintf("  Per-Thread Memory:       %d MB\n", req.PerThreadMemoryMB))
	report.WriteString(fmt.Sprintf("  Flow Tracking:           %d MB\n", req.FlowMemoryMB))
	report.WriteString(fmt.Sprintf("  Stream Reassembly:       %d MB\n", req.StreamMemoryMB))
	report.WriteString(fmt.Sprintf("  IP Defragmentation:      %d MB\n", req.DefragMemoryMB))
	report.WriteString(fmt.Sprintf("  Ring Buffers:            %d MB\n", req.RingBufferMemoryMB))
	report.WriteString(fmt.Sprintf("  Safety Margin:           %d MB\n\n", req.SafetyMarginMB))

	// Memory Recommendations
	report.WriteString("Memory Recommendations:\n")
	report.WriteString(fmt.Sprintf("  Minimum (bare minimum):  %d MB\n", req.MinimumMemoryMB))
	report.WriteString(fmt.Sprintf("  Recommended (normal):    %d MB\n", req.RecommendedMemoryMB))
	report.WriteString(fmt.Sprintf("  Optimal (high perf):     %d MB\n\n", req.OptimalMemoryMB))

	// OOM Analysis
	report.WriteString("OOM Killer Risk Assessment:\n")
	report.WriteString(fmt.Sprintf("  OOM Risk Level:          %s\n", strings.ToUpper(req.OOMRiskLevel)))
	report.WriteString(fmt.Sprintf("  Will Avoid OOM:          %v\n", req.WillAvoidOOM))

	if !req.WillAvoidOOM {
		report.WriteString("\nWARNING: Current system memory may be insufficient!\n")

		memNeeded := (req.RecommendedMemoryMB + req.SafetyMarginMB) - req.AvailableForSuricataMB
		report.WriteString(fmt.Sprintf("  Additional memory needed: %d MB\n", memNeeded))

		report.WriteString("\nRecommendations:\n")
		if req.AvailableForSuricataMB < req.MinimumMemoryMB {
			report.WriteString("  - CRITICAL: Add more RAM to the system\n")
			report.WriteString("  - Cannot safely run Suricata with current memory\n")
		} else if req.AvailableForSuricataMB < req.RecommendedMemoryMB {
			report.WriteString("  - Reduce number of worker threads\n")
			report.WriteString(fmt.Sprintf("  - Suggested threads: %d (current: %d)\n",
				req.NumberOfThreads/2, req.NumberOfThreads))
			report.WriteString("  - Reduce max-flows setting\n")
			report.WriteString(fmt.Sprintf("  - Suggested max-flows: %d (current: %d)\n",
				req.MaxFlows/2, req.MaxFlows))
		} else {
			report.WriteString("  - Add safety margin by reducing threads or max-flows\n")
			report.WriteString("  - Monitor memory usage closely\n")
		}
	} else {
		report.WriteString("\n✓ System has sufficient memory to avoid OOM killer\n")
	}

	report.WriteString("\n═══════════════════════════════════════════════════\n")

	return report.String()
}

// GetSuricataYAMLMemoryConfig generates YAML configuration snippet
func (req *SuricataMemoryRequirements) GetSuricataYAMLMemoryConfig() string {
	var config strings.Builder

	config.WriteString("# Memory configuration for Suricata\n")
	config.WriteString("# Generated based on system memory analysis\n\n")

	config.WriteString(fmt.Sprintf("max-pending-packets: %d\n", 1024*req.NumberOfThreads))
	config.WriteString(fmt.Sprintf("default-packet-size: 1514\n"))
	config.WriteString("\n")

	config.WriteString("flow:\n")
	config.WriteString(fmt.Sprintf("  memcap: %dm\n", req.FlowMemoryMB))
	config.WriteString(fmt.Sprintf("  hash-size: %d\n", req.MaxFlows))
	config.WriteString("  prealloc: 10000\n")
	config.WriteString("\n")

	config.WriteString("stream:\n")
	config.WriteString(fmt.Sprintf("  memcap: %dm\n", req.StreamMemoryMB))
	config.WriteString("  reassembly:\n")
	config.WriteString(fmt.Sprintf("    memcap: %dm\n", req.StreamMemoryMB))
	config.WriteString("\n")

	config.WriteString("defrag:\n")
	config.WriteString(fmt.Sprintf("  memcap: %dm\n", req.DefragMemoryMB))
	config.WriteString("\n")

	config.WriteString("threading:\n")
	config.WriteString(fmt.Sprintf("  set-cpu-affinity: yes\n"))
	config.WriteString(fmt.Sprintf("  cpu-affinity:\n"))
	config.WriteString(fmt.Sprintf("    - worker-cpu-set:\n"))
	config.WriteString(fmt.Sprintf("        cpu: [ 0-%d ]\n", req.NumberOfThreads-1))
	config.WriteString(fmt.Sprintf("        mode: \"exclusive\"\n"))

	return config.String()
}

// Example usage
func main() {
	fmt.Println("Suricata Memory Calculator\n")

	// Example 1: Auto-detect threads, 1Gbps network
	fmt.Println("Example 1: Auto-detect, 1Gbps network")
	req1, err := CalculateMinimalMemoryForSuricata(0, 0, "1gbps")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println(req1.GenerateReport())

	// Example 2: 4 threads, 256K flows, 10Gbps network
	fmt.Println("\nExample 2: 4 threads, 256K flows, 10Gbps")
	req2, err := CalculateMinimalMemoryForSuricata(4, 262144, "10gbps")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println(req2.GenerateReport())

	// Example 3: Get minimal safe memory only
	fmt.Println("\nExample 3: Get minimal safe memory (simple)")
	minMem, err := GetMinimalSafeMemory(0, 0, "1gbps")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Minimal safe memory: %d MB\n\n", minMem)

	// Example 4: Generate YAML config
	fmt.Println("Example 4: Suggested Suricata YAML configuration")
	fmt.Println(req2.GetSuricataYAMLMemoryConfig())
}

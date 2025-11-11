package CheckMem

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// SuricataConfig represents the Suricata YAML configuration
type SuricataConfig struct {
	AFPacket  []AFPacketInterface `yaml:"af-packet"`
	PFRing    []PFRingInterface   `yaml:"pfring"`
	PCAP      []PCAPInterface     `yaml:"pcap"`
	Flow      FlowConfig          `yaml:"flow"`
	Stream    StreamConfig        `yaml:"stream"`
	Defrag    DefragConfig        `yaml:"defrag"`
	Threading ThreadingConfig     `yaml:"threading"`
}

// AFPacketInterface represents AF_PACKET interface configuration
type AFPacketInterface struct {
	Interface   string      `yaml:"interface"`
	Threads     interface{} `yaml:"threads"` // Can be int or "auto"
	ClusterID   int         `yaml:"cluster-id"`
	ClusterType string      `yaml:"cluster-type"`
}

// PFRingInterface represents PF_RING interface configuration
type PFRingInterface struct {
	Interface   string      `yaml:"interface"`
	Threads     interface{} `yaml:"threads"`
	ClusterID   int         `yaml:"cluster-id"`
	ClusterType string      `yaml:"cluster-type"`
}

// PCAPInterface represents PCAP interface configuration
type PCAPInterface struct {
	Interface string `yaml:"interface"`
}

// FlowConfig represents flow configuration
type FlowConfig struct {
	Memcap   string `yaml:"memcap"`
	HashSize int    `yaml:"hash-size"`
}

// StreamConfig represents stream configuration
type StreamConfig struct {
	Memcap     string           `yaml:"memcap"`
	Reassembly StreamReassembly `yaml:"reassembly"`
}

// StreamReassembly represents stream reassembly configuration
type StreamReassembly struct {
	Memcap string `yaml:"memcap"`
}

// DefragConfig represents defrag configuration
type DefragConfig struct {
	Memcap string `yaml:"memcap"`
}

// ThreadingConfig represents threading configuration
type ThreadingConfig struct {
	SetCPUAffinity bool                `yaml:"set-cpu-affinity"`
	CPUAffinity    []CPUAffinityConfig `yaml:"cpu-affinity"`
}

// CPUAffinityConfig represents CPU affinity configuration
type CPUAffinityConfig struct {
	WorkerCPUSet WorkerCPUSet `yaml:"worker-cpu-set"`
}

// WorkerCPUSet represents worker CPU set configuration
type WorkerCPUSet struct {
	CPU  []interface{} `yaml:"cpu"`
	Mode string        `yaml:"mode"`
}

// InterfaceSpeedInfo holds detected interface information
type InterfaceSpeedInfo struct {
	InterfaceName string
	SpeedMbps     uint64
	SpeedString   string // "100m", "1g", "10g", etc.
	IsUp          bool
	Duplex        string
	MTU           int
}

// ParseSuricataConfig parses the Suricata YAML configuration file
func ParseSuricataConfig(configPath string) (*SuricataConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config SuricataConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &config, nil
}

// GetInterfacesFromConfig extracts all interfaces from Suricata config
func GetInterfacesFromConfig(config *SuricataConfig) []string {
	interfaces := make(map[string]bool)

	// Get AF_PACKET interfaces
	for _, iface := range config.AFPacket {
		if iface.Interface != "" {
			interfaces[iface.Interface] = true
		}
	}

	// Get PF_RING interfaces
	for _, iface := range config.PFRing {
		if iface.Interface != "" {
			interfaces[iface.Interface] = true
		}
	}

	// Get PCAP interfaces
	for _, iface := range config.PCAP {
		if iface.Interface != "" {
			interfaces[iface.Interface] = true
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(interfaces))
	for iface := range interfaces {
		result = append(result, iface)
	}

	return result
}

// GetInterfaceSpeed detects the speed of a network interface using ethtool
func GetInterfaceSpeed(interfaceName string) (*InterfaceSpeedInfo, error) {
	info := &InterfaceSpeedInfo{
		InterfaceName: interfaceName,
	}

	// Get speed using ethtool
	cmd := exec.Command("ethtool", interfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ethtool failed for %s: %w", interfaceName, err)
	}

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse speed
		if strings.HasPrefix(line, "Speed:") {
			speedStr := strings.TrimPrefix(line, "Speed:")
			speedStr = strings.TrimSpace(speedStr)

			// Extract numeric value (e.g., "1000Mb/s" -> 1000)
			re := regexp.MustCompile(`(\d+)`)
			matches := re.FindStringSubmatch(speedStr)
			if len(matches) > 1 {
				speed, _ := strconv.ParseUint(matches[1], 10, 64)
				info.SpeedMbps = speed

				// Determine speed string
				if speed >= 100000 {
					info.SpeedString = "100g"
				} else if speed >= 40000 {
					info.SpeedString = "40g"
				} else if speed >= 10000 {
					info.SpeedString = "10g"
				} else if speed >= 1000 {
					info.SpeedString = "1g"
				} else if speed >= 100 {
					info.SpeedString = "100m"
				} else {
					info.SpeedString = "10m"
				}
			}

			// Handle "Unknown!" speed (interface down or virtual)
			if strings.Contains(speedStr, "Unknown") {
				info.SpeedString = "1g" // Default assumption
				info.SpeedMbps = 1000
			}
		}

		// Parse link status
		if strings.HasPrefix(line, "Link detected:") {
			info.IsUp = strings.Contains(line, "yes")
		}

		// Parse duplex
		if strings.HasPrefix(line, "Duplex:") {
			info.Duplex = strings.TrimSpace(strings.TrimPrefix(line, "Duplex:"))
		}
	}

	// Get MTU from ip link show
	cmd = exec.Command("ip", "link", "show", interfaceName)
	output, err = cmd.CombinedOutput()
	if err == nil {
		re := regexp.MustCompile(`mtu (\d+)`)
		matches := re.FindStringSubmatch(string(output))
		if len(matches) > 1 {
			mtu, _ := strconv.Atoi(matches[1])
			info.MTU = mtu
		}
	}

	return info, nil
}

// GetAllInterfaceSpeeds gets speed information for all interfaces
func GetAllInterfaceSpeeds(interfaces []string) (map[string]*InterfaceSpeedInfo, error) {
	speedInfo := make(map[string]*InterfaceSpeedInfo)

	for _, iface := range interfaces {
		info, err := GetInterfaceSpeed(iface)
		if err != nil {
			// Don't fail completely, just skip this interface
			fmt.Printf("Warning: Could not get speed for %s: %v\n", iface, err)
			continue
		}
		speedInfo[iface] = info
	}

	return speedInfo, nil
}

// GetMaxInterfaceSpeed returns the maximum speed among all interfaces
func GetMaxInterfaceSpeed(speedInfo map[string]*InterfaceSpeedInfo) uint64 {
	var maxSpeed uint64 = 0

	for _, info := range speedInfo {
		if info.SpeedMbps > maxSpeed {
			maxSpeed = info.SpeedMbps
		}
	}

	return maxSpeed
}

// GetThreadCountFromConfig extracts thread count from config
func GetThreadCountFromConfig(config *SuricataConfig) int {
	threads := 0

	// Check AF_PACKET interfaces
	for _, iface := range config.AFPacket {
		t := parseThreadValue(iface.Threads)
		if t > threads {
			threads = t
		}
	}

	// Check PF_RING interfaces
	for _, iface := range config.PFRing {
		t := parseThreadValue(iface.Threads)
		if t > threads {
			threads = t
		}
	}

	return threads
}

// parseThreadValue converts thread value (int or "auto") to int
func parseThreadValue(threads interface{}) int {
	switch v := threads.(type) {
	case int:
		return v
	case string:
		if v == "auto" {
			// Return 0 to indicate auto-detection needed
			return 0
		}
		// Try to parse as int
		if num, err := strconv.Atoi(v); err == nil {
			return num
		}
	}
	return 0
}

// GetMaxFlowsFromConfig extracts max flows from config
func GetMaxFlowsFromConfig(config *SuricataConfig) uint64 {
	if config.Flow.HashSize > 0 {
		return uint64(config.Flow.HashSize)
	}
	return 0 // Will be auto-calculated
}

// CalculateMemoryFromConfig combines config parsing and memory calculation
func CalculateMemoryFromConfig(configPath string) (*SuricataMemoryRequirements, error) {
	// Parse config
	config, err := ParseSuricataConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Get interfaces
	interfaces := GetInterfacesFromConfig(config)
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no interfaces found in config")
	}

	// Get interface speeds
	speedInfo, err := GetAllInterfaceSpeeds(interfaces)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface speeds: %w", err)
	}

	// Get maximum interface speed
	maxSpeed := GetMaxInterfaceSpeed(speedInfo)
	speedString := ""
	if maxSpeed >= 10000 {
		speedString = "10g"
	} else if maxSpeed >= 1000 {
		speedString = "1g"
	} else {
		speedString = "100m"
	}

	// Get thread count
	threads := GetThreadCountFromConfig(config)

	// Get max flows
	maxFlows := GetMaxFlowsFromConfig(config)

	// Calculate memory requirements
	req, err := CalculateMinimalMemoryForSuricata(threads, maxFlows, speedString)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate memory: %w", err)
	}

	return req, nil
}

// GenerateInterfaceReport generates a report of detected interfaces
func GenerateInterfaceReport(speedInfo map[string]*InterfaceSpeedInfo) string {
	var report strings.Builder

	report.WriteString("═══════════════════════════════════════════════════\n")
	report.WriteString("  Detected Network Interfaces\n")
	report.WriteString("═══════════════════════════════════════════════════\n\n")

	report.WriteString(fmt.Sprintf("%-15s %-10s %-8s %-10s %-6s\n",
		"Interface", "Speed", "Link", "Duplex", "MTU"))
	report.WriteString(strings.Repeat("-", 60) + "\n")

	for name, info := range speedInfo {
		linkStatus := "DOWN"
		if info.IsUp {
			linkStatus = "UP"
		}

		speedDisplay := fmt.Sprintf("%d Mbps", info.SpeedMbps)
		if info.SpeedString != "" {
			speedDisplay = fmt.Sprintf("%s (%d)", info.SpeedString, info.SpeedMbps)
		}

		report.WriteString(fmt.Sprintf("%-15s %-10s %-8s %-10s %-6d\n",
			name, speedDisplay, linkStatus, info.Duplex, info.MTU))
	}

	report.WriteString("\n")
	return report.String()
}

// Example usage
func Example() {
	configPath := "/etc/suricata/suricata.yaml"

	fmt.Println("Suricata Configuration Analyzer\n")

	// Parse config
	fmt.Println("Parsing configuration...")
	config, err := ParseSuricataConfig(configPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("\nTrying with example values...")

		// Fallback to manual calculation
		req, _ := CalculateMinimalMemoryForSuricata(0, 0, "1g")
		fmt.Println(req.GenerateReport())
		return
	}

	// Get interfaces
	interfaces := GetInterfacesFromConfig(config)
	fmt.Printf("Found %d interface(s): %v\n\n", len(interfaces), interfaces)

	if len(interfaces) == 0 {
		fmt.Println("No interfaces configured. Using defaults.")
		req, _ := CalculateMinimalMemoryForSuricata(0, 0, "1g")
		fmt.Println(req.GenerateReport())
		return
	}

	// Get interface speeds
	fmt.Println("Detecting interface speeds...")
	speedInfo, err := GetAllInterfaceSpeeds(interfaces)
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	// Show interface report
	if len(speedInfo) > 0 {
		fmt.Println(GenerateInterfaceReport(speedInfo))
	}

	// Calculate memory requirements
	fmt.Println("Calculating memory requirements...")
	req, err := CalculateMemoryFromConfig(configPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Show full report
	fmt.Println(req.GenerateReport())

	// Show YAML config suggestion
	fmt.Println("\nSuggested Configuration:")
	fmt.Println(req.GetSuricataYAMLMemoryConfig())
}

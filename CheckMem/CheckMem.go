package CheckMem

import (
	"fmt"
	"os"
	"strings"
)

// AutoDetectMemoryRequirements automatically detects all parameters from the system
// and Suricata configuration, then calculates memory requirements
func AutoDetectMemoryRequirements(configPath string) (*SuricataMemoryRequirements, map[string]*InterfaceSpeedInfo, error) {
	// Parse Suricata configuration
	config, err := ParseSuricataConfig(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Extract interfaces from config
	interfaces := GetInterfacesFromConfig(config)
	if len(interfaces) == 0 {
		return nil, nil, fmt.Errorf("no interfaces configured in %s", configPath)
	}

	// Detect interface speeds
	speedInfo, err := GetAllInterfaceSpeeds(interfaces)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to detect interface speeds: %w", err)
	}

	// Get maximum interface speed
	maxSpeedMbps := GetMaxInterfaceSpeed(speedInfo)
	speedString := ConvertSpeedToString(maxSpeedMbps)

	// Get thread count from config
	threads := GetThreadCountFromConfig(config)

	// Get max flows from config
	maxFlows := GetMaxFlowsFromConfig(config)

	// Calculate memory requirements
	req, err := CalculateMinimalMemoryForSuricata(threads, maxFlows, speedString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate memory: %w", err)
	}

	return req, speedInfo, nil
}

// ConvertSpeedToString converts speed in Mbps to string format
func ConvertSpeedToString(speedMbps uint64) string {
	if speedMbps >= 100000 {
		return "100g"
	} else if speedMbps >= 40000 {
		return "40g"
	} else if speedMbps >= 10000 {
		return "10g"
	} else if speedMbps >= 1000 {
		return "1g"
	} else if speedMbps >= 100 {
		return "100m"
	} else {
		return "10m"
	}
}

// GenerateFullReport generates a comprehensive report including interface info and memory
func GenerateFullReport(configPath string) (string, error) {
	var report string

	req, speedInfo, err := AutoDetectMemoryRequirements(configPath)
	if err != nil {
		return "", err
	}

	// Add interface report
	if len(speedInfo) > 0 {
		report += GenerateInterfaceReport(speedInfo)
	}

	// Add memory report
	report += req.GenerateReport()

	return report, nil
}

// CheckOOMRisk checks if the current configuration has OOM risk
func CheckOOMRisk(configPath string) (bool, string, error) {
	req, _, err := AutoDetectMemoryRequirements(configPath)
	if err != nil {
		return true, "critical", err
	}

	return !req.WillAvoidOOM, req.OOMRiskLevel, nil
}

// GetMinimalMemoryFromConfig is a simple wrapper that returns just the minimum safe memory
func GetMinimalMemoryFromConfig(configPath string) (uint64, error) {
	req, _, err := AutoDetectMemoryRequirements(configPath)
	if err != nil {
		return 0, err
	}

	return req.RecommendedMemoryMB + req.SafetyMarginMB, nil
}

// GetServerMemoryRecommendations returns total server memory recommendations
func (m *MemoryRequirements) GetServerMemoryRecommendations() string {
	var report strings.Builder

	report.WriteString("═══════════════════════════════════════════════════\n")
	report.WriteString("  Total Server Memory Recommendations\n")
	report.WriteString("═══════════════════════════════════════════════════\n\n")

	report.WriteString("These values represent the TOTAL RAM needed for the\n")
	report.WriteString("Linux server to safely run Suricata along with the OS.\n\n")

	report.WriteString(fmt.Sprintf("Minimal Server RAM:      %d MB (%.1f GB)\n",
		m.MinimalServerMemoryMB,
		float64(m.MinimalServerMemoryMB)/1024.0))
	report.WriteString("  └─ Bare minimum to start Suricata\n")
	report.WriteString("  └─ High risk of OOM under load\n")
	report.WriteString("  └─ NOT recommended for production\n\n")

	report.WriteString(fmt.Sprintf("Recommended Server RAM:  %d MB (%.1f GB)\n",
		m.RecommendedServerMemoryMB,
		float64(m.RecommendedServerMemoryMB)/1024.0))
	report.WriteString("  └─ Safe for normal operation\n")
	report.WriteString("  └─ Includes safety margin\n")
	report.WriteString("  └─ Recommended for production\n\n")

	report.WriteString(fmt.Sprintf("Optimal Server RAM:      %d MB (%.1f GB)\n",
		m.OptimalServerMemoryMB,
		float64(m.OptimalServerMemoryMB)/1024.0))
	report.WriteString("  └─ Best performance\n")
	report.WriteString("  └─ No memory pressure\n")
	report.WriteString("  └─ Ideal for high-traffic networks\n\n")

	report.WriteString("═══════════════════════════════════════════════════\n")
	report.WriteString("Breakdown:\n")
	report.WriteString("═══════════════════════════════════════════════════\n\n")

	report.WriteString(fmt.Sprintf("Suricata Base Memory:         %d MB\n", m.Report.BaseMemoryMB))
	report.WriteString(fmt.Sprintf("Per-Thread Memory:            %d MB\n", m.Report.PerThreadMemoryMB))
	report.WriteString(fmt.Sprintf("Flow Tracking:                %d MB\n", m.Report.FlowMemoryMB))
	report.WriteString(fmt.Sprintf("Stream Reassembly:            %d MB\n", m.Report.StreamMemoryMB))
	report.WriteString(fmt.Sprintf("IP Defragmentation:           %d MB\n", m.Report.DefragMemoryMB))
	report.WriteString(fmt.Sprintf("Ring Buffers:                 %d MB\n", m.Report.RingBufferMemoryMB))
	report.WriteString(fmt.Sprintf("Safety Margin:                %d MB\n", m.Report.SafetyMarginMB))
	report.WriteString(fmt.Sprintf("System Reserved (OS + other): %d MB\n", m.Report.SystemReservedMB))
	report.WriteString("═══════════════════════════════════════════════════\n\n")

	// Provide purchasing recommendation
	report.WriteString("Server Purchase Recommendation:\n")
	report.WriteString("───────────────────────────────────────────────────\n")

	// Round up to common RAM sizes
	recommendedGB := float64(m.RecommendedServerMemoryMB) / 1024.0
	var suggestedRAM int

	// Common server RAM sizes: 4, 8, 16, 32, 64, 128, 256 GB
	commonSizes := []int{4, 8, 16, 32, 64, 128, 256}
	for _, size := range commonSizes {
		if float64(size) >= recommendedGB {
			suggestedRAM = size
			break
		}
	}

	if suggestedRAM == 0 {
		suggestedRAM = 256 // Maximum common size
	}

	report.WriteString(fmt.Sprintf("Buy a server with at least:   %d GB RAM\n", suggestedRAM))
	report.WriteString(fmt.Sprintf("  └─ This covers recommended: %.1f GB\n", recommendedGB))
	report.WriteString(fmt.Sprintf("  └─ Extra headroom:          %.1f GB\n", float64(suggestedRAM)-recommendedGB))
	report.WriteString("\n")

	return report.String()
}

type MemoryRequirements struct {
	MinMemRequire             uint64                         `json:"min_mem_require"`
	RecommendedServerMemoryMB uint64                         `json:"recommended_server_memory_mb"`
	MinimalServerMemoryMB     uint64                         `json:"minimal_server_memory_mb"`
	OptimalServerMemoryMB     uint64                         `json:"optimal_server_memory_mb"`
	SpeedInfo                 map[string]*InterfaceSpeedInfo `json:"speed_info"`
	Report                    SuricataMemoryRequirements     `json:"report"`
	HasRisk                   bool                           `json:"has_risk"`
	RiskLevel                 string                         `json:"risk_level"`
	WillAvoidOOM              bool                           `json:"will_avoid_oom"`
	OOMRiskLevel              string                         `json:"oom_risk_level"`
}

func Run() MemoryRequirements {
	configPath := "/etc/suricata/suricata.yaml"
	var f MemoryRequirements

	// Get minimal memory from config
	minMem, err := GetMinimalMemoryFromConfig(configPath)
	if err != nil {
		fmt.Printf("Error getting minimal memory: %v\n", err)
		// Return empty struct with error indication
		f.HasRisk = true
		f.RiskLevel = "critical"
		f.OOMRiskLevel = "critical"
		return f
	}
	f.MinMemRequire = minMem

	// Get full requirements
	req, speedInfo, err := AutoDetectMemoryRequirements(configPath)
	if err != nil {
		fmt.Printf("Error auto-detecting requirements: %v\n", err)
		f.HasRisk = true
		f.RiskLevel = "critical"
		f.OOMRiskLevel = "critical"
		return f
	}

	// Print report
	fmt.Println(req.GenerateReport())

	// Assign req to struct (this was missing!)
	f.Report = *req
	f.SpeedInfo = speedInfo
	f.WillAvoidOOM = req.WillAvoidOOM
	f.OOMRiskLevel = req.OOMRiskLevel

	// Calculate total server memory recommendations
	// These include Suricata memory + system reserved memory

	// Minimal: Absolute minimum to run Suricata (may cause OOM under load)
	// Formula: Minimum Suricata memory + System reserved
	f.MinimalServerMemoryMB = req.MinimumMemoryMB + req.SystemReservedMB

	// Recommended: Safe memory to run Suricata without OOM issues
	// Formula: Recommended Suricata memory + Safety margin + System reserved
	f.RecommendedServerMemoryMB = req.RecommendedMemoryMB + req.SafetyMarginMB + req.SystemReservedMB

	// Optimal: Best performance, no memory pressure
	// Formula: Optimal Suricata memory + Safety margin + System reserved
	f.OptimalServerMemoryMB = req.OptimalMemoryMB + req.SafetyMarginMB + req.SystemReservedMB

	// Check OOM risk
	hasRisk, riskLevel, err := CheckOOMRisk(configPath)
	if err != nil {
		fmt.Printf("Error checking OOM risk: %v\n", err)
		f.HasRisk = true
		f.RiskLevel = "critical"
		return f
	}

	f.HasRisk = hasRisk
	f.RiskLevel = riskLevel

	return f
}

func CmdLine() {
	configPath := "/etc/suricata/suricata.yaml"

	fmt.Printf("╔═══════════════════════════════════════════════════╗\n")
	fmt.Printf("║   Suricata Memory Requirement Analyzer           ║\n")
	fmt.Printf("║   Auto-detecting from: %-27s║\n", configPath)
	fmt.Printf("╚═══════════════════════════════════════════════════╝\n\n")

	// Check if config exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("Config file not found: %s\n", configPath)
		fmt.Println("Using default values for demonstration...\n")

		// Use defaults
		req, _ := CalculateMinimalMemoryForSuricata(0, 0, "1g")
		fmt.Println(req.GenerateReport())
		return
	}

	// Generate full report
	report, err := GenerateFullReport(configPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("\nFalling back to default calculation...")

		// Fallback
		req, _ := CalculateMinimalMemoryForSuricata(0, 0, "1g")
		fmt.Println(req.GenerateReport())
		return
	}

	fmt.Println(report)

	// Check OOM risk
	hasOOMRisk, riskLevel, err := CheckOOMRisk(configPath)
	if err == nil && hasOOMRisk {
		fmt.Printf("\n⚠️  WARNING: OOM KILLER RISK DETECTED (%s)\n", riskLevel)
		fmt.Println("\nRecommended Actions:")

		// Get requirements for recommendations
		req, _, _ := AutoDetectMemoryRequirements(configPath)

		if req.AvailableForSuricataMB < req.MinimumMemoryMB {
			fmt.Println("  1. Add more physical RAM to the system")
			fmt.Printf("     Current available: %d MB\n", req.AvailableForSuricataMB)
			fmt.Printf("     Minimum required:  %d MB\n", req.MinimumMemoryMB)
			fmt.Printf("     Deficit:           %d MB\n", req.MinimumMemoryMB-req.AvailableForSuricataMB)
		} else {
			fmt.Println("  1. Reduce worker threads in suricata.yaml")
			fmt.Printf("     Current:    %d threads\n", req.NumberOfThreads)
			fmt.Printf("     Suggested:  %d threads\n", req.NumberOfThreads/2)

			fmt.Println("\n  2. Reduce max flows in flow configuration")
			fmt.Printf("     Current:    %d flows\n", req.MaxFlows)
			fmt.Printf("     Suggested:  %d flows\n", req.MaxFlows/2)

			fmt.Println("\n  3. Reduce memory caps in suricata.yaml")
			fmt.Println("     - flow.memcap")
			fmt.Println("     - stream.memcap")
			fmt.Println("     - stream.reassembly.memcap")
		}
	} else {
		fmt.Println("\n✅ SYSTEM CONFIGURATION LOOKS GOOD")
		fmt.Println("Memory is sufficient to avoid OOM killer")
	}

	// Generate suggested YAML
	req, _, _ := AutoDetectMemoryRequirements(configPath)
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Suggested Suricata YAML Memory Configuration:")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println(req.GetSuricataYAMLMemoryConfig())

	// Summary
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Quick Summary:")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Minimum safe memory needed: %d MB\n", req.RecommendedMemoryMB+req.SafetyMarginMB)
	fmt.Printf("Available for Suricata:     %d MB\n", req.AvailableForSuricataMB)
	fmt.Printf("OOM Risk Level:             %s\n", req.OOMRiskLevel)
	if req.WillAvoidOOM {
		fmt.Println("Status:                     ✅ SAFE")
	} else {
		fmt.Println("Status:                     ⚠️  AT RISK")
	}
	fmt.Println(strings.Repeat("=", 60))

	// Display total server memory recommendations
	fmt.Println("\n")
	memReq := MemoryRequirements{
		MinimalServerMemoryMB:     req.MinimumMemoryMB + req.SystemReservedMB,
		RecommendedServerMemoryMB: req.RecommendedMemoryMB + req.SafetyMarginMB + req.SystemReservedMB,
		OptimalServerMemoryMB:     req.OptimalMemoryMB + req.SafetyMarginMB + req.SystemReservedMB,
		Report:                    *req,
	}
	fmt.Println(memReq.GetServerMemoryRecommendations())
}

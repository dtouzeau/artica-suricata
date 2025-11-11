package SuriStructs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"futils"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type OtxOptions struct {
	Enabled     int    `json:"Enabled"`
	SkipIPRep   bool   `json:"SkipIPRep"`
	SkipFileMD5 bool   `json:"SkipFileMD5"`
	ApiKey      string `json:"ApiKey"`
	DestDir     string `json:"DestDir"`
	MaxPages    int    `json:"MaxPages"`
	LastUpdate  int64  `json:"LastUpdate"`
}
type HomeNets struct {
	Negative int `json:"Negative"`
	Enabled  int `json:"Enabled"`
}

type SuriDaemon struct {
	Version                    string              `json:"Version"`
	LastUpdate                 int64               `json:"LastUpdate"`
	RulesCount                 int                 `json:"RulesCount"`
	ActiveRules                int                 `json:"ActiveRules"`
	Categories                 map[string]int      `json:"Categories"`
	Families                   map[string]int      `json:"Families"`
	Otx                        OtxOptions          `json:"Otx"`
	QueueFailed                string              `json:"QueueFailed"`
	UseQueueFailed             int                 `json:"UseQueueFailed"`
	DataShieldIPv4Blocklist    int                 `json:"DataShieldIPv4Blocklist"`
	DataShieldIPv4BlocklistSHA string              `json:"DataShieldIPv4BlocklistMd5"`
	DataShieldIPv4BlocklistRec int                 `json:"DataShieldIPv4BlocklistRec"`
	EveLogsType                map[string]int      `json:"EveLogsType"`
	HomeNets                   map[string]HomeNets `json:"HomeNets"`
	NDPIOK                     bool                `json:"NDPIOK"`
	NDPICheckVer               string              `json:"NDPICheckVer"`
	NDPICheckTime              int64               `json:"NDPICheckTime"`
	NDPIEnabled                int                 `json:"NDPIEnabled"`
}

func LoadConfig() SuriDaemon {

	var f SuriDaemon
	data, _ := futils.FileGetContentsBytes("/etc/suricata/suriDaemon.json")
	_ = json.Unmarshal(data, &f)
	if f.Categories == nil {
		f.Categories = make(map[string]int)
	}
	if f.Families == nil {
		f.Families = make(map[string]int)
	}
	if f.EveLogsType == nil {
		f.EveLogsType = make(map[string]int)
	}
	if f.Otx.MaxPages == 0 {
		f.Otx.MaxPages = 20
	}
	if len(f.QueueFailed) < 3 {
		f.QueueFailed = "/home/suricata/queue-failed"
	}
	if f.HomeNets == nil {
		f.HomeNets = make(map[string]HomeNets)
	}
	if len(f.HomeNets) == 0 {
		f.HomeNets["10.0.0.0/8"] = HomeNets{Negative: 0, Enabled: 1}
		f.HomeNets["172.16.0.0/12"] = HomeNets{Negative: 0, Enabled: 1}
		f.HomeNets["192.168.0.0/16"] = HomeNets{Negative: 0, Enabled: 1}
	}

	if len(f.EveLogsType) == 0 {
		f.EveLogsType = map[string]int{
			"alert":    1,
			"anomaly":  0,
			"http":     0,
			"dns":      0,
			"tls":      0,
			"files":    0,
			"smtp":     0,
			"ssh":      0,
			"flow":     0,
			"netflow":  0,
			"stats":    0,
			"dhcp":     0,
			"tftp":     0,
			"smb":      0,
			"nfs":      0,
			"ftp":      0,
			"rdp":      0,
			"sip":      0,
			"ikev2":    0,
			"krb5":     0,
			"snmp":     0,
			"rfb":      0,
			"mqtt":     0,
			"dcerpc":   0,
			"metadata": 0,
			"dnp3":     0,
			"modbus":   0,
			"drop":     0,
		}
	}
	if len(f.NDPICheckVer) == 0 {
		go NDPICheckVer()
	}
	if !f.NDPIOK {
		f.NDPIEnabled = 0
	}

	return f
}
func SaveConfig(f SuriDaemon) {
	d, _ := json.Marshal(f)
	futils.CreateDir("/etc/suricata")
	_ = futils.FilePutContentsBytes("/etc/suricata/suriDaemon.json", d)
}

func NDPICheckVer() {
	Conf := LoadConfig()

	if Conf.NDPICheckTime > 0 {
		TimeMin := futils.TimeMin(Conf.NDPICheckTime)
		if TimeMin < 10 {
			return
		}
	}
	OutPut, err := suricataBuildInfo()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	Curver, err := getSuricataVersion(OutPut)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}

	if len(Conf.NDPICheckVer) > 0 {
		if Conf.NDPICheckVer == Curver {
			Conf.NDPICheckTime = time.Now().Unix()
			return
		}
	}

	val, err := checkNDPISupport(OutPut)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	Conf.NDPICheckTime = time.Now().Unix()
	Conf.NDPIOK = val
	Conf.NDPICheckVer = Curver
	SaveConfig(Conf)

}
func suricataBuildInfo() (string, error) {
	// Create a context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	suricata := futils.FindProgram("suricata")
	cmd := exec.CommandContext(ctx, suricata, "--build-info")

	// Capture both stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command
	err := cmd.Run()
	if err != nil {
		// If there's stderr output, include it in the error
		if stderr.Len() > 0 {
			return "", fmt.Errorf("suricata --build-info failed: %w\nStderr: %s", err, stderr.String())
		}
		return "", fmt.Errorf("suricata --build-info failed: %w", err)
	}

	// Return the output
	return stdout.String(), nil
}

// CheckNDPISupport checks if nDPI support is enabled in Suricata
// Returns true if nDPI is supported, false otherwise
func checkNDPISupport(output string) (bool, error) {

	// Check for nDPI support in the output
	// Look for "nDPI support: yes" or similar patterns
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "ndpi") {
			// Check if it says "yes" or "enabled"
			if strings.Contains(strings.ToLower(line), "yes") ||
				strings.Contains(strings.ToLower(line), "enabled") {
				return true, nil
			}
		}
	}

	return false, nil
}
func getSuricataVersion(output string) (string, error) {

	// Parse the version from the output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "This is Suricata version") {
			// Extract version number
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				return parts[4], nil
			}
		}
	}

	return "", fmt.Errorf("version information not found in build-info output")
}

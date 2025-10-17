package articaunix

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"futils"
	"github.com/rs/zerolog/log"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type PCIRegion struct {
	Index       int
	Description string
}

type PCIDevice struct {
	Slot          string
	Class         string
	VendorInfo    string
	Revision      string
	ProgIf        string
	DeviceName    string
	Control       string
	Status        string
	Latency       string
	Interrupt     string
	IOMMUGroup    string
	KernelDriver  string
	KernelModules string
	Regions       []PCIRegion
	Raw           string
}

func Lspci() []PCIDevice {
	TimeOut := time.Duration(10)
	ctx, cancel := context.WithTimeout(context.Background(), TimeOut*time.Second)
	defer cancel()
	systemctl := futils.FindProgram("systemctl")
	if !futils.FileExists(systemctl) {
		return []PCIDevice{}
	}
	lspci := futils.FindProgram("lspci")
	var outputBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, lspci, "-vv")
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf // Redirect stderr to the same buffer as stdout
	cmd.Env = append(cmd.Env, futils.ExecEnv()...)
	if err := cmd.Start(); err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []PCIDevice{}
	}
	err := cmd.Wait()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), "Timed-out!")
			return []PCIDevice{}

		}
		return parseLspciVV(outputBuf.String())
	}
	return parseLspciVV(outputBuf.String())
}

func parseLspciVV(output string) []PCIDevice {
	var devices []PCIDevice
	var current *PCIDevice
	regionRegexp := regexp.MustCompile(`Region (\d+): (.+)`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		if match := regexp.MustCompile(`^([0-9a-f]{2}:[0-9a-f]{2}\.[0-9]) (.+?): (.+?)( \(rev [0-9a-f]+\))?( \(prog-if .+\))?$`).FindStringSubmatch(line); match != nil {
			if current != nil {
				devices = append(devices, *current)
			}
			current = &PCIDevice{
				Slot:       match[1],
				Class:      match[2],
				VendorInfo: match[3],
				Revision:   strings.TrimSpace(match[4]),
				ProgIf:     strings.TrimSpace(match[5]),
			}
			current.Raw = line + "\n"
			continue
		}

		if current != nil {
			current.Raw += line + "\n"
			line = strings.TrimSpace(line)

			switch {
			case strings.HasPrefix(line, "DeviceName:"):
				current.DeviceName = strings.TrimPrefix(line, "DeviceName: ")
			case strings.HasPrefix(line, "Control:"):
				current.Control = strings.TrimPrefix(line, "Control: ")
			case strings.HasPrefix(line, "Status:"):
				current.Status = strings.TrimPrefix(line, "Status: ")
			case strings.HasPrefix(line, "Latency:"):
				current.Latency = strings.TrimPrefix(line, "Latency: ")
			case strings.HasPrefix(line, "Interrupt:"):
				current.Interrupt = strings.TrimPrefix(line, "Interrupt: ")
			case strings.HasPrefix(line, "IOMMU group:"):
				current.IOMMUGroup = strings.TrimPrefix(line, "IOMMU group: ")
			case strings.HasPrefix(line, "Kernel driver in use:"):
				current.KernelDriver = strings.TrimPrefix(line, "Kernel driver in use: ")
			case strings.HasPrefix(line, "Kernel modules:"):
				current.KernelModules = strings.TrimPrefix(line, "Kernel modules: ")
			case regionRegexp.MatchString(line):
				sub := regionRegexp.FindStringSubmatch(line)
				current.Regions = append(current.Regions, PCIRegion{
					Index:       futils.StrToInt(sub[1]),
					Description: sub[2],
				})
			}
		}
	}
	if current != nil {
		devices = append(devices, *current)
	}
	return devices
}

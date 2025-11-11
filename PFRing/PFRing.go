package PFRing

import (
	"fmt"
	"futils"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type PFringInfo struct {
	Enable                    int    `json:"enable"`
	Filename                  string `json:"filename"`
	Alias                     string `json:"alias"`
	Version                   string `json:"version"`
	Description               string `json:"description"`
	Author                    string `json:"author"`
	License                   string `json:"license"`
	SrcVersion                string `json:"srcversion"`
	Depends                   string `json:"depends"`
	Retpoline                 string `json:"retpoline"`
	Name                      string `json:"name"`
	Vermagic                  string `json:"vermagic"`
	MinNumSlots               string `json:"min_num_slots"`
	PerfectRulesHashSize      string `json:"perfect_rules_hash_size"`
	EnableTxCapture           string `json:"enable_tx_capture"`
	EnableFragCoherence       string `json:"enable_frag_coherence"`
	EnableIPDefrag            string `json:"enable_ip_defrag"`
	KeepVlanOffload           string `json:"keep_vlan_offload"`
	QuickMode                 string `json:"quick_mode"`
	ForceRingLock             string `json:"force_ring_lock"`
	EnableDebug               string `json:"enable_debug"`
	TransparentModeDeprecated string `json:"transparent_mode"`
}

func PFringSoPath() string {

	f := []string{"/usr/lib/suricata/pfring.so"}

	for _, fpath := range f {
		if futils.FileExists(fpath) {
			return fpath
		}
	}
	return "/usr/lib/suricata/pfring.so"
}

func Check() PFringInfo {
	var Mod PFringInfo
	kernel := futils.KernelVersion()
	log.Debug().Msgf("%v kernel version: %v", futils.GetCalleRuntime(), kernel)
	koPath := fmt.Sprintf("/usr/lib/modules/%v/kernel/net/pf_ring/pf_ring.ko", kernel)
	if !futils.FileExists(koPath) {
		Mod.Enable = 0
		log.Warn().Msgf("%v %v no such module...", futils.GetCalleRuntime(), koPath)
		return Mod
	}
	modinfo := futils.FindProgram("modinfo")
	err, out := futils.ExecuteShell(fmt.Sprintf("%s pf_ring", modinfo))
	if err != nil {
		log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), out)
		if strings.Contains(out, "pf_ring not found") {
			err := futils.RunDepmod()
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			}
		}
		modprobe := futils.FindProgram("modprobe")
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v pf_ring transparent_mode=0 min_num_slots=32768", modprobe))
		modinfo := futils.FindProgram("modinfo")
		err, out = futils.ExecuteShell(fmt.Sprintf("%s pf_ring", modinfo))
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), out)
			Mod.Enable = 0
			return Mod
		}

	}
	log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), out)
	Mod, err = parseModuleInfo(out)
	if err != nil {
		Mod.Enable = 0
		return Mod
	}
	Mod.Enable = 1
	return Mod
}
func parseModuleInfo(data string) (PFringInfo, error) {
	lines := strings.Split(data, "\n")
	module := PFringInfo{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "filename":
			module.Filename = value
		case "alias":
			module.Alias = value
		case "version":
			module.Version = value
		case "description":
			module.Description = value
		case "author":
			module.Author = value
		case "license":
			module.License = value
		case "srcversion":
			module.SrcVersion = value
		case "depends":
			module.Depends = value
		case "retpoline":
			module.Retpoline = value
		case "name":
			module.Name = value
		case "vermagic":
			module.Vermagic = value
		case "parm":
			if strings.Contains(value, "Min number of ring slots") {
				module.MinNumSlots = value
			} else if strings.Contains(value, "Perfect rules hash size") {
				module.PerfectRulesHashSize = value
			} else if strings.Contains(value, "capture outgoing packets") {
				module.EnableTxCapture = value
			} else if strings.Contains(value, "handle fragments") {
				module.EnableFragCoherence = value
			} else if strings.Contains(value, "enable IP defragmentation") {
				module.EnableIPDefrag = value
			} else if strings.Contains(value, "keep vlan stripping") {
				module.KeepVlanOffload = value
			} else if strings.Contains(value, "run at full speed") {
				module.QuickMode = value
			} else if strings.Contains(value, "force ring locking") {
				module.ForceRingLock = value
			} else if strings.Contains(value, "enable PF_RING debug") {
				module.EnableDebug = value
			} else if strings.Contains(value, "(deprecated)") {
				module.TransparentModeDeprecated = value
			}
		}
	}

	return module, nil
}
func Unload() bool {

	if !futils.IsModulesLoaded("pf_ring") {
		return true
	}

	rmmod := futils.FindProgram("rmmod")
	cmdline := fmt.Sprintf("%v pf_ring", rmmod)

	err, out := futils.ExecuteShell(cmdline)
	if err != nil {
		log.Error().Msgf("%v [%v]", futils.GetCalleRuntime(), out)
		return true

	}

	for i := 0; i < 5; i++ {
		if !futils.IsModulesLoaded("pf_ring") {
			break
		}
		_, _ = futils.ExecuteShell(cmdline)
		time.Sleep(1 * time.Second)
	}
	return true

}

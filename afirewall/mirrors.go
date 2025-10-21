package afirewall

import (
	"afirewall/aFirewallTools"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"ipclass"
	"strings"
)

func BuildMirroredInterfaces() {
	Interfaces := ipclass.AllInterfacesFromDB()
	TEERemoveAll()
	for _, Interface := range Interfaces {
		if Interface.Mirror == 0 {
			continue
		}
		log.Info().Msgf("%v Create TEE rule for %v", futils.GetCalleRuntime(), Interface.Interface)
		err := TEEAdd(Interface.Interface, Interface.Mirrorgateway)
		if err != nil {
			log.Error().Msgf("%v Create TEE %v Interface failed: %v", futils.GetCalleRuntime(), Interface.Interface, err.Error())
			continue
		}
	}
}
func TEERemoveAll() {
	Comment := "comment TEE_"
	Dump, _ := aFirewallTools.GetCurrentIPTablesRules()
	tb := strings.Split(Dump, "\n")
	ToUpdate := false
	var NewLines []string
	for _, line := range tb {
		if strings.Contains(line, Comment) {
			ToUpdate = true
			continue
		}
		NewLines = append(NewLines, line)
	}
	if !ToUpdate {
		return
	}
	_ = aFirewallTools.IPTablesRestore(strings.Join(NewLines, "\n"))
}
func TEERemove(IfaceName string) {
	Comment := fmt.Sprintf("TEE_%v", IfaceName)
	Dump, _ := aFirewallTools.GetCurrentIPTablesRules()
	tb := strings.Split(Dump, "\n")
	ToUpdate := false
	var NewLines []string
	for _, line := range tb {
		if strings.Contains(line, Comment) {
			ToUpdate = true
			continue
		}
		NewLines = append(NewLines, line)
	}
	if !ToUpdate {
		return
	}
	_ = aFirewallTools.IPTablesRestore(strings.Join(NewLines, "\n"))
}
func TEEAdd(InterfaceName string, gateway string) error {
	iptables := futils.FindProgram("iptables")
	xprefix := fmt.Sprintf("%v -t mangle -I PREROUTING -i %v", iptables, InterfaceName)
	xprefix2 := fmt.Sprintf("%v -t mangle -I POSTROUTING -o %v", iptables, InterfaceName)
	Comment := fmt.Sprintf("-m comment --comment \"TEE_%v\"", InterfaceName)
	err, out := futils.ExecuteShell(fmt.Sprintf("%v -j TEE --gateway %v %v", xprefix, gateway, Comment))
	if err != nil {
		log.Error().Msgf("%v TEE add iptables failed: %v", futils.GetCalleRuntime(), out)
		return err
	}
	err, out = futils.ExecuteShell(fmt.Sprintf("%v -j TEE --gateway %v %v", xprefix2, gateway, Comment))
	if err != nil {
		log.Error().Msgf("%v TEE add iptables failed: %v", futils.GetCalleRuntime(), out)
		return err
	}
	return nil
}

package afirewall

import (
	"afirewall/aFirewallTools"
	"fmt"
	"futils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog/log"
	"regexp"
	"strings"
)

func IsGroupN(GroupName string) bool {
	var RegexChain = regexp.MustCompile(fmt.Sprintf(`Chain\s+%v.*?references`, GroupName))
	iptablesBin := futils.FindProgram("iptables")
	_, out := futils.ExecuteShell(fmt.Sprintf("%v -L", iptablesBin))
	Results := strings.Split(out, "\n")
	for _, line := range Results {

		if futils.RegexFind(RegexChain, line) {
			log.Info().Msgf("%v found %v in %v OK", futils.GetCalleRuntime(), GroupName, line)
			return true
		}
		log.Debug().Msgf("%v UNKNOWN %v in [%v]", futils.GetCalleRuntime(), GroupName, line)
	}
	log.Warn().Msgf("%v %v not found in %v lines", futils.GetCalleRuntime(), GroupName, len(Results))
	return false
}
func GetIptablesArray() []string {
	Temp, _ := aFirewallTools.GetCurrentIPTablesRules()
	return strings.Split(Temp, "\n")
}

func countIptablesRules(table, chain string) (int, error) {
	ipt, err := iptables.New()
	if err != nil {
		return 0, fmt.Errorf("could not initialize iptables: %v", err)
	}
	rules, err := ipt.List(table, chain)
	if err != nil {
		return 0, fmt.Errorf("could not list rules in table %s chain %s: %v", table, chain, err)
	}
	ruleCount := len(rules) - 1

	return ruleCount, nil
}

func CountOfRules() int {
	chains := []string{"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"}
	iptables_save := futils.FindProgram("iptables-save")
	_, out := futils.ExecuteShell(iptables_save)
	tb := strings.Split(out, "\n")
	var BigTot int

	for _, table := range tb {

		for _, chain := range chains {
			if strings.Contains(strings.ToLower(table), strings.ToLower(chain)) {
				BigTot++
			}
		}

	}
	return BigTot
}

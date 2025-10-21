package Rules

import (
	"IfacesStruct"
	"fmt"
	"futils"
	"ipclass"
	"iproutes"

	"github.com/rs/zerolog/log"
)

func ExtractFirewallRuleNextHope(rule IptablesRules, GbCommands []string) (string, string, []string) {
	iptables := futils.FindProgram("iptables")

	ID := rule.ID
	MARK := 1024 + ID

	RoutingTableName := fmt.Sprintf("RouteMark%d", MARK)
	if !ipclass.IsIPAddress(rule.ForwardTo) {
		log.Warn().Msgf("%v Rule %d mark %d ForwardTo %v Unable to create rt_tables %v", futils.GetCalleRuntime(), ID, MARK, rule.ForwardTo, "Not a gateway address")
		return "", "", GbCommands
	}

	rtTablesId := 1000 + ID
	err := iproutes.CreatTable(rtTablesId, RoutingTableName)
	if err != nil {
		log.Warn().Msgf("%v Rule %d mark %d ForwardTo %v Unable to create rt_tables %v", futils.GetCalleRuntime(), ID, MARK, rule.ForwardTo, err.Error())
		return "", "", GbCommands
	}
	err = iproutes.AddDefaultToTable(IfacesStruct.RouteConfig{
		Metric:  0,
		Gateway: rule.ForwardTo,
		Iface:   rule.Iface,
		Table:   rtTablesId,
	})
	if err != nil {
		log.Error().Msgf("%v Rule %d mark %d ForwardTo %v table ID %d Unable to create route %v", futils.GetCalleRuntime(), ID, MARK, rule.ForwardTo, rtTablesId, err.Error())
		return "", "", GbCommands
	}

	log.Debug().Msgf("%v ID:%d Mark %d", futils.GetCalleRuntime(), ID, MARK)

	//iptables -t mangle -A PREROUTING -p tcp --dport 80 -j MARK --set-mark 1
	//iptables -t mangle -A PREROUTING -p tcp --dport 443 -j MARK --set-mark 1

	FINAL := fmt.Sprintf("-j MARK --set-mark %v", MARK)
	xprefix := fmt.Sprintf("%v -t mangle -A PREROUTING", iptables)
	return xprefix, FINAL, GbCommands
}

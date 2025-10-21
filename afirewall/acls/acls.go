package acls

import (
	"GlobalAcls"
	"afirewall/Rules"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"strings"
)

func BuildRuleSourcesDest(rule Rules.IptablesRules, direction int) []Rules.AclsRules {

	IPFEED_PATH := "/home/artica/firewall/CyberCrimeNet.txt"
	var Returned []Rules.AclsRules
	direction_name := make(map[int]string)
	direction_name[0] = "inbound"
	direction_name[1] = "outbound"
	NameGroupTypeS := make(map[int]string)
	NameGroupTypeS[0] = "src"
	NameGroupTypeS[1] = "dst"
	IpSetPrefix := ""

	IpSetTypeTxt := make(map[string]string)
	IpSetTypeTxt["src"] = "src"
	IpSetTypeTxt["dst"] = "dst"
	IpSetTypeTxt["arp"] = "src"

	IpSetDestDir := fmt.Sprintf("/home/artica/firewall/groups/rule.%d/%v", rule.ID, direction_name[direction])
	futils.RmRF(IpSetDestDir)
	futils.CreateDir(IpSetDestDir)
	if direction == 0 {
		IpSetPrefix = "Inbound"
		IpSetTypeTxt["fwgeo"] = "src"
		IpSetTypeTxt["teamviewer"] = "src"
		IpSetTypeTxt["whatsapp"] = "src"
		IpSetTypeTxt["office365"] = "src"
		IpSetTypeTxt["facebook"] = "src"
		IpSetTypeTxt["skype"] = "src"
		IpSetTypeTxt["google"] = "src"
		IpSetTypeTxt["localnet"] = "src"

		if rule.MOD == "IPFEED" {
			var record Rules.AclsRules
			record.DataPath = IPFEED_PATH
			record.IPsetName = "CyberCrimeIP"
			record.ExRule = groupSrcip(record.IPsetName, "src")
			if !futils.FileExists(IPFEED_PATH) {
				var f []string
				f = append(f, "create CyberCrimeIP hash:net family inet hashsize 16384 maxelem 1500000")
				_ = futils.FilePutContents(IPFEED_PATH, strings.Join(f, "\n"))

			}
			Returned = append(Returned, record)
		}
		log.Debug().Msgf("%v Get Object for Rule %d and Direction=%d", futils.GetCalleRuntime(), rule.ID, direction)

	}

	//AclGroupTypeFirewall := GlobalAcls.AclGroupTypeFirewallIn()
	if direction == 1 {
		IpSetTypeTxt["fwgeo"] = "dst"
		IpSetTypeTxt["teamviewer"] = "dst"
		IpSetTypeTxt["whatsapp"] = "dst"
		IpSetTypeTxt["office365"] = "dst"
		IpSetTypeTxt["facebook"] = "dst"
		IpSetTypeTxt["skype"] = "dst"
		IpSetTypeTxt["google"] = "dst"
		IpSetTypeTxt["localnet"] = "dst"
		IpSetPrefix = "Outbound"
		//	AclGroupTypeFirewall = GlobalAcls.AclGroupTypeFirewallOut()
	}
	objects := GlobalAcls.ListFirewallObjects(rule.ID, direction)
	groupir := make(map[string][]GlobalAcls.AclObject)

	for _, object := range objects {
		log.Debug().Msgf("%v Object: %v Type:%v Negation:%d", futils.GetCalleRuntime(), object.GroupName, object.GroupType, object.Negation)
		if object.Negation == 0 {
			groupir[object.GroupType] = append(groupir[object.GroupType], object)
		}
	}

	// Une fois les objets groupés par type, on construit les IPSets

	for IpSetType, Groups := range groupir {
		var IpSetFile []string
		HType := "net"
		Family := " family inet"
		if IpSetType == "arp" {
			HType = "mac"
			Family = ""
		}
		log.Info().Msgf("%v [%v]: rule:%d (returned=%d)", futils.GetCalleRuntime(), IpSetType, rule.ID, len(Returned))
		// Si l'object est geoip, alors on construit la règle et on continue.
		log.Info().Msgf("%v [%d] Type=<%v>", futils.GetCalleRuntime(), rule.ID, IpSetType)
		if IpSetType == "geoip" {
			var record Rules.AclsRules
			record.DataPath = ""
			record.IPsetName = ""
			// on ne peut pas grouper les groupes car certains peuvent $etre négatifs
			Returned = groupsGeoIP(Returned, Groups, direction)
			log.Info().Msgf("%v [GeoIP]: Get Object for Rule %d (%d items)", futils.GetCalleRuntime(), rule.ID, len(Returned))
			continue
		}

		// Le nom de l'ipset va être l'interface+ Flux + type + l'ID de la règle
		IpSetName := fmt.Sprintf("Group%v%v%v%d", strings.ReplaceAll(rule.Iface, ":", ""), IpSetPrefix, IpSetType, rule.ID)
		log.Debug().Msgf("%v Compile: %v IPSET Type: %v-->%v", futils.GetCalleRuntime(), IpSetName, IpSetType, HType)
		IpSetFile = append(IpSetFile, fmt.Sprintf("create %v hash:%v%v -exist", IpSetName, HType, Family))
		IpSetFile = append(IpSetFile, fmt.Sprintf("flush %v", IpSetName))
		for _, Group := range Groups {
			nomatch := ""
			if Group.Negation == 1 {
				nomatch = " nomatch"
			}
			for _, item := range Group.Items {
				IpSetFile = append(IpSetFile, fmt.Sprintf("add %v %v%v -exist", IpSetName, item, nomatch))
			}
		}
		IpSetFileName := fmt.Sprintf("%v/%v.ipset", IpSetDestDir, IpSetName)
		_ = futils.FilePutContents(IpSetFileName, strings.Join(IpSetFile, "\n"))
		var record Rules.AclsRules
		record.DataPath = IpSetFileName
		record.IPsetName = IpSetName
		record.ExRule = groupSrcip(record.IPsetName, IpSetTypeTxt[IpSetType])
		log.Debug().Msgf("%v Restoring %v", futils.GetCalleRuntime(), IpSetFileName)
		cmd := fmt.Sprintf("/sbin/ipset restore -! < %v", IpSetFileName)
		err, out := futils.ExecuteShell(cmd)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), out)
			continue
		}
		Returned = append(Returned, record)
		log.Info().Msgf("%v Get Object for Rule %d (%d items)", futils.GetCalleRuntime(), rule.ID, len(Returned))
	}
	log.Info().Msgf("%v [ENDLOOP] Get Object for Rule %d (%d items)", futils.GetCalleRuntime(), rule.ID, len(Returned))
	return Returned
}
func groupSrcip(groupname string, dir string) string {
	if len(dir) < 2 {
		dir = "src"
	}
	return fmt.Sprintf("-m set --match-set %v %v", groupname, dir)
}

func groupsGeoIP(returned []Rules.AclsRules, Groups []GlobalAcls.AclObject, direction int) []Rules.AclsRules {

	token := "--src-cc"

	if direction == 1 {
		token = "--dst-cc"
	}

	GroupingNeg := make(map[string]bool)
	GroupingPos := make(map[string]bool)

	//On groupe par négation pour éviter les doublons.
	for _, Group := range Groups {

		if Group.Negation == 1 {
			for _, item := range Group.Items {

				DBPath := fmt.Sprintf("/usr/share/xt_geoip/%v.iv4", strings.ToUpper(item))
				if !futils.FileExists(DBPath) {
					continue
				}
				zPattern := fmt.Sprintf("-m geoip ! %v %v", token, strings.ToUpper(item))
				GroupingNeg[zPattern] = true

			}
			continue
		}
		for _, item := range Group.Items {
			DBPath := fmt.Sprintf("/usr/share/xt_geoip/%v.iv4", strings.ToUpper(item))
			if !futils.FileExists(DBPath) {
				continue
			}
			zPattern := fmt.Sprintf("-m geoip %v %v", token, strings.ToUpper(item))
			GroupingPos[zPattern] = true
		}

	}

	if len(GroupingNeg) == 0 && len(GroupingPos) == 0 {
		return returned
	}
	// on vérifie si le module x_geo est bien installé...
	if !xtGeoIPModule() {
		return returned
	}
	// On commence par les négations

	if len(GroupingNeg) > 0 {
		for line, _ := range GroupingNeg {
			var record Rules.AclsRules
			record.DataPath = ""
			record.IPsetName = ""
			record.ExRule = line
			returned = append(returned, record)
		}
	}
	if len(GroupingPos) > 0 {
		for line, _ := range GroupingPos {
			var record Rules.AclsRules
			record.DataPath = ""
			record.IPsetName = ""
			record.ExRule = line
			returned = append(returned, record)
		}
	}
	log.Info().Msgf("%v objects are %d rows", futils.GetCalleRuntime(), len(returned))
	// On renvoi les règles
	return returned
}
func xtGeoIPModule() bool {
	ModulePath := "/etc/modules-load.d/xt_geoip.conf"
	kernel := futils.KernelVersion()
	xtGeoip := fmt.Sprintf("/usr/lib/modules/%v/extra/xt_geoip.ko", kernel)
	if !futils.FileExists(xtGeoip) {
		log.Error().Msgf("%v %v no such kernel module", xtGeoip)
		return false
	}

	if futils.IsModulesLoaded("xt_geoip") {
		return true
	}
	err := futils.RunDepmod()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}

	err = futils.RunModeProbe("xt_geoip")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}

	if !futils.IsModulesLoaded("xt_geoip") {
		log.Error().Msgf("%v xt_geoip connot be loaded", futils.GetCalleRuntime())
		futils.DeleteFile(ModulePath)
		return true
	}

	_ = futils.FilePutContents(ModulePath, "xt_geoip\n")
	return true
}

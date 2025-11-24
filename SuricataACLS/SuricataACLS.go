package SuricataACLS

import (
	"SqliteConns"
	"SuricataACLS/CheckArule"
	"SuricataACLS/DomainsGrouping"
	"SuricataACLS/PortsGrouping"
	"bufio"
	"database/sql"
	"fmt"
	"futils"
	"ipclass"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type SuriACLS struct {
	ID                        int    `json:"ID"`
	Name                      string `json:"Name"`
	Rules                     string `json:"Rules"`
	ApplayerProtocol          string `json:"ApplayerProtocol"`
	Target                    string `json:"Target"`
	Enabled                   int    `json:"Enabled"`
	Type                      string `json:"Type"`
	Priority                  int    `json:"Priority"`
	Action                    string `json:"Action"`
	Source                    string `json:"Source"`
	ExplainSource             string `json:"ExplainSource"`
	DestinationExpl           string `json:"ExplainDestination"`
	Destination               string `json:"Destination"`
	DestinationPorts          string `json:"DestinationPorts"`
	DestinationPortsExplain   string `json:"DestinationPortsExplain"`
	DestinationDomains        string `json:"DestinationDomains"`
	DestinationDomainsExplain string `json:"DestinationDomainsExplain"`
	DestinationGEO            string `json:"DestinationGEO"`
	DestinationGEOExplain     string `json:"DestinationGEOExplain"`
	SourceGEO                 string `json:"SourceGEO"`
	SourceGEOExplain          string `json:"SourceGEOExplain"`
	Direction                 int    `json:"Direction"`
	Count                     int    `json:"Count"`
	Seconds                   int    `json:"Seconds"`
	Proto                     string `json:"Proto"`
	Flow                      string `json:"Flow"`
	Classtype                 string `json:"Classtype"`
	Created                   int64  `json:"Created"`
	ITypes                    string `json:"ITypes"`
	ITypesExplain             string `json:"ITypesExplain"`
}

func GetACLs() []SuriACLS {

	db, err := SqliteConns.AclsConnectRO()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []SuriACLS{}
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	rows, err := db.Query("SELECT ID,aclname,proto,ApplayerProtocol,enabled,count,seconds,target,flow,classtype,action,priority,direction,created FROM suricata_sqacls ORDER BY xORDER")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []SuriACLS{}
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var tables []SuriACLS
	for rows.Next() {
		var acl SuriACLS
		var Priority sql.NullString
		if err := rows.Scan(&acl.ID, &acl.Name, &acl.Proto, &acl.ApplayerProtocol, &acl.Enabled, &acl.Count, &acl.Seconds, &acl.Target, &acl.Flow, &acl.Classtype, &acl.Action, &Priority, &acl.Direction, &acl.Created); err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		acl.Priority = futils.StrToInt(Priority.String)
		if acl.Priority == 0 {
			acl.Priority = 1
		}
		acl.Source, acl.ExplainSource = aclsGroup(acl.ID, "src")
		acl.Destination, acl.DestinationExpl = aclsGroup(acl.ID, "dst,dstserv")
		log.Info().Msgf("%v ACL %v DEST=(%v)", futils.GetCalleRuntime(), acl.Name, acl.Destination)
		acl.DestinationDomains, acl.DestinationDomainsExplain = aclsGroup(acl.ID, "dstdomain")
		acl.DestinationPorts, acl.DestinationPortsExplain = aclsGroup(acl.ID, "port")
		acl.DestinationGEO, acl.DestinationGEOExplain = aclsGroup(acl.ID, "geoipdest")
		acl.SourceGEO, acl.SourceGEOExplain = aclsGroup(acl.ID, "geoipsrc")
		acl.ITypes, acl.ITypesExplain = aclsGroup(acl.ID, "itype")
		tables = append(tables, acl)
	}
	return tables
}
func aclsGroup(aclid int, GroupType string) (string, string) {

	OnMouse := `onmouseover="this.style.cursor='pointer';this.style.color='#337AB7'" onmouseout="this.style.cursor='default';this.style.color=''" style="border-bottom: 1px solid rgb(204, 204, 204); font-weight: bold; cursor: default;"`

	db, err := SqliteConns.AclsConnectRO()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return "", fmt.Sprintf("<span class='text-danger'>Error %v</span>", err.Error())
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	FilterGroup := fmt.Sprintf("webfilters_sqgroups.GroupType='%v'", GroupType)
	if strings.Contains(GroupType, ",") {
		zgrp := strings.Split(GroupType, ",")
		var tb []string
		for _, Gptype := range zgrp {
			tb = append(tb, fmt.Sprintf("webfilters_sqgroups.GroupType='%v'", Gptype))
		}
		FilterGroup = fmt.Sprintf("( %v )", strings.Join(tb, " OR "))
	}

	log.Debug().Msgf("%v Query GroupType:%v from rule id %d", futils.GetCalleRuntime(), GroupType, aclid)
	query := fmt.Sprintf(`SELECT suricata_sqacllinks.negation,suricata_sqacllinks.gpid,webfilters_sqgroups.GroupName,webfilters_sqgroups.GroupType FROM suricata_sqacllinks,webfilters_sqgroups WHERE 
				suricata_sqacllinks.gpid=webfilters_sqgroups.ID
			    AND webfilters_sqgroups.enabled=1
				AND %v AND aclid=? ORDER BY zOrder`, FilterGroup)

	log.Debug().Msgf("%v Query [%v]", futils.GetCalleRuntime(), query)
	rows, err := db.Query(query, aclid)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return "", fmt.Sprintf("<span class='text-danger'>Error %v</span>", err.Error())
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var positif []string
	var negatif []string
	var explanations []string

	for rows.Next() {
		var gpid int
		var GroupName string
		var negation sql.NullInt32
		var GroupType string

		err := rows.Scan(&negation, &gpid, &GroupName, &GroupType)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		GroupName = futils.Latin1ToUTF8([]byte(GroupName))
		log.Debug().Msgf("%v Query Group GroupType:%v [%v] id %d", futils.GetCalleRuntime(), GroupType, GroupName, gpid)

		if negation.Int32 == 0 {
			explanations = append(explanations, fmt.Sprintf("<span %v OnClick=\"Loadjs('fw.rules.items.php?groupid=%d&TableLink=suricata_sqacllinks&IDS=1');\">%v ({%v})</span>", OnMouse, gpid, GroupName, GroupType))
			positif = append(positif, fmt.Sprintf("%v|%v", gpid, GroupType))
			continue
		}
		explanations = append(explanations, fmt.Sprintf("<span %v OnClick=\"Loadjs('fw.rules.items.php?groupid=%d&TableLink=suricata_sqacllinks&IDS=1');\">{not} %v ({%v})</span>", OnMouse, gpid, GroupName, GroupType))
		negatif = append(negatif, fmt.Sprintf("%v|%v", gpid, GroupType))
	}
	NumberOfGroups := 0
	Clean1 := make(map[string]bool)
	Clean2 := make(map[string]bool)
	var final []string
	var Items []string

	for _, gpidPattern := range positif {
		NumberOfGroups++
		tb := strings.Split(gpidPattern, "|")
		GroupType := tb[1]
		gpid := futils.StrToInt(tb[0])
		log.Info().Msgf("%v find items for Group id:%d (%v) = \"%v\"", futils.GetCalleRuntime(), gpid, GroupType, gpidPattern)

		if GroupType == "dstserv" {
			Items = append(Items, `$SERVER_IP`)
		}

		if GroupType == "dst" || GroupType == "src" {
			Items = getItemsNetworkFromGpid(db, gpid)
			log.Debug().Msgf("%v find items for Group %d %v = %d", futils.GetCalleRuntime(), gpid, GroupType, len(Items))
		}
		if GroupType == "port" {
			Items = getItemsPortsFromGpid(db, gpid, 0)
		}
		if GroupType == "dstdomain" {
			Items = getItemsDomainsFromGpid(db, gpid)
		}
		if GroupType == "geoipsrc" {
			Items = getItemsGeoFromGpid(db, gpid)
		}
		if GroupType == "itype" {
			Items = getItemsIntegerFromGpid(db, gpid)
		}

		for _, item := range Items {
			log.Debug().Msgf("%v Cleaning %v", futils.GetCalleRuntime(), item)
			Clean1[item] = true
		}
	}

	for _, gpidPattern := range negatif {
		NumberOfGroups++
		tb := strings.Split(gpidPattern, "|")
		GroupType := tb[1]
		gpid := futils.StrToInt(tb[0])

		if GroupType == "dstserv" {
			Items = append(Items, `!$SERVER_IP`)
		}

		if GroupType == "dst" || GroupType == "src" {
			Items = getItemsNetworkFromGpid(db, gpid)
			log.Debug().Msgf("%v NEGATIVE Group %d %v Items %v", futils.GetCalleRuntime(), gpid, GroupType, len(Items))
		}
		if GroupType == "port" {
			Items = getItemsPortsFromGpid(db, gpid, 1)
		}
		if GroupType == "geoipsrc" || GroupType == "geoipdest" {
			Items = getItemsGeoFromGpid(db, gpid)
		}

		if GroupType == "itype" {
			Items = getItemsIntegerFromGpid(db, gpid)
		}

		for _, item := range Items {
			log.Debug().Msgf("%v Cleaning !%v", futils.GetCalleRuntime(), item)
			Clean2["!"+item] = true
		}
	}
	if len(Clean1) > 0 {
		for k := range Clean1 {
			final = append(final, k)
		}
	}
	if len(Clean2) > 0 {
		for k := range Clean2 {
			final = append(final, k)
		}
	}
	log.Debug().Msgf("%v GroupType:%v Items %v --> {%v}", futils.GetCalleRuntime(), GroupType, strings.Join(positif, ","), final)
	if GroupType == "dst" || GroupType == "src" || GroupType == "dstserv" || GroupType == "dst,dstserv" {
		if len(final) == 0 {
			log.Debug().Msgf("%v finally, no items after %d groups", futils.GetCalleRuntime(), NumberOfGroups)
			return "", ""
		}
		log.Debug().Msgf("%v finally, %v after %d groups", futils.GetCalleRuntime(), strings.Join(final, ","), NumberOfGroups)
		if len(final) == 1 {
			return final[0], strings.Join(explanations, " {or} ")
		}
		return "[" + strings.Join(final, ",") + "]", strings.Join(explanations, " {or} ")
	}
	if GroupType == "port" {
		if len(final) == 0 {
			return "", ""
		}
		R := PortsGrouping.GroupPorts(final)
		log.Debug().Msgf("%v %v Items %v --> {%v}", futils.GetCalleRuntime(), GroupType, strings.Join(final, ","), R)
		return R, strings.Join(explanations, " {or} ")
	}
	if GroupType == "dstdomain" {
		if len(final) == 0 {
			return "", ""
		}
		R := DomainsGrouping.Build(aclid, final)
		if len(R) > 0 {
			return R, strings.Join(explanations, " {or} ")
		}
		return "", ""
	}
	if GroupType == "geoipsrc" || GroupType == "geoipdest" {
		if len(final) == 0 {
			return "", ""
		}
		R := DomainsGrouping.BuildGeoIP(final, GroupType)
		if len(R) > 0 {
			return R, strings.Join(explanations, " {and} ")
		}
		return "", ""
	}
	if GroupType == "itype" {
		if len(final) == 0 {
			return "", ""
		}
		R := DomainsGrouping.BuiliTypes(final)
		if len(R) > 0 {
			return R, strings.Join(explanations, " {and} ")
		}
		return "", ""
	}

	return "", ""
}
func getItemsPortsFromGpid(db *sql.DB, gpid int, ExpandPorts int) []string {
	query := `SELECT pattern FROM webfilters_sqitems WHERE gpid=? and enabled=1`
	rows, err := db.Query(query, gpid)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []string{}
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var r []string
	for rows.Next() {
		var pattern sql.NullString
		err := rows.Scan(&pattern)
		if err != nil {
			continue
		}
		Pattern := strings.TrimSpace(pattern.String)
		if len(Pattern) == 0 {
			continue
		}
		// if there is "-" in the port and parts are numeric, we consider it as a range
		if strings.Contains(Pattern, "-") {
			tb := strings.Split(Pattern, "-")
			if len(tb) < 2 {
				continue
			}
			if !futils.IsNumeric(tb[0]) || !futils.IsNumeric(tb[1]) {
				continue
			}
			if ExpandPorts == 1 {
				// For negative ports, we expand it..
				tb := PortsGrouping.ExpandPortRange(Pattern)
				if tb == nil {
					continue
				}
				for _, port := range tb {
					r = append(r, futils.IntToString(port))
				}
				continue
			}

			r = append(r, Pattern)
			continue
		}
		if !futils.IsNumeric(Pattern) {
			continue
		}
		r = append(r, Pattern)
	}

	return r
}
func getItemsNetworkFromGpid(db *sql.DB, gpid int) []string {
	query := `SELECT pattern FROM webfilters_sqitems WHERE gpid=? and enabled=1`

	rows, err := db.Query(query, gpid)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []string{}
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var r []string
	for rows.Next() {
		var pattern sql.NullString
		err := rows.Scan(&pattern)
		if err != nil {
			continue
		}
		Pattern := strings.TrimSpace(pattern.String)
		if len(Pattern) < 3 {
			continue
		}

		if !ipclass.IsValidIPorCDIRorRange(Pattern) {
			continue
		}
		r = append(r, Pattern)
	}

	return r
}
func getItemsGeoFromGpid(db *sql.DB, gpid int) []string {
	query := `SELECT pattern FROM webfilters_sqitems WHERE gpid=? and enabled=1`
	rows, err := db.Query(query, gpid)

	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []string{}
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var r []string
	for rows.Next() {
		var pattern sql.NullString
		err := rows.Scan(&pattern)
		if err != nil {
			continue
		}
		Pattern := strings.TrimSpace(pattern.String)
		if len(Pattern) < 2 {
			continue
		}

		Pattern = strings.ToUpper(Pattern)

		r = append(r, Pattern)
	}

	return r
}
func getItemsIntegerFromGpid(db *sql.DB, gpid int) []string {
	query := `SELECT pattern FROM webfilters_sqitems WHERE gpid=? and enabled=1`

	rows, err := db.Query(query, gpid)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []string{}
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var r []string
	for rows.Next() {
		var pattern sql.NullString
		err := rows.Scan(&pattern)
		if err != nil {
			continue
		}
		Pattern := strings.TrimSpace(pattern.String)
		if !futils.IsNumeric(Pattern) {
			continue
		}
		r = append(r, Pattern)
	}

	return r
}
func getItemsDomainsFromGpid(db *sql.DB, gpid int) []string {
	query := `SELECT pattern FROM webfilters_sqitems WHERE gpid=? and enabled=1`

	rows, err := db.Query(query, gpid)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []string{}
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var r []string
	for rows.Next() {
		var pattern sql.NullString
		err := rows.Scan(&pattern)
		if err != nil {
			continue
		}
		Pattern := strings.TrimSpace(pattern.String)
		if len(Pattern) < 3 {
			continue
		}
		if strings.HasPrefix("regex:", Pattern) {
			continue
		}
		Pattern = strings.TrimPrefix(Pattern, "^")

		r = append(r, Pattern)
	}

	return r
}
func SetACLsExplain() {
	Acls := GetACLs()
	explain := make(map[int]string)

	prios := make(map[int]string)
	prios[0] = "{none}"
	prios[1] = "{ids_prio_1}"
	prios[2] = "{medium}"
	prios[3] = "{low}"
	prios[4] = "{info}"

	Direction := make(map[int]string)
	Direction[0] = "{one_direction_only}"
	Direction[1] = "{both_stateful}"

	if len(Acls) == 0 {
		log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), "No ACLs")
		return
	}

	for _, acl := range Acls {
		var f []string
		var final []string
		var zobjetcs []string
		log.Debug().Msgf("%v (%d) %v", futils.GetCalleRuntime(), acl.ID, acl.Name)
		if acl.Action == "alert" {
			f = append(f, "{ids_prefix_1}: "+acl.Action+"<br>")
		} else {
			f = append(f, "{ids_prefix_2}: "+acl.Action+"<br>")
		}

		if acl.ExplainSource == "" {
			f = append(f, fmt.Sprintf("{network_traffic_from}: {all}"))
		} else {
			f = append(f, fmt.Sprintf("{network_traffic_from}: %v", acl.ExplainSource))
		}

		f = append(f, "&nbsp;<i class='fa fa-arrow-right'></i>&nbsp;")

		if acl.DestinationExpl == "" {
			f = append(f, fmt.Sprintf("{to_networks}: {all}"))
		} else {
			f = append(f, fmt.Sprintf("{to_networks}: %v", acl.DestinationExpl))
			if len(acl.DestinationPortsExplain) > 1 {
				f = append(f, fmt.Sprintf("{destination_port}: %v", acl.DestinationPortsExplain))
			}
		}
		f = append(f, fmt.Sprintf("(%v)", Direction[acl.Direction]))

		proto := "{all}"
		if len(acl.Proto) > 0 {
			if acl.Proto == "ip" {
				proto = "{all}"
			}
		}

		zobjetcs = append(zobjetcs, "{protocol} <strong>"+proto+"</strong>")

		if len(acl.ApplayerProtocol) > 0 {
			zobjetcs = append(zobjetcs, "{ApplicationLayerProtocol} <strong>"+acl.ApplayerProtocol+"</strong>")
		} else {
			zobjetcs = append(zobjetcs, "{ApplicationLayerProtocol} <strong>{all}</strong>")
		}
		if len(acl.Target) > 0 {
			zobjetcs = append(zobjetcs, "{Target} <strong>{"+acl.Target+"}</strong>")
		}
		if len(acl.Flow) > 0 {
			zobjetcs = append(zobjetcs, "{flow} <strong>{flow_"+acl.Flow+"}</strong>")
		} else {
			zobjetcs = append(zobjetcs, "{flow} <strong>{all}</strong>")
		}
		if len(acl.SourceGEOExplain) > 1 {
			zobjetcs = append(zobjetcs, "{geoipsrc} "+acl.SourceGEOExplain)
		}
		if len(acl.DestinationGEOExplain) > 1 {
			zobjetcs = append(zobjetcs, "{geoipdest} "+acl.DestinationGEOExplain)
		}
		if len(acl.ITypesExplain) > 1 {
			zobjetcs = append(zobjetcs, "{itype} "+acl.ITypesExplain)
		}

		if acl.Count > 1 && acl.Seconds > 0 {
			zobjetcs = append(zobjetcs, fmt.Sprintf("{OnlyAfter} %d {times} {during} %d {seconds}", acl.Count, acl.Seconds))
		}
		if acl.Action == "alert" {
			final = append(final, fmt.Sprintf("{ids_class_in}: <strong>"+acl.Classtype+"</strong>"))
			final = append(final, fmt.Sprintf("{ids_class_level}: <strong>%v</strong>", prios[acl.Priority]))
		}
		explain[acl.ID] = strings.Join(f, " ") + "&nbsp;" + strings.Join(zobjetcs, " {and} ") + "<br>{finally} " + strings.Join(final, " ")
	}

	db, err := SqliteConns.AclsConnectRW()
	if err != nil {
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	for id, exp := range explain {
		log.Debug().Msgf("%v UPDATE ID %v", futils.GetCalleRuntime(), id)
		_, err := db.Exec("UPDATE suricata_sqacls SET zExplain=? WHERE ID=?", exp, id)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
	}

}

func BuildACLs() []string {
	Acls := GetACLs()

	Targets := make(map[string]string)
	Targets["src"] = "src_ip"
	Targets["dst"] = "dest_ip"

	prioMeta := make(map[int]string)
	prioMeta[1] = "Major"
	prioMeta[2] = "Critical"
	prioMeta[3] = "Minor"
	prioMeta[4] = "Informational"

	AcceptedDomains := DomainsGrouping.AcceptedDomains()

	rows := make(map[int]string)
	var final []string

	for _, acl := range Acls {
		Sources := "any"
		Destinations := "any"
		DestinationsPorts := "any"
		var metadata []string

		if acl.Enabled == 0 {
			continue
		}
		proto := acl.Proto
		if proto == "" {
			proto = "ip"
		}
		if len(acl.ITypes) > 2 {
			proto = "icmp"
		}

		if len(acl.DestinationDomains) > 3 {
			if len(AcceptedDomains[proto]) == 0 {
				ztime := futils.TimeStampToString()
				rows[acl.ID] = "ERROR: " + ztime + " --> {protocol}: <" + acl.Proto + "> <-- {suricata_error_proto_not_accepted_domains}"
				continue
			}
		}
		if len(acl.DestinationGEO) > 3 && len(acl.SourceGEO) > 3 {
			ztime := futils.TimeStampToString()
			rows[acl.ID] = "ERROR: " + ztime + " --> {geo_not_mix_srcdst}"
			continue
		}

		metadata = append(metadata, fmt.Sprintf("signature_severity %v", prioMeta[acl.Priority]))
		if acl.Created > 0 {
			metadata = append(metadata, fmt.Sprintf("created_at %v", FormatTimestamp(acl.Created)))
		} else {
			metadata = append(metadata, fmt.Sprintf("created_at %v", FormatTimestamp(time.Now().Unix())))
		}
		metadata = append(metadata, fmt.Sprintf("artica_id %d", acl.ID))

		Dir := "->"

		if acl.Direction == 1 {
			Dir = "=>"
		}
		acl.Name = strings.ReplaceAll(acl.Name, `"`, "'")

		ruleSid := RuleSIDPrefix(acl.ID, 7100, 4)
		target := ""
		if len(acl.Target) > 0 {
			target = Targets[acl.Target]
		}

		if len(acl.Source) > 0 {
			Sources = acl.Source
		}
		log.Debug().Msgf("%v ACL %d %v Destination=[%v]", futils.GetCalleRuntime(), acl.ID, acl.Name, acl.Destination)
		if len(acl.Destination) > 0 {
			Destinations = acl.Destination
		}
		if len(acl.DestinationPorts) > 0 {
			DestinationsPorts = acl.DestinationPorts
		}
		prefix := acl.Action + " " + proto + fmt.Sprintf(" %s any %s %s %s", Sources, Dir, Destinations, DestinationsPorts)
		var opts []string
		if len(acl.ApplayerProtocol) > 0 && acl.ApplayerProtocol != acl.Proto {
			opts = append(opts, fmt.Sprintf("app-layer-protocol: %v", acl.ApplayerProtocol))
		}
		if len(acl.DestinationDomains) > 3 {
			opts = append(opts, DomainsGrouping.GetAcls(acl.Proto, acl.DestinationDomains))
		}

		if len(target) > 1 {
			opts = append(opts, fmt.Sprintf("target:%v", target))
		}
		if len(acl.Target) > 0 {
			opts = append(opts, acl.Target)
		}

		if len(acl.DestinationGEO) > 3 {
			opts = append(opts, acl.DestinationGEO)
		}
		if len(acl.SourceGEO) > 3 {
			opts = append(opts, acl.SourceGEO)
		}
		if len(acl.ITypes) > 2 {
			opts = append(opts, acl.ITypes)
		}

		if acl.Count > 1 && acl.Seconds > 0 {
			opts = append(opts, fmt.Sprintf("threshold:type limit, track by_src, count %d, seconds %d", acl.Count, acl.Seconds))
		}
		opts = append(opts, fmt.Sprintf("sid:%v", ruleSid))
		opts = append(opts, fmt.Sprintf("msg:\"%v\"", futils.Latin1ToUTF8([]byte(acl.Name))))
		opts = append(opts, fmt.Sprintf("priority:%d", acl.Priority))
		if len(acl.Flow) > 1 {
			// A voir flow:to_server,established
			opts = append(opts, fmt.Sprintf("flow:%v", acl.Flow))
		}
		opts = append(opts, fmt.Sprintf("rev:1"))
		// always at the end for ";"
		opts = append(opts, fmt.Sprintf("metadata:%v;", strings.Join(metadata, ", ")))
		FinalRule := fmt.Sprintf("%s (%s)", prefix, strings.Join(opts, "; "))
		FinalRule = strings.ReplaceAll(FinalRule, ";;", ";")
		rows[acl.ID] = FinalRule
		final = append(final, fmt.Sprintf("# P:%d", acl.ID))
		final = append(final, FinalRule)
	}

	db, err := SqliteConns.AclsConnectRW()
	if err != nil {
		return final
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	for id, exp := range rows {

		if strings.HasPrefix(exp, "ERROR") {
			_, err := db.Exec("UPDATE suricata_sqacls SET coded=?,iserror=1 WHERE ID=?", exp, id)
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			}
			continue
		}

		err := CheckArule.CheckRule(exp)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			_, err := db.Exec("UPDATE suricata_sqacls SET coded=?,iserror=1 WHERE ID=?", exp+"\n"+err.Error(), id)
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			}
			continue
		}

		log.Debug().Msgf("%v UPDATE ID %v with [%v]", futils.GetCalleRuntime(), id, exp)
		_, err = db.Exec("UPDATE suricata_sqacls SET coded=?,iserror=0 WHERE ID=?", exp, id)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
	}

	return final
}
func RuleSIDPrefix(id int, prefix int, pad int) string {
	format := fmt.Sprintf("%%d%%0%dd", pad)
	return fmt.Sprintf(format, prefix, id)
}
func FormatTimestamp(ts int64) string {
	t := time.Unix(ts, 0).Local()
	return t.Format("2006_01_02")
}
func LoadAdminRulePNumbers() map[int]bool {
	const rulesPath = "/etc/suricata/rules/Admin.rules"

	f, err := os.Open(rulesPath)
	if err != nil {
		return map[int]bool{}
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	pMap := make(map[int]bool)
	re := regexp.MustCompile(`^#\s*P\s*:\s*([0-9]+)`)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		pMap[n] = true
	}

	if err := scanner.Err(); err != nil {
		return pMap
	}

	return pMap
}

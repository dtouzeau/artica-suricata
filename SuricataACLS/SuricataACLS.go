package SuricataACLS

import (
	"SqliteConns"
	"database/sql"
	"fmt"
	"futils"
	"ipclass"
	"strings"

	"github.com/rs/zerolog/log"
)

type SuriACLS struct {
	ID               int    `json:"ID"`
	Name             string `json:"Name"`
	Rules            string `json:"Rules"`
	ApplayerProtocol string `json:"ApplayerProtocol"`
	Target           string `json:"Target"`
	Enabled          int    `json:"Enabled"`
	Type             string `json:"Type"`
	Priority         int    `json:"Priority"`
	Action           string `json:"Action"`
	Source           string `json:"Source"`
	ExplainSource    string `json:"ExplainSource"`
	DestinationExpl  string `json:"ExplainDestination"`
	Destination      string `json:"Destination"`
	Count            int    `json:"Count"`
	Seconds          int    `json:"Seconds"`
	Proto            string `json:"Proto"`
	Flow             string `json:"Flow"`
	Classtype        string `json:"Classtype"`
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
	rows, err := db.Query("SELECT ID,aclname,ApplayerProtocol,enabled,count,seconds,target,flow,classtype,action,priority FROM suricata_sqacls ORDER BY xORDER")
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
		if err := rows.Scan(&acl.ID, &acl.Name, &acl.ApplayerProtocol, &acl.Enabled, &acl.Count, &acl.Seconds, &acl.Target, &acl.Flow, &acl.Classtype, &acl.Action, &Priority); err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		acl.Priority = futils.StrToInt(Priority.String)
		if acl.Priority == 0 {
			acl.Priority = 1
		}
		acl.Source, acl.ExplainSource = aclsGroup(acl.ID, "src")
		acl.Destination, acl.DestinationExpl = aclsGroup(acl.ID, "dst")
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
	log.Debug().Msgf("%v Query Group %v from rule id %d", futils.GetCalleRuntime(), GroupType, aclid)
	query := `SELECT suricata_sqacllinks.negation,suricata_sqacllinks.gpid,webfilters_sqgroups.GroupName FROM suricata_sqacllinks,webfilters_sqgroups WHERE 
				suricata_sqacllinks.gpid=webfilters_sqgroups.ID
			    AND webfilters_sqgroups.enabled=1
				AND webfilters_sqgroups.GroupType=?
				AND aclid=? ORDER BY zOrder`

	rows, err := db.Query(query, GroupType, aclid)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return "", fmt.Sprintf("<span class='text-danger'>Error %v</span>", err.Error())
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var positif []int
	var negatif []int
	var explanations []string

	for rows.Next() {
		var gpid int
		var GroupName string
		var negation sql.NullInt32

		err := rows.Scan(&negation, &gpid, &GroupName)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		GroupName = futils.Latin1ToUTF8([]byte(GroupName))
		log.Debug().Msgf("%v Query Group %v id %d", futils.GetCalleRuntime(), GroupName, gpid)

		if negation.Int32 == 0 {
			explanations = append(explanations, fmt.Sprintf("<span %v OnClick=\"Loadjs('fw.rules.items.php?groupid=%d&TableLink=suricata_sqacllinks&IDS=1');\">%v ({%v})</span>", OnMouse, gpid, GroupName, GroupType))
			positif = append(positif, gpid)
			continue
		}
		explanations = append(explanations, fmt.Sprintf("<span %v OnClick=\"Loadjs('fw.rules.items.php?groupid=%d&TableLink=suricata_sqacllinks&IDS=1');\">{not} %v ({%v})</span>", OnMouse, gpid, GroupName, GroupType))
		negatif = append(negatif, gpid)
	}

	Clean1 := make(map[string]bool)
	Clean2 := make(map[string]bool)
	var final []string

	for _, gpid := range positif {
		Items := getItemsNetworkFromGpid(db, gpid)
		for _, item := range Items {
			Clean1[item] = true
		}
	}

	for _, gpid := range negatif {
		Items := getItemsNetworkFromGpid(db, gpid)
		for _, item := range Items {
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
	return "[" + strings.Join(final, ",") + "]", strings.Join(explanations, " {or} ")

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

func SetACLsExplain() {
	Acls := GetACLs()
	explain := make(map[int]string)

	prios := make(map[int]string)
	prios[0] = "{none}"
	prios[1] = "{ids_prio_1}"
	prios[2] = "{medium}"
	prios[3] = "{low}"
	prios[4] = "{info}"

	if len(Acls) == 0 {
		log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), "No ACLs")
		return
	}

	for _, acl := range Acls {
		var f []string
		var zobjetcs []string
		log.Debug().Msgf("%v (%d) %v", futils.GetCalleRuntime(), acl.ID, acl.Name)
		if acl.Action == "alert" {
			f = append(f, "{ids_prefix_1}")
		} else {
			f = append(f, "{ids_prefix_2}")
		}
		f = append(f, fmt.Sprintf("{ids_class_in}: <strong>"+acl.Classtype+"</strong> %v", fmt.Sprintf("{ids_class_level}: %v", prios[acl.Priority])))

		proto := "{all}"
		if len(acl.Proto) > 0 {
			if acl.Proto == "ip" {
				proto = "{all}"
			}
		}
		if acl.ExplainSource == "" {
			f = append(f, fmt.Sprintf("{network_traffic_from}: {all}"))
		} else {
			f = append(f, fmt.Sprintf("{network_traffic_from}: %v", acl.ExplainSource))
		}
		if acl.DestinationExpl == "" {
			f = append(f, fmt.Sprintf("{to_networks}: {all}"))
		} else {
			f = append(f, fmt.Sprintf("{to_networks}: %v", acl.DestinationExpl))
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

		if acl.Count > 1 && acl.Seconds > 0 {
			zobjetcs = append(zobjetcs, fmt.Sprintf("{OnlyAfter} %d {times} {during} %d {seconds}", acl.Count, acl.Seconds))
		}
		explain[acl.ID] = strings.Join(f, " ") + "&nbsp;" + strings.Join(zobjetcs, " {and} ")
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

func BuildACLs() {
	Acls := GetACLs()

	Targets := make(map[string]string)
	Targets["src"] = "src_ip"
	Targets["dst"] = "dest_ip"

	var rows []string

	for _, acl := range Acls {
		if acl.Enabled == 0 {
			continue
		}
		acl.Name = strings.ReplaceAll(acl.Name, `"`, "'")
		proto := acl.Proto
		if proto == "" {
			proto = "ip"
		}
		ruleSid := RuleSIDPrefix(acl.ID, 7100, 4)
		target := ""
		if len(acl.Target) > 0 {
			target = Targets[acl.Target]
		}
		prefix := "alert " + proto
		var opts []string
		if len(acl.ApplayerProtocol) > 0 {
			opts = append(opts, fmt.Sprintf("app-layer-protocol: %v", acl.ApplayerProtocol))
		}
		if len(target) > 1 {
			opts = append(opts, fmt.Sprintf("target:%v", target))
		}
		if len(acl.Target) > 0 {
			opts = append(opts, acl.Target)
		}
		if acl.Count > 1 && acl.Seconds > 0 {
			opts = append(opts, fmt.Sprintf("threshold:type limit, track by_src, count %d, seconds %d", acl.Count, acl.Seconds))
		}
		opts = append(opts, fmt.Sprintf("sid:%v", ruleSid))
		opts = append(opts, fmt.Sprintf("msg:\"%v\"", acl.Name))
		if len(acl.Flow) > 1 {
			// A voir flow:to_server,established
			opts = append(opts, fmt.Sprintf("flow:%v", acl.Flow))
		}
		opts = append(opts, fmt.Sprintf("rev:1"))
		rows = append(rows, fmt.Sprintf("%s any any -> any any (%s)", prefix, strings.Join(opts, "; ")))
	}
	fmt.Println(strings.Join(rows, "\n"))
}
func RuleSIDPrefix(id int, prefix int, pad int) string {
	format := fmt.Sprintf("%%d%%0%dd", pad)
	return fmt.Sprintf(format, prefix, id)
}

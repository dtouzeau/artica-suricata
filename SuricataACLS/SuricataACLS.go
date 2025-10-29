package SuricataACLS

import (
	"SqliteConns"
	"database/sql"
	"fmt"
	"futils"
	"strings"

	"github.com/rs/zerolog/log"
)

type SuriACLS struct {
	ID               int      `json:"ID"`
	Name             string   `json:"Name"`
	Rules            string   `json:"Rules"`
	ApplayerProtocol string   `json:"ApplayerProtocol"`
	Target           string   `json:"Target"`
	Enabled          int      `json:"Enabled"`
	Type             string   `json:"Type"`
	Priority         int      `json:"Priority"`
	Action           string   `json:"Action"`
	Source           []string `json:"Source"`
	Destination      []string `json:"Destination"`
	Count            int      `json:"Count"`
	Seconds          int      `json:"Seconds"`
	Proto            string   `json:"Proto"`
	Flow             string   `json:"Flow"`
}

func GetACLs() []SuriACLS {

	db, err := SqliteConns.SuricataConnectRO()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []SuriACLS{}
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	rows, err := db.Query("SELECT ID,aclname,ApplayerProtocol,enabled,count,seconds,target,flow FROM suricata_sqacls ORDER BY xORDER")
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
		if err := rows.Scan(&acl.ID, &acl.Name, &acl.ApplayerProtocol, &acl.Enabled, &acl.Count, &acl.Seconds, &acl.Target, &acl.Flow); err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		acl.Source = aclsSources(db, acl.ID)
		tables = append(tables, acl)
	}
	return tables
}
func aclsSources(db *sql.DB, aclid int) []string {
	return []string{}
}

func SetACLsExplain() {
	Acls := GetACLs()
	explain := make(map[int]string)
	for _, acl := range Acls {
		var f []string
		var zobjetcs []string
		f = append(f, "{ids_prefix_1}")
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

		if acl.Count > 1 && acl.Seconds > 0 {
			zobjetcs = append(zobjetcs, fmt.Sprintf("{OnlyAfter} %d {times} {during} %d {seconds}", acl.Count, acl.Seconds))
		}
		explain[acl.ID] = strings.Join(zobjetcs, " ")
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

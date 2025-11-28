package ImportExport

import (
	"SqliteConns"
	"database/sql"
	"encoding/json"
	"fmt"
	"futils"
	"notifs"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

type SQItems struct {
	Pattern     string `json:"pattern"`
	Enabled     int    `json:"enabled"`
	Zdate       string `json:"zdate"`
	Description string `json:"description"`
}

type SQObjects struct {
	GroupName     string    `json:"GroupName" db:"GroupName"`
	GroupType     string    `json:"GroupType" db:"GroupType"`
	AclTpl        string    `json:"acltpl" db:"acltpl"`
	TplReset      int       `json:"tplreset" db:"tplreset"`
	Enabled       int       `json:"enabled" db:"enabled"`
	PortDirection int       `json:"PortDirection" db:"PortDirection"`
	IdTemp        int       `json:"idtemp" db:"idtemp"`
	BulkImport    string    `json:"bulkimport" db:"bulkimport"`
	BulkMD5       string    `json:"bulkmd5" db:"bulkmd5"`
	Params        string    `json:"params" db:"params"`
	PacPxy        string    `json:"pacpxy" db:"pacpxy"`
	Negation      int32     `json:"negation" db:"negation"`
	ZOrder        int       `json:"zOrder" db:"zOrder"`
	Items         []SQItems `json:"items"`
}

type SQACL struct {
	ID               int64       `json:"ID"`
	ApplayerProtocol string      `json:"ApplayerProtocol"`
	AclName          string      `json:"aclname"`
	AclPort          int         `json:"aclport"`
	AclTpl           string      `json:"acltpl"`
	Enabled          int         `json:"enabled"`
	AclGroup         int         `json:"aclgroup"`
	AclGPID          int         `json:"aclgpid"`
	ZExplain         string      `json:"zExplain"`
	ZTemplate        string      `json:"zTemplate"`
	XOrder           int         `json:"xORDER"`
	Objects          []SQObjects `json:"Objects"`
}

// ExportSuricataSQACLToJSON loads a row by ID and returns it as JSON.
func Export(id int64) (string, error) {

	db, err := SqliteConns.AclsConnectRO()
	if err != nil {
		return "", err
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	const query = `
SELECT ID,
       ApplayerProtocol,
       aclname,
       aclport,
       acltpl,
       enabled,
       aclgroup,
       aclgpid,
       zExplain,
       zTemplate,
       xORDER
FROM suricata_sqacls
WHERE ID = ?`

	var row SQACL

	err = db.QueryRow(query, id).Scan(
		&row.ID,
		&row.ApplayerProtocol,
		&row.AclName,
		&row.AclPort,
		&row.AclTpl,
		&row.Enabled,
		&row.AclGroup,
		&row.AclGPID,
		&row.ZExplain,
		&row.ZTemplate,
		&row.XOrder,
	)
	if err != nil {
		return "", err // might be sql.ErrNoRows
	}

	row.Objects = getObjects(db, id)

	data, err := json.MarshalIndent(row, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
func getObjects(db *sql.DB, aclid int64) []SQObjects {

	query := `SELECT 
    			suricata_sqacllinks.negation,
    			suricata_sqacllinks.zOrder,
       			suricata_sqacllinks.gpid FROM suricata_sqacllinks,webfilters_sqgroups WHERE 
				suricata_sqacllinks.gpid=webfilters_sqgroups.ID
				AND aclid=? ORDER BY zOrder`

	rows, err := db.Query(query, aclid)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []SQObjects{}
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var r []SQObjects

	for rows.Next() {
		var gpid int
		var negation sql.NullInt32
		var zOrder int

		err := rows.Scan(&negation, &zOrder, &gpid)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		GQ := LoadGroup(db, gpid)
		if len(GQ.GroupName) == 0 {
			continue
		}
		GQ.Negation = negation.Int32
		GQ.ZOrder = zOrder
		Items := LoadItems(db, gpid)
		if len(Items) > 0 {
			GQ.Items = Items
		}
		r = append(r, GQ)

	}
	return r
}

func Import(filepath string) {

	notifs.BuildProgress(10, "{importing}", "suricata.acls.parse")
	data, err := futils.FileGetContentsBytes(filepath)
	if err != nil {
		notifs.BuildProgress(110, err.Error(), "suricata.acls.parse")
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	var rule SQACL
	err = json.Unmarshal(data, &rule)
	if err != nil {
		notifs.BuildProgress(110, err.Error(), "suricata.acls.parse")
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	db, err := SqliteConns.AclsConnectRW()
	if err != nil {
		notifs.BuildProgress(110, err.Error(), "suricata.acls.parse")
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	res, err := db.Exec(`INSERT INTO suricata_sqacls (ApplayerProtocol, aclname,aclport,acltpl,enabled,aclgroup,aclgpid,zExplain,zTemplate,xORDER) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, rule.ApplayerProtocol, rule.AclName, rule.AclPort, rule.AclTpl, rule.Enabled, rule.AclGroup, rule.AclGPID, rule.ZExplain, rule.ZTemplate, rule.XOrder)
	if err != nil {
		notifs.BuildProgress(110, err.Error(), "suricata.acls.parse")
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	ruleid, err := res.LastInsertId()
	if err != nil {
		notifs.BuildProgress(110, err.Error(), "suricata.acls.parse")
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	if ruleid == 0 {
		notifs.BuildProgress(110, "bad last id", "suricata.acls.parse")
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), "bad last id")
		return
	}

	for _, sGroup := range rule.Objects {
		notifs.BuildProgress(50, "{import} "+sGroup.GroupName, "suricata.acls.parse")
		res, err := db.Exec(`INSERT INTO webfilters_sqgroups (GroupName,GroupType,acltpl,tplreset,enabled,PortDirection,idtemp,bulkimport,bulkmd5,params,pacpxy) VALUES ($1,$2,$3,$3,$4,$5,$6,$7,$8,$9,$10)`, sGroup.GroupName, sGroup.GroupType, sGroup.AclTpl, sGroup.TplReset, sGroup.Enabled, sGroup.PortDirection, sGroup.IdTemp, sGroup.BulkImport, sGroup.BulkMD5, sGroup.Params, sGroup.PacPxy)
		if err != nil {
			notifs.BuildProgress(110, err.Error(), "suricata.acls.parse")
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return
		}
		lastGpid, err := res.LastInsertId()
		if err != nil {
			notifs.BuildProgress(110, err.Error(), "suricata.acls.parse")
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return
		}
		zmd5 := futils.Md5String(fmt.Sprintf("%d%d", ruleid, lastGpid))
		_, err = db.Exec(`INSERT INTO suricata_sqacllinks (zmd5,aclid,gpid,negation,zOrder) VALUES ($1,$2,$3,$4,$5)`, zmd5, ruleid, lastGpid, sGroup.Negation, sGroup.ZOrder)
		if err != nil {
			notifs.BuildProgress(110, err.Error(), "suricata.acls.parse")
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return
		}
		for _, zPat := range sGroup.Items {
			_, err = db.Exec(`INSERT INTO webfilters_sqitems (pattern,enabled,zdate,description,gpid) VALUES ($1,$2,$3,$4,$5)`, zPat.Pattern, zPat.Enabled, zPat.Zdate, zPat.Description, lastGpid)
			if err != nil {
				notifs.BuildProgress(110, err.Error(), "suricata.acls.parse")
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
				continue
			}
		}

	}
	notifs.BuildProgress(100, "{success}", "suricata.acls.parse")
}

func LoadGroup(db *sql.DB, id int) SQObjects {

	var bulkimport, Params, bulkmd5, PacPxy sql.NullString

	const query = `
SELECT GroupName,
       GroupType,
       acltpl,
       tplreset,
       enabled,
       PortDirection,
       idtemp,
       bulkimport,
       bulkmd5,
       params,
       pacpxy FROM webfilters_sqgroups WHERE ID=?`

	var g SQObjects

	err := db.QueryRow(query, id).Scan(
		&g.GroupName,
		&g.GroupType,
		&g.AclTpl,
		&g.TplReset,
		&g.Enabled,
		&g.PortDirection,
		&g.IdTemp,
		&bulkimport,
		&bulkmd5,
		&Params,
		&PacPxy)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return SQObjects{
			GroupName:     "",
			GroupType:     "",
			AclTpl:        "",
			TplReset:      0,
			Enabled:       0,
			PortDirection: 0,
			IdTemp:        0,
			BulkImport:    "",
			BulkMD5:       "",
			Params:        "",
			PacPxy:        "",
		}
	}
	g.BulkImport = bulkimport.String
	g.BulkMD5 = bulkmd5.String
	g.Params = Params.String
	g.PacPxy = PacPxy.String
	return g

}
func LoadItems(db *sql.DB, gpid int) []SQItems {
	query := `SELECT pattern,enabled,description,zdate FROM webfilters_sqitems WHERE gpid=?`

	rows, err := db.Query(query, gpid)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []SQItems{}
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var r []SQItems

	for rows.Next() {
		var pattern, description, zdate sql.NullString
		var enabled int

		err := rows.Scan(&pattern, &enabled, &description, &zdate)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		if len(pattern.String) == 0 {
			continue
		}
		r = append(r, SQItems{pattern.String, enabled, zdate.String, description.String})

	}
	return r

}

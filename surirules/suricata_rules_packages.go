package surirules

import (
	"SqliteConns"
	"SuriStructs"
	"database/sql"
	"futils"

	"github.com/rs/zerolog/log"
)

func Classifications() {

	db, err := SqliteConns.SuricataRulesConnectRO()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	Query := "SELECT count(*) as tcount,source_file FROM rules GROUP BY source_file"
	rows, err := db.Query(Query)
	if err != nil {
		log.Error().Msgf("%v:%v %v", futils.GetCalleRuntime(), Query, err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	Main := make(map[string]int)
	for rows.Next() {
		var SourceFile string
		var zcount int
		err := rows.Scan(&zcount, &SourceFile)
		if err != nil {
			log.Error().Msgf("%v: Error while scanning row %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		Main[SourceFile] = zcount
	}

	if len(Main) == 0 {
		return
	}

	_ = rows.Close()
	Query = "SELECT count(*) as tcount,classtype FROM rules GROUP BY classtype"
	rows, err = db.Query(Query)
	if err != nil {
		log.Error().Msgf("%v:%v %v", futils.GetCalleRuntime(), Query, err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)
	GlobalConfig := SuriStructs.LoadConfig()
	for rows.Next() {
		var classtype string
		var zcount int
		err := rows.Scan(&zcount, &classtype)
		if err != nil {
			log.Error().Msgf("%v: Error while scanning row %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		GlobalConfig.Categories[classtype] = zcount
	}
	SuriStructs.SaveConfig(GlobalConfig)

	_ = db.Close()
	db, err = SqliteConns.SuricataConnectRW()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	TotalCount := 0
	for rulefile, count := range Main {
		TotalCount = TotalCount + count
		_, err = db.Exec(`INSERT OR IGNORE INTO suricata_rules_packages (rulefile,category,rulesnumber) VALUES(?,'ALL',?)`, rulefile, count)
	}
	for rulefile, count := range Main {
		TotalCount = TotalCount + count
		_, err = db.Exec(`UPDATE suricata_rules_packages SET rulesnumber=? WHERE rulefile=?`, count, rulefile)
	}
	Global := SuriStructs.LoadConfig()
	Global.RulesCount = TotalCount
	SuriStructs.SaveConfig(Global)
}

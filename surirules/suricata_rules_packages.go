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
	GlobalConfig := SuriStructs.LoadConfig()
	Main := make(map[string]int)
	for rows.Next() {
		var SourceFile string
		var zcount int
		err := rows.Scan(&zcount, &SourceFile)
		if err != nil {
			log.Error().Msgf("%v: Error while scanning row %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		log.Debug().Msgf("%v %v ---> %d", futils.GetCalleRuntime(), SourceFile, zcount)
		GlobalConfig.Families[SourceFile] = zcount
		Main[SourceFile] = zcount
	}

	if len(Main) == 0 {
		log.Error().Msgf("%v: No rules found", futils.GetCalleRuntime())
		return
	}
	SuriStructs.SaveConfig(GlobalConfig)
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

	TotalCount := 0
	for rulefile, count := range Main {
		TotalCount = TotalCount + count
		GlobalConfig.Families[rulefile] = count

	}
	GlobalConfig.RulesCount = TotalCount
	SuriStructs.SaveConfig(GlobalConfig)
}

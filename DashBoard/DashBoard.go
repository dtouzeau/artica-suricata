package DashBoard

import (
	"apostgres"
	"database/sql"
	"fmt"
	"futils"
	"sockets"

	"github.com/leeqvip/gophp"
	"github.com/rs/zerolog/log"
)

func Build() {

	EnableSuricata := sockets.GET_INFO_INT("EnableSuricata")
	if EnableSuricata == 0 {
		return
	}

	db, err := apostgres.SQLConnectRO()
	if err != nil {
		log.Error().Msgf("%v failed to connect to database: %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	rows, err := db.Query("SELECT SUM(xcount) as tcount, severity FROM suricata_events GROUP BY severity")
	if err != nil {
		log.Error().Msgf("%v failed to query database: %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	severities := make(map[int]int)
	for rows.Next() {
		var tcount int
		var severity int
		err = rows.Scan(&tcount, &severity)
		if err != nil {
			log.Error().Msgf("%v failed to query database: %v", futils.GetCalleRuntime(), err.Error())
			return
		}

		if tcount > 0 {
			severities[severity] = tcount
		}
	}
	err = rows.Err()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}
	Serialized, _ := gophp.Serialize(severities)
	filePth := "/usr/share/artica-postfix/ressources/interface-cache/suricata.dashboard"
	serialized_text := fmt.Sprintf("%s", Serialized)
	_ = futils.FilePutContents(filePth, serialized_text)

}

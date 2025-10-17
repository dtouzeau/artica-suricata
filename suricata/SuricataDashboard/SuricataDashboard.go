package SuricataDashboard

import (
	"apostgres"
	"futils"
	"github.com/rs/zerolog/log"
	"sockets"
)

func CountOfSuricata() {

	EnableSuricata := sockets.GET_INFO_INT("EnableSuricata")
	if EnableSuricata == 0 {
		return
	}
	DisablePostGres := sockets.GET_INFO_INT("DisablePostGres")
	if DisablePostGres == 1 {
		return
	}

	db, err := apostgres.SQLConnectRO()
	if err != nil {
		log.Error().Msgf("%v Error connecting to database: %v", futils.GetCalleRuntime(), err)
		return
	}

	var totalEventCount int
	err = db.QueryRow(`SELECT SUM(xcount) as xcount FROM suricata_events`).Scan(&totalEventCount)
	if err != nil {
		log.Error().Msgf("%v Failed to execute query: %v", futils.GetCalleRuntime(), err)
		return
	}
	_ = futils.FilePutContents("/usr/share/artica-postfix/ressources/interface-cache/COUNT_OF_SURICATA", futils.IntToString(totalEventCount))

	var CountOfSuricataIpSrc int
	err = db.QueryRow(`SELECT COUNT(*) as xcount FROM ( SELECT src_ip FROM suricata_events GROUP BY src_ip ) as t`).Scan(&CountOfSuricataIpSrc)
	if err != nil {
		log.Error().Msgf("%v Failed to execute query: %v", futils.GetCalleRuntime(), err)
		return
	}
	_ = futils.FilePutContents("/usr/share/artica-postfix/ressources/interface-cache/COUNT_OF_SURICATA_IP_SRC", futils.IntToString(CountOfSuricataIpSrc))

}

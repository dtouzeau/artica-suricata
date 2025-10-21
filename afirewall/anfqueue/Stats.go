package anfqueue

import (
	"apostgres"
	"database/sql"
	"fmt"
	"futils"
	"ipscan"
	"sockets"
	"strings"
	"time"

	"github.com/leeqvip/gophp"
	"github.com/rs/zerolog/log"
)

const NfqueueStatsDir = "/usr/share/artica-postfix/ressources/logs/nfqueue"

func ImportStats() {
	BlockDir := "/home/artica/nfqueue/stats/blocks"
	WhiteDir := "/home/artica/nfqueue/stats/white"
	if !futils.IsDirDirectory(BlockDir) {
		return
	}
	if sockets.GET_INFO_INT(TokenEnabled) == 0 {
		_ = futils.RmRF(BlockDir)
		return
	}

	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}

	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	CurTime := futils.RoundToNearest10Minutes(time.Now().Unix())
	Files := futils.DirectoryScan(BlockDir)
	for _, fName := range Files {
		zDate := futils.StrToInt64(fName)
		if zDate == 0 {
			continue
		}
		if zDate == CurTime {
			continue
		}
		FullPath := fmt.Sprintf("%v/%v", BlockDir, fName)
		err := scanfile(db, FullPath)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return
		}
		futils.DeleteFile(FullPath)
	}

	Files = futils.DirectoryScan(WhiteDir)
	for _, fName := range Files {
		zDate := futils.StrToInt64(fName)
		if zDate == 0 {
			continue
		}
		if zDate == CurTime {
			continue
		}
		FullPath := fmt.Sprintf("%v/%v", WhiteDir, fName)
		err := scanfile(db, FullPath)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return
		}
		futils.DeleteFile(FullPath)
	}
	log.Debug().Msgf("%v --> prepareStatsCurrentDay", futils.GetCalleRuntime())
	prepareStatsCurrentDay(db)
}
func scanfile(db *sql.DB, filepath string) error {
	tb := strings.Split(futils.FileGetContents(filepath), "\n")
	for _, line := range tb {
		if !strings.Contains(line, ",") {
			continue
		}
		tr := strings.Split(line, ",")
		xTime := tr[0]
		sIP := tr[1]
		Category := tr[2]
		ts := time.Unix(futils.StrToInt64(xTime), 0).Local()
		_, err := db.Exec(`INSERT INTO nfqueue (ipaddr,zdate,category) VALUES ($1,$2,$3)`, sIP, ts, Category)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return err
		}
	}
	return nil
}
func prepareStatsCurrentDay(db *sql.DB) {
	rows, err := db.Query(`SELECT (date_trunc('minute', zdate) - (EXTRACT(minute FROM zdate)::int % 10) * INTERVAL '1 minute') AS interval_start,
	COUNT(*) AS cnt
	FROM nfqueue
	WHERE zdate <  date_trunc('day', now()) + INTERVAL '1 day'
	AND category <> 'WHITE'
	GROUP BY interval_start
	ORDER BY interval_start;`)

	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}

	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var interval string
		err := rows.Scan(&interval, &cnt)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}

		v[interval] = cnt
	}
	futils.CreateDir(NfqueueStatsDir)
	futils.ChownFolder(NfqueueStatsDir, "www-data", "www-data")
	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/todayBlackHits.array", string(NewMemArrayBytes))
	prepareStatsCurrentPie1(db)
	log.Debug().Msgf("%v -> prepareStatsCurrentPie2", futils.GetCalleRuntime())
	prepareStatsCurrentPie2(db)
	log.Debug().Msgf("%v -> prepareStatsYesterDayline", futils.GetCalleRuntime())
	prepareStatsYesterDayline(db)
	log.Debug().Msgf("%v -> prepareStatsYesterdayPie2", futils.GetCalleRuntime())
	prepareStatsYesterdayPie2(db)
	log.Debug().Msgf("%v -> prepareStatsYesterdayPie1", futils.GetCalleRuntime())
	prepareStatsYesterdayPie1(db)
	prepareStatsWeeklyline(db)
	prepareStatsWeeklyPie1(db)
	prepareStatsWeeklyPie2(db)
	prepareStatsMonthlyline(db)
	prepareStatsMonthlyPie1(db)
	prepareStatsMonthlyPie2(db)
}
func prepareStatsCurrentPie1(db *sql.DB) {
	rows, err := db.Query(`SELECT COUNT(*) AS cnt,category FROM nfqueue WHERE category <> 'WHITE' GROUP by category ORDER BY cnt DESC LIMIT 15`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var category string
		err := rows.Scan(&cnt, &category)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}

		v[category] = cnt
	}
	futils.CreateDir(NfqueueStatsDir)
	log.Debug().Msgf("%v %d items", futils.GetCalleRuntime(), len(v))
	futils.ChownFolder(NfqueueStatsDir, "www-data", "www-data")
	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/todayCategories.array", string(NewMemArrayBytes))

}
func prepareStatsCurrentPie2(db *sql.DB) {
	rows, err := db.Query(`SELECT COUNT(*) AS cnt,ipaddr FROM nfqueue WHERE category <> 'WHITE' GROUP by ipaddr ORDER BY cnt DESC LIMIT 15`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var ipaddr string
		err := rows.Scan(&cnt, &ipaddr)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		_ = ipscan.AddToQueue(ipaddr)
		v[ipaddr] = cnt
	}
	futils.CreateDir(NfqueueStatsDir)
	futils.ChownFolder(NfqueueStatsDir, "www-data", "www-data")
	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/todayIps.array", string(NewMemArrayBytes))

}
func prepareStatsYesterDayline(db *sql.DB) {

	rows, err := db.Query(`SELECT zdate,SUM(hits) AS cnt
	FROM nfqueue_days
	WHERE zdate >= date_trunc('day', now() - INTERVAL '1 day')
	AND zdate <= date_trunc('day', now() - INTERVAL '1 day') + INTERVAL '23:59:59' 
	AND category <> 'WHITE'
	GROUP BY zdate ORDER BY zdate;`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var interval string
		err := rows.Scan(&interval, &cnt)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}

		v[interval] = cnt
	}
	futils.CreateDir(NfqueueStatsDir)
	futils.ChownFolder(NfqueueStatsDir, "www-data", "www-data")
	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/YesterdayBlackHits.array", string(NewMemArrayBytes))

}
func prepareStatsYesterdayPie1(db *sql.DB) {
	rows, err := db.Query(`SELECT SUM(hits) AS cnt,category FROM nfqueue_days 
				WHERE category <> 'WHITE' 
				AND zdate >= date_trunc('day', now() - INTERVAL '1 day')
				AND zdate <= date_trunc('day', now() - INTERVAL '1 day') + INTERVAL '23:59:59'
                GROUP by category ORDER BY cnt DESC LIMIT 15`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var ipaddr string
		err := rows.Scan(&cnt, &ipaddr)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}

		v[ipaddr] = cnt
	}

	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/yesterdayCategories.array", string(NewMemArrayBytes))

}
func prepareStatsYesterdayPie2(db *sql.DB) {
	rows, err := db.Query(`SELECT SUM(hits) AS cnt,ipaddr FROM nfqueue_days 
				WHERE category <> 'WHITE' 
				AND zdate >= date_trunc('day', now() - INTERVAL '1 day')
				AND zdate <= date_trunc('day', now() - INTERVAL '1 day') + INTERVAL '23:59:59'
                GROUP by ipaddr ORDER BY cnt DESC LIMIT 15`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var ipaddr string
		err := rows.Scan(&cnt, &ipaddr)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}

		v[ipaddr] = cnt
	}

	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/yesterdayIps.array", string(NewMemArrayBytes))

}
func prepareStatsWeeklyline(db *sql.DB) {
	rows, err := db.Query(`SELECT zdate,SUM(hits) AS cnt
	FROM nfqueue_days
	WHERE zdate >= date_trunc('week', now() AT TIME ZONE 'UTC')
    AND zdate <= date_trunc('week', now() AT TIME ZONE 'UTC') + INTERVAL '6 days 23:59:59' 
	AND category <> 'WHITE'
	GROUP BY zdate ORDER BY zdate;`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var interval string
		err := rows.Scan(&interval, &cnt)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}

		v[interval] = cnt
	}
	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/WeeklyBlackHits.array", string(NewMemArrayBytes))

}
func prepareStatsMonthlyline(db *sql.DB) {
	myMonth := thisMonth()
	rows, err := db.Query(`SELECT zdate,SUM(hits) AS cnt
	FROM nfqueue_days
	WHERE date_trunc('month',zdate)=$1
	AND category <> 'WHITE'
	GROUP BY zdate ORDER BY zdate;`, myMonth)

	log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), fmt.Sprintf("SELECT zdate,SUM(hits) AS cnt FROM nfqueue_days WHERE date_trunc('month',zdate)=%v AND category <> 'WHITE' GROUP BY zdate ORDER BY zdate", myMonth))

	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var interval string
		err := rows.Scan(&interval, &cnt)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}

		v[interval] = cnt
	}
	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/MonthlyBlackHits.array", string(NewMemArrayBytes))

}
func prepareStatsWeeklyPie1(db *sql.DB) {
	rows, err := db.Query(`SELECT SUM(hits) AS cnt,category FROM nfqueue_days 
		WHERE category <> 'WHITE' 
		AND zdate >= date_trunc('week', now() AT TIME ZONE 'UTC')
    	AND zdate <= date_trunc('week', now() AT TIME ZONE 'UTC') + INTERVAL '6 days 23:59:59' 
        GROUP by category ORDER BY cnt DESC LIMIT 15`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var ipaddr string
		err := rows.Scan(&cnt, &ipaddr)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}

		v[ipaddr] = cnt
	}

	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/weeklyCategories.array", string(NewMemArrayBytes))

}
func prepareStatsMonthlyPie1(db *sql.DB) {
	myMonth := thisMonth()
	rows, err := db.Query(`SELECT SUM(hits) AS cnt,category FROM nfqueue_days 
		WHERE category <> 'WHITE' 
		AND date_trunc('month',zdate)=$1
        GROUP by category ORDER BY cnt DESC LIMIT 15`, myMonth)

	log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), fmt.Sprintf("SELECT SUM(hits) AS cnt,category FROM nfqueue_days WHERE category <> 'WHITE' AND date_trunc('month',zdate)='%v' GROUP by category ORDER BY cnt DESC LIMIT 15`, myMonth", myMonth))

	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var ipaddr string
		err := rows.Scan(&cnt, &ipaddr)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}

		v[ipaddr] = cnt
	}

	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/monthlyCategories.array", string(NewMemArrayBytes))

}
func prepareStatsWeeklyPie2(db *sql.DB) {
	rows, err := db.Query(`SELECT SUM(hits) AS cnt,ipaddr FROM nfqueue_days 
		WHERE category <> 'WHITE' 
		AND zdate >= date_trunc('week', now() AT TIME ZONE 'UTC')
    	AND zdate <= date_trunc('week', now() AT TIME ZONE 'UTC') + INTERVAL '6 days 23:59:59' 
        GROUP by ipaddr ORDER BY cnt DESC LIMIT 15`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var ipaddr string
		err := rows.Scan(&cnt, &ipaddr)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}

		v[ipaddr] = cnt
	}

	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/weeklyIps.array", string(NewMemArrayBytes))

}
func prepareStatsMonthlyPie2(db *sql.DB) {
	myMonth := thisMonth()
	rows, err := db.Query(`SELECT SUM(hits) AS cnt,ipaddr FROM nfqueue_days 
		WHERE category <> 'WHITE' 
		AND date_trunc('month',zdate)=$1
        GROUP by ipaddr ORDER BY cnt DESC LIMIT 15`, myMonth)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	v := make(map[string]int)

	for rows.Next() {
		var cnt int
		var ipaddr string
		err := rows.Scan(&cnt, &ipaddr)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}

		v[ipaddr] = cnt
	}

	NewMemArrayBytes, _ := gophp.Serialize(v)
	_ = futils.FilePutContents(NfqueueStatsDir+"/monthlyIps.array", string(NewMemArrayBytes))

}
func thisMonth() string {
	now := time.Now()
	// first day of this month at 00:00:00 in the same location
	firstOfMonth := time.Date(
		now.Year(),
		now.Month(),
		1, // day
		0, 0, 0, 0,
		now.Location(),
	)
	// format as "YYYY-MM-01 00:00:00"
	return firstOfMonth.Format("2006-01-02 15:04:05")
}
func thisWeek() (string, string) {

	now := time.Now()
	loc := now.Location()
	weekday := int(now.Weekday())
	daysSinceMonday := (weekday + 6) % 7

	startThisWeek := time.Date(
		now.Year(), now.Month(), now.Day(),
		0, 0, 0, 0, loc,
	).AddDate(0, 0, -daysSinceMonday)
	startLastWeek := startThisWeek.AddDate(0, 0, -7)

	return startLastWeek.Format("2006-01-02 15:04:05"), startThisWeek.Format("2006-01-02 15:04:05")

}
func CompressDays() {
	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	if err := db.Ping(); err != nil {
		db, err = apostgres.SQLConnect()
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return
		}
	}

	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	rows, err := db.Query(`SELECT ipaddr,category,(date_trunc('minute', zdate) - (EXTRACT(minute FROM zdate)::int % 60) * INTERVAL '1 minute') AS interval_start,
    COUNT(*) AS cnt FROM nfqueue WHERE zdate >= date_trunc('day', now() - INTERVAL '1 day') AND zdate <= date_trunc('day', now() - INTERVAL '1 day') + INTERVAL '23:59:59' GROUP BY interval_start,ipaddr,category ORDER BY interval_start;`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		var ipaddr, category, interval string
		var cnt int
		err := rows.Scan(&ipaddr, &category, &interval, &cnt)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return
		}
		zmd5 := futils.Md5String(fmt.Sprintf("%v%v%v%v", ipaddr, category, interval, cnt))
		_, err = db.Exec(`INSERT INTO nfqueue_days (zmd5,ipaddr,zdate,category,hits) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, zmd5, ipaddr, interval, category, cnt)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return
		}
	}
	_, err = db.Exec(`DELETE FROM nfqueue  WHERE zdate >= date_trunc('day', now() - INTERVAL '1 day') AND zdate <= date_trunc('day', now() - INTERVAL '1 day') + INTERVAL '23:59:59'`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
}

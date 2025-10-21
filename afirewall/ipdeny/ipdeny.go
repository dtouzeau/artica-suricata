package ipdeny

import (
	"apostgres"
	"bufio"
	"database/sql"
	"fmt"
	"futils"
	"github.com/leeqvip/gophp"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
	"httpclient"
	"notifs"
	"os"
	"regexp"
	"sockets"
	"strings"
	"time"
)

func Update() {

	FireHolEnable := sockets.GET_INFO_INT("FireHolEnable")
	if FireHolEnable == 0 {
		return
	}
	DisablePostGres := sockets.GET_INFO_INT("DisablePostGres")
	if DisablePostGres == 1 {
		return
	}

	futils.CreateDir("/etc/artica-postfix/cron.1")
	lockfile := "/etc/artica-postfix/cron.1/exec.ipdeny.com.php.lock"

	TimeMin := futils.FileTimeMin(lockfile)
	if TimeMin < 240 {
		log.Debug().Msgf("%v need 240min, current = %dmn", futils.GetCalleRuntime(), TimeMin)
		return
	}
	futils.TouchFile(lockfile)
	dataEncoded := futils.Base64Decode(sockets.GET_INFO_STR("ipblocksMD5"))
	ipblocksMD5 := futils.UnserializeMap1(dataEncoded)
	if len(ipblocksMD5) > 5 {
		ztime := ipblocksMD5["TIME"]
		Mins := futils.TimeMin(futils.StrToInt64(ztime))
		if Mins < 360 {
			rest := 360 - Mins
			log.Debug().Msgf("%v Need %dmin", futils.GetCalleRuntime(), rest)
			return
		}
	}

	db, err := apostgres.SQLConnect()
	if err != nil {
		notifs.SquidAdminMysql(0, "IPDeny: Unable to connect to database", err.Error(), futils.GetCalleRuntime(), 36)
		return
	}

	TempFile := futils.TempFileName()
	if !httpclient.DownloadFile("http://www.ipdeny.com/ipblocks/data/aggregated/MD5SUM", TempFile) {
		notifs.SquidAdminMysql(0, "Unable to download list from www.ipdeny.com", "", futils.GetCalleRuntime(), 36)
		futils.DeleteFile(lockfile)
		return
	}
	content, err := os.ReadFile(TempFile)
	if err != nil {
		log.Error().Msgf("Error reading file: %v", err)
		return
	}

	lines := strings.Split(string(content), "\n")
	ipblocksMD5New := make(map[string]string)
	var updated []string

	re := regexp.MustCompile(`^(.+?)\s+([a-z]+)-aggregated\.zone`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse the line with regex
		matches := re.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}

		country := matches[2]
		filename := fmt.Sprintf("%s-aggregated.zone", country)
		newmd5 := strings.TrimSpace(matches[1])

		// Check if filename exists in ipblocksMD5 map
		if _, exists := ipblocksMD5[filename]; !exists {
			log.Debug().Msgf("%v %s not in array()", futils.GetCalleRuntime(), filename)
			ipblocksMD5[filename] = ""
		}

		// Skip if MD5 matches
		if ipblocksMD5[filename] == newmd5 {
			ipblocksMD5New[filename] = newmd5
			log.Debug().Msgf("%v %s SKIPPED (already imported)", futils.GetCalleRuntime(), filename)
			continue
		}

		log.Debug().Msgf("%v %s [%s] ! === [%s]", futils.GetCalleRuntime(), filename, newmd5, ipblocksMD5[filename])

		if !updateAggregated(db, filename, newmd5) {
			fmt.Printf("%s failed\n", filename)
			ipblocksMD5New[filename] = ipblocksMD5[filename]
			continue
		}

		updated = append(updated, country)
		ipblocksMD5New[filename] = newmd5
	}
	ipblocksMD5New["TIME"] = fmt.Sprintf("%d", time.Now().Unix())
	serialized, _ := gophp.Serialize(ipblocksMD5New)
	serializedText := fmt.Sprintf("%s", serialized)
	ipblocksmd5newCrypt := futils.Base64Encode(serializedText)
	sockets.SET_INFO_STR("ipblocksMD5", ipblocksmd5newCrypt)

	if len(updated) > 0 {
		notifs.SquidAdminMysql(2, fmt.Sprintf("ipdeny.com: %d countries updated", len(updated)), strings.Join(updated, "\n"), futils.GetCalleRuntime(), 114)
		ipdenyCountGeo(db)
	}

	if apostgres.CountOfRows(db, "ipdeny_countgeo") == 0 {
		ipdenyCountGeo(db)
	}

}
func ipdenyCountGeo(db *sql.DB) bool {
	// Delete existing entries in ipdeny_countgeo table
	_, err := db.Exec("DELETE FROM ipdeny_countgeo")
	if err != nil {
		log.Printf("Error deleting from ipdeny_countgeo: %v", err)
		return false
	}

	// Query to count entries grouped by country
	rows, err := db.Query("SELECT COUNT(*) as tcount, country FROM ipdeny_geo GROUP BY country")
	if err != nil {
		log.Printf("Error querying ipdeny_geo: %v", err)
		return false
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	// Accumulate values to insert
	var entries []string
	for rows.Next() {
		var country string
		var count int
		if err := rows.Scan(&count, &country); err != nil {
			log.Error().Msgf("%v Error scanning row: %v", futils.GetCalleRuntime(), err)
			return false
		}
		log.Debug().Msgf("%v %s........: %d elem", futils.GetCalleRuntime(), country, count)
		entries = append(entries, fmt.Sprintf("('%s', %d)", country, count))
	}

	// Check for errors after iterating rows
	if err := rows.Err(); err != nil {
		log.Error().Msgf("%v Error after iterating rows: %v", futils.GetCalleRuntime(), err)
		return false
	}

	// Insert into ipdeny_countgeo
	if len(entries) > 0 {
		insertQuery := fmt.Sprintf("INSERT INTO ipdeny_countgeo (country, items) VALUES %s", strings.Join(entries, ","))
		_, err = db.Exec(insertQuery)
		if err != nil {
			log.Error().Msgf("Error inserting into ipdeny_countgeo: %v", err)
			return false
		}
	}

	return true
}
func updateAggregated(db *sql.DB, filename string, md5 string) bool {
	re := regexp.MustCompile(`^([a-z]+)-aggregated\.zone`)
	MatchesCountry := futils.RegexGroup1(re, filename)
	if len(MatchesCountry) == 0 {
		log.Debug().Msgf("%v Bad file %s", futils.GetCalleRuntime(), filename)
		return false
	}

	country := strings.ToUpper(MatchesCountry)
	log.Debug().Msgf("%v Importing %v", futils.GetCalleRuntime(), country)
	tempFile := futils.TempFileName()
	if !httpclient.DownloadFile(fmt.Sprintf("http://www.ipdeny.com/ipblocks/data/aggregated/%v", filename), tempFile) {
		notifs.SquidAdminMysql(0, fmt.Sprintf("Unable to download %v from www.ipdeny.com", country), "", futils.GetCalleRuntime(), 36)
		return false
	}

	CurMD5 := futils.MD5File(tempFile)
	if CurMD5 != md5 {
		log.Error().Msgf("%v (%v) MD5 mismatch", futils.GetCalleRuntime(), country)
		return false
	}

	file, err := os.Open(tempFile)
	if err != nil {
		log.Error().Msgf("%v cannot handle %s", futils.GetCalleRuntime(), filename)
		futils.DeleteFile(tempFile)
		return false
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	_, err = db.Exec("DELETE FROM ipdeny_geo WHERE country = $1", country)
	if err != nil {
		notifs.SquidAdminMysql(1, "ipdeny.com: PostgreSQL error", err.Error(), futils.GetCalleRuntime(), 151)
		futils.DeleteFile(tempFile)
		return false
	}

	prefix := "INSERT INTO ipdeny_geo (country, pattern) VALUES "
	batchSize := 1500
	var entries []string
	fmt.Printf("Parsing %s\n", filename)

	reMatchesIP := regexp.MustCompile(`^[0-9\.]+\/[0-9]+`)

	// Scan file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !reMatchesIP.MatchString(line) {
			continue
		}

		// Append entry to batch
		entries = append(entries, fmt.Sprintf("('%s', '%s')", country, line))

		// Insert batch if it reaches the specified batch size
		if len(entries) >= batchSize {
			log.Debug().Msgf("%v Importing %d elements for %s", futils.GetCalleRuntime(), batchSize, country)
			query := prefix + strings.Join(entries, ",") + " ON CONFLICT DO NOTHING"
			_, err := db.Exec(query)
			if err != nil {
				notifs.SquidAdminMysql(1, "ipdeny.com: PostgreSQL error", err.Error(), futils.GetCalleRuntime(), 151)
				futils.DeleteFile(tempFile)
				return false
			}
			entries = []string{}
		}
	}

	// Insert any remaining entries after the loop
	if len(entries) > 0 {
		log.Debug().Msgf("%v Importing %d elements for %s", futils.GetCalleRuntime(), len(entries), country)
		query := prefix + strings.Join(entries, ",") + " ON CONFLICT DO NOTHING"
		_, err := db.Exec(query)
		if err != nil {
			notifs.SquidAdminMysql(1, "ipdeny.com: PostgreSQL error", err.Error(), futils.GetCalleRuntime(), 151)
			futils.DeleteFile(tempFile)
			return false
		}
	}

	futils.DeleteFile(tempFile)
	return true

}

package Classifications

import (
	"apostgres"
	"bufio"
	"database/sql"
	"futils"
	"os"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

func Parse() {
	file, err := os.Open("/etc/suricata/rules/classification.config")
	if err != nil {
		log.Error().Msgf("%v Error opening file: %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v Error connecting to database: %v", futils.GetCalleRuntime(), err)
		return
	}

	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	re := regexp.MustCompile(`^config classification:\s+(.+?),(.+?),([0-9]+)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		val := strings.TrimSpace(scanner.Text())
		if val == "" || strings.HasPrefix(val, "#") {
			continue
		}

		if match := re.FindStringSubmatch(val); match != nil {
			uduniq := futils.Md5String(match[2])
			shortname := match[1]
			description := match[2]
			priority := match[3]
			log.Debug().Msgf("%v %s %s = %s", futils.GetCalleRuntime(), uduniq, description, priority)
			_, err := db.Exec(`INSERT INTO suricata_classifications (uduniq, shortname, description, priority) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, uduniq, shortname, description, priority)
			if err != nil {
				log.Error().Msgf("%v Error inserting row into DB: %v", futils.GetCalleRuntime(), err)
			}
			_, err = db.Exec(`UPDATE suricata_classifications SET description=$1,priority=$2 WHERE shortname=$3`, description, priority, shortname)
			if err != nil {
				log.Error().Msgf("%v Error update row into DB: %v", futils.GetCalleRuntime(), err)
			}

		}
	}
	if err := scanner.Err(); err != nil {
		log.Error().Msgf("%v Error reading file: %v", futils.GetCalleRuntime(), err)
	}
}

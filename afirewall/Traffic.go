package afirewall

import (
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"os"
)

func CountOfTrafficShapingRules() int {

	db, err := ConnectDB()
	if err != nil {
		log.Error().Msgf("%v failed to open database: %v", futils.GetCalleRuntime(), err)
		return 0
	}
	defer db.Close()

	var Count int
	db.QueryRow(`SELECT count(*) as tcount FROM iptables_main WHERE xt_ratelimit=1 AND enabled=1`).Scan(&Count)
	return Count

}
func ipRatelimit() error {
	// Open SQLite database
	db, err := ConnectDB()
	if err != nil {
		return fmt.Errorf("%v failed to open database: %v", futils.GetCalleRuntime(), err)
	}
	defer db.Close()

	// Execute SQL query
	rows, err := db.Query("SELECT pattern, ruleid, `limit`, limit_unit FROM traffic_shaping WHERE enabled=1 ORDER BY ruleid")
	if err != nil {
		return fmt.Errorf("%v failed to execute query: %v", futils.GetCalleRuntime(), err)
	}
	defer rows.Close()

	for rows.Next() {
		var pattern string
		var ruleid int
		var limit int
		var limitUnit string

		if err := rows.Scan(&pattern, &ruleid, &limit, &limitUnit); err != nil {
			return fmt.Errorf("%v failed to scan row: %v", futils.GetCalleRuntime(), err)
		}

		final := 0
		target := fmt.Sprintf("/proc/net/ipt_ratelimit/rule%d", ruleid)

		switch limitUnit {
		case "kbit":
			final = limit * 1024
		case "Mbit":
			final = limit * 1024 * 1024
		default:
			final = limit
		}

		content := fmt.Sprintf("@+%s %d\n", pattern, final)
		if err := os.WriteFile(target, []byte(content), 0644); err != nil {
			return fmt.Errorf("%v failed to write to file %s: %v", futils.GetCalleRuntime(), target, err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("%v error iterating over rows: %v", futils.GetCalleRuntime(), err)
	}

	return nil
}

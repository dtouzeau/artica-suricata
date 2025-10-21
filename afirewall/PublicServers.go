package afirewall

import (
	"fmt"
	"futils"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"strings"
)

func PublicServers() error {

	filename := "/home/artica/firewall/PublicServers.txt"

	db, err := ConnectDB()
	if err != nil {
		return fmt.Errorf("%v failed to open database: %v", futils.GetCalleRuntime(), err)
	}
	defer db.Close()

	// Execute SQL query
	rows, err := db.Query("SELECT pattern, port FROM firehol_itself ORDER BY pattern ASC")
	if err != nil {
		return fmt.Errorf("%v failed to execute query: %v", futils.GetCalleRuntime(), err)
	}
	defer rows.Close()

	// Create and open the file
	fh, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("%v failed to create file: %v", futils.GetCalleRuntime(), err)
	}
	defer fh.Close()

	// Write initial line to the file
	_, err = fh.WriteString("create PublicServers hash:net,port hashsize 16384 maxelem 1000000\n")
	if err != nil {
		return fmt.Errorf("%v failed to write to file: %v", futils.GetCalleRuntime(), err)
	}

	// Process query results and write to the file
	count := 0
	for rows.Next() {
		var pattern, port string
		if err := rows.Scan(&pattern, &port); err != nil {
			return fmt.Errorf("%v failed to scan row: %v", futils.GetCalleRuntime(), err)
		}

		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		port = strings.Replace(port, "tcp:", "", -1)
		_, err := fh.WriteString(fmt.Sprintf("add PublicServers %s,%s\n", pattern, port))
		if err != nil {
			return fmt.Errorf("%v failed to write to file: %v", futils.GetCalleRuntime(), err)
		}

		count++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("%v error iterating over rows: %v", futils.GetCalleRuntime(), err)
	}

	ipsetBin := futils.FindProgram("ipset")
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v flush PublicServers", ipsetBin))

	err, out := futils.ExecuteShell(fmt.Sprintf("%v restore -! < %s", ipsetBin, filename))
	if err != nil {
		return fmt.Errorf("%v failed to restore ipset: %v [%v]", futils.GetCalleRuntime(), err, out)
	}
	return nil
}

package apostgres

import (
	"bytes"
	"database/sql"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"os/exec"
	"sockets"
	"strings"
)

const PgRestore = "/usr/local/ArticaStats/bin/pg_restore"
const PgSocket = "/run/ArticaStats"

func ImportFileToTable(SourceFile string) error {

	if !futils.FileExists(PgRestore) {
		return fmt.Errorf("%v %v no such binary", futils.GetCalleRuntime(), PgRestore)
	}
	cmd := fmt.Sprintf("%v -v --dbname=proxydb -Fc --clean -h %v -U ArticaStats %v", PgRestore, PgSocket, SourceFile)
	_, out := futils.ExecuteShell(cmd)

	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, ": ERROR") {
			if !strings.Contains(line, "does not exist") {
				return fmt.Errorf("%v %v %v", futils.GetCalleRuntime(), futils.Basename(SourceFile), line)
			}
		}
	}

	return nil
}
func ExportTableToFile(TableName string, DestinationFile string) error {

	Dirname := futils.DirName(DestinationFile)
	futils.CreateDir(Dirname)
	InfluxUseRemote := sockets.GET_INFO_INT("InfluxUseRemote")

	dsn := `--host=/run/ArticaStats`
	pgDumpPath := "/usr/local/ArticaStats/bin/pg_dump"

	if InfluxUseRemote == 1 {
		InfluxUseRemoteIpaddr := sockets.GET_INFO_STR("InfluxUseRemote")
		InfluxUseRemotePort := sockets.GET_INFO_INT("InfluxUseRemotePort")
		if InfluxUseRemotePort == 0 {
			InfluxUseRemotePort = 5432
		}
		dsn = fmt.Sprintf("--host=%v --port=%d", InfluxUseRemoteIpaddr, InfluxUseRemotePort)
	}

	var args []string
	args = append(args, "-Fc")
	args = append(args, "--no-password")
	args = append(args, "--username=ArticaStats")
	args = append(args, "--dbname=proxydb")
	args = append(args, dsn)
	args = append(args, fmt.Sprintf("--table=%s", TableName))
	args = append(args, fmt.Sprintf("--file=%s", DestinationFile))

	// Run the command
	cmd := exec.Command(pgDumpPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append(cmd.Env, futils.ExecEnv()...)

	log.Debug().Msgf("%v(%v) Dump to [%v]", futils.GetCalleRuntime(), TableName, DestinationFile)
	err := cmd.Run()
	out := stdout.String() + " " + stderr.String()
	if err != nil {
		if strings.Contains(out, "no matching tables were found") {
			log.Warn().Msgf("%v(%v) table:%v [%v]", futils.GetCalleRuntime(), TableName, err.Error(), out)
			return nil
		}
		cmdline := fmt.Sprintf("%v %v", pgDumpPath, strings.Join(cmd.Args, " "))
		log.Error().Msgf("%v(%v) Running [%v]  failed table=%v [%v]", futils.GetCalleRuntime(), cmdline, TableName, err.Error(), out)
		return fmt.Errorf("%v Error %v [%v]", futils.GetCalleRuntime(), err.Error(), out)
	}

	if !futils.FileExists(DestinationFile) {
		log.Error().Msg(fmt.Sprintf("%v %v no such file", futils.GetCalleRuntime(), DestinationFile))
		return fmt.Errorf("%v %v %v", futils.GetCalleRuntime(), DestinationFile, "failed (no such file)")
	}

	FileSize := futils.FileSize(DestinationFile)
	if FileSize == 0 {
		log.Warn().Msgf("%v(%v) Dump results:=[%v] FileSize is 0!", futils.GetCalleRuntime(), TableName, out)
		futils.DeleteFile(DestinationFile)
		return nil
	}
	log.Info().Msgf("%v(%v) Dump results:=[%v]  size=%d bytes (seems OK)", futils.GetCalleRuntime(), TableName, out, FileSize)

	return nil
}

func ImportTableFromFile(SourceFile string) error {
	pg_restore := "/usr/local/ArticaStats/bin/pg_restore"
	InfluxUseRemote := sockets.GET_INFO_INT("InfluxUseRemote")
	dsn := `--host='/run/ArticaStats'`
	if InfluxUseRemote == 1 {
		InfluxUseRemoteIpaddr := sockets.GET_INFO_STR("InfluxUseRemote")
		InfluxUseRemotePort := sockets.GET_INFO_INT("InfluxUseRemotePort")
		if InfluxUseRemotePort == 0 {
			InfluxUseRemotePort = 5432
		}
		dsn = fmt.Sprintf("--host=%v --port=%d", InfluxUseRemoteIpaddr, InfluxUseRemotePort)

	}
	cmdline := fmt.Sprintf("%v -Fc --clean --if-exists --no-password --username=ArticaStats --dbname=proxydb %v \"%v\"", pg_restore, dsn, SourceFile)

	err, out := futils.ExecuteShell(cmdline)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("ImportTableFromFile %v return false", cmdline))
		return fmt.Errorf(fmt.Sprintf("Error %v [%v]", err.Error(), out))
	}
	return nil
}

func ResetTables(TableNames []string) {
	db, err := SQLConnect()
	if err != nil {
		return
	}
	defer db.Close()
	for _, TableName := range TableNames {
		_, _ = db.Exec("TRUNCATE TABLE " + TableName)
	}
}

func Truncate(TableName string) error {
	db, err := SQLConnect()
	if err != nil {
		return err
	}
	defer db.Close()

	if !isTableExists(db, TableName) {
		return nil
	}
	_, err = db.Exec("TRUNCATE TABLE " + TableName)
	return err
}
func isTableExists(db *sql.DB, TableName string) bool {
	query := `SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema';`

	rows, err := db.Query(query)
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var tablename string
		if err := rows.Scan(&tablename); err != nil {
			return false
		}
		if strings.ToLower(tablename) == TableName {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		return false
	}
	return false
}
func TableExists(TableName string) bool {
	db, err := SQLConnectRO()
	TableName = strings.TrimSpace(strings.ToLower(TableName))
	if err != nil {
		return false
	}
	defer db.Close()
	query := `SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema';`

	rows, err := db.Query(query)
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var tablename string
		if err := rows.Scan(&tablename); err != nil {
			return false
		}
		if strings.ToLower(tablename) == TableName {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		return false
	}
	return false

}
func TableExistsDB(db *sql.DB, TableName string) bool {

	TableName = strings.TrimSpace(strings.ToLower(TableName))
	query := `SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema';`
	rows, err := db.Query(query)
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var tablename string
		if err := rows.Scan(&tablename); err != nil {
			return false
		}
		if strings.ToLower(tablename) == TableName {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		return false
	}
	return false

}
func ListTables() (error, []string) {
	var Tables []string
	db, err := SQLConnect()
	if err != nil {
		return err, Tables
	}
	defer db.Close()
	query := `SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema';`

	rows, err := db.Query(query)
	if err != nil {
		return err, Tables
	}
	defer rows.Close()

	// Iterate through the result set and print the table names
	fmt.Println("Tables:")
	for rows.Next() {
		var tablename string
		if err := rows.Scan(&tablename); err != nil {
			return err, Tables
		}
		Tables = append(Tables, tablename)
	}
	if err := rows.Err(); err != nil {
		return err, Tables
	}
	return nil, Tables
}

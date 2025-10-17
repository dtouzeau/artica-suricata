package csqlite

import (
	"database/sql"
	"fmt"
	"futils"
	"os"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/mattn/go-sqlite3"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

func FieldExists(db *sql.DB, tableName, columnName string) (bool, error) {
	query := "PRAGMA table_info(`" + tableName + "`)"
	rows, err := db.Query(query)
	if err != nil {
		return false, err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)
	for rows.Next() {
		var cid int
		var name string
		var dataType string
		var notnull int
		var dfltValue *string
		var pk int
		err = rows.Scan(&cid, &name, &dataType, &notnull, &dfltValue, &pk)
		if err != nil {
			return false, err
		}
		if strings.EqualFold(name, columnName) {
			return true, nil
		}
	}

	return false, nil
}
func ConfigureDBPool(db *sql.DB) {
	db.SetMaxOpenConns(25)                 // Maximum number of open connections to the database
	db.SetMaxIdleConns(25)                 // Maximum number of idle connections
	db.SetConnMaxLifetime(5 * time.Minute) // Maximum lifetime of a connection (to avoid stale connections)
	Drv := GetDriverName(db)

	if Drv == "sqlite" {
		if !IsWalMode(db) {
			_, err := db.Exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;")
			if err != nil {
				if strings.Contains(err.Error(), "a readonly database") {
					return
				}
				log.Error().Msgf("%v Error setting journal_mode to WAL: %s", futils.GetCalleRuntime(), err.Error())
			}
		}
	}
}
func GetDriverName(db *sql.DB) string {
	drv := db.Driver()

	switch d := drv.(type) {
	case *sqlite3.SQLiteDriver:
		return "sqlite"
	case *pq.Driver:
		return "postgresql"
	default:
		return fmt.Sprintf("%T", d)
	}
}
func IsWalMode(db *sql.DB) bool {
	row := db.QueryRow("PRAGMA journal_mode;")
	var mode string
	if err := row.Scan(&mode); err != nil {
		log.Error().Msgf("%v  %v", futils.GetCalleRuntime(), err.Error())
		return false
	}
	if strings.ToLower(mode) == "wal" {
		return true
	}
	return false
}
func FieldExist(db *sql.DB, tableName, columnName string) bool {
	res, _ := FieldExists(db, tableName, columnName)
	return res
}
func IsDBClosed(db *sql.DB) bool {
	if db == nil {
		return true
	}
	err := db.Ping()
	return err != nil
}
func FieldExistCreateINT(db *sql.DB, tableName, columnName string) {
	res, _ := FieldExists(db, tableName, columnName)
	if res {
		return
	}
	prefix := "ALTER TABLE"
	_, err := db.Exec(fmt.Sprintf("%v `%v` ADD %v INTEGER NOT NULL DEFAULT 0", prefix, tableName, columnName))
	if err != nil {
		if strings.Contains(err.Error(), "duplicate column name") {
			return
		}
		log.Error().Msgf("%v: Error adding column %s to table %s: %s", futils.GetCalleRuntime(), columnName, tableName, err.Error())
		return
	}
}
func FieldExistCreateINTDef1(db *sql.DB, tableName, columnName string) {
	res, _ := FieldExists(db, tableName, columnName)
	if res {
		return
	}
	prefix := "ALTER TABLE"

	_, err := db.Exec(fmt.Sprintf("%v `%v` ADD %v INTEGER NOT NULL DEFAULT 1", prefix, tableName, columnName))
	if err != nil {
		log.Error().Msgf("%v Error adding column %s to table %s: %s", futils.GetCalleRuntime(), columnName, tableName, err.Error())
		return
	}
}
func FieldExistCreateINTDefManual(db *sql.DB, tableName, columnName string, Default int) {
	res, _ := FieldExists(db, tableName, columnName)
	if res {
		return
	}
	prefix := "ALTER TABLE"

	_, err := db.Exec(fmt.Sprintf("%v `%v` ADD %v INTEGER NOT NULL DEFAULT %d", prefix, tableName, columnName, Default))
	if err != nil {
		log.Error().Msgf("%v Error adding column %s to table %s: %s", futils.GetCalleRuntime(), columnName, tableName, err.Error())
		return
	}
}
func FieldExistCreateTEXTUUENC(db *sql.DB, tableName, columnName string) {
	res, _ := FieldExists(db, tableName, columnName)
	if res {
		return
	}
	prefix := "ALTER TABLE"
	_, err := db.Exec(fmt.Sprintf("%v %v ADD %v TEXT NOT NULL DEFAULT 'YTowOnt9'", prefix, tableName, columnName))
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: Error adding column %s to table: %s", futils.GetCalleRuntime(), columnName, err.Error()))
		return
	}
}
func CountRows(db *sql.DB, tableName string) int {
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM `%s`", tableName)
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: Error Count rows %s to table: %s", futils.GetCalleRuntime(), tableName, err.Error()))
	}
	return count
}
func FieldExistCreateTEXT(db *sql.DB, tableName, columnName string) {
	res, _ := FieldExists(db, tableName, columnName)
	if res {
		return
	}
	prefix := "ALTER TABLE"
	_, err := db.Exec(fmt.Sprintf("%v `%v` ADD %v TEXT NOT NULL DEFAULT ''", prefix, tableName, columnName))
	if err != nil {
		log.Error().Msgf("%v: Error adding column %s to table: %s", futils.GetCalleRuntime(), columnName, err.Error())
		return
	}
}
func CheckDatabaseIntegrity(db *sql.DB) error {
	var result string
	// Run the integrity check
	err := db.QueryRow("PRAGMA integrity_check;").Scan(&result)
	if err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("database integrity check failed: %s", result)
	}
	return nil
}
func FieldExistCreateTEXTVal(db *sql.DB, tableName, columnName string, defval string) {
	res, _ := FieldExists(db, tableName, columnName)
	if res {
		return
	}
	prefix := "ALTER TABLE"
	_, err := db.Exec(fmt.Sprintf("%v %v ADD %v TEXT NOT NULL DEFAULT '%v'", prefix, tableName, columnName, defval))
	if err != nil {
		log.Error().Msg(fmt.Sprintf("FieldExistCreateINT: Error adding column %s to table: %s", columnName, err.Error()))
		return
	}
}
func FieldExistCreateFLOAT(db *sql.DB, tableName, columnName string) {
	res, _ := FieldExists(db, tableName, columnName)
	if res {
		return
	}
	prefix := "ALTER TABLE"
	_, err := db.Exec(fmt.Sprintf("%v %v ADD %v REAL NOT NULL DEFAULT 0", prefix, tableName, columnName))
	if err != nil {
		log.Error().Msg(fmt.Sprintf("FieldExistCreateFLOAT: Error adding column %s to table: %s", columnName, err.Error()))
		return
	}
}
func PatchSSLTable(db *sql.DB) {

	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS sslcertificates (ID INTEGER PRIMARY KEY AUTOINCREMENT,CommonName TEXT UNIQUE,DateFrom TEXT NOT NULL DEFAULT '',DateTo TEXT NOT NULL DEFAULT '',CountryName TEXT NOT NULL DEFAULT '',stateOrProvinceName TEXT NOT NULL DEFAULT '',localityName TEXT NOT NULL DEFAULT '',OrganizationName TEXT NOT NULL DEFAULT '',OrganizationalUnit TEXT NOT NULL DEFAULT '',CompanyName  TEXT NOT NULL DEFAULT '',emailAddress TEXT NOT NULL DEFAULT '',levelenc INTEGER NOT NULL DEFAULT '4096',CertificateMaxDays INTEGER NOT NULL DEFAULT 0,IsClientCert INTEGER NOT NULL DEFAULT 0,AsProxyCertificate INTEGER NOT NULL DEFAULT 0,UsePrivKeyCrt INTEGER NOT NULL DEFAULT 0,UseGodaddy INTEGER NOT NULL DEFAULT 0,UseLetsEncrypt INTEGER NOT NULL DEFAULT 0,easyrsa INTEGER NOT NULL DEFAULT 0,DynamicCert TEXT NOT NULL DEFAULT '',DynamicDer TEXT NOT NULL DEFAULT '',DerContent TEXT NOT NULL DEFAULT '',csr TEXT NOT NULL DEFAULT '',srca TEXT NOT NULL DEFAULT '',der TEXT NOT NULL DEFAULT '',privkey TEXT NOT NULL DEFAULT '',pks12 TEXT NOT NULL DEFAULT '',keyPassword TEXT NOT NULL DEFAULT '',crt TEXT NOT NULL DEFAULT '',Squidkey TEXT NOT NULL DEFAULT '',SquidCert TEXT NOT NULL DEFAULT '',bundle TEXT NOT NULL DEFAULT '',clientkey TEXT NOT NULL DEFAULT '',clientcert TEXT NOT NULL DEFAULT '',easyrsabackup BLOB, CertPassword TEXT NOT NULL DEFAULT '', password TEXT NOT NULL DEFAULT '' )`)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v CREATE %v", futils.GetCalleRuntime(), err.Error()))
		return
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS subcertificates (
		ID INTEGER PRIMARY KEY AUTOINCREMENT,
		certid INTEGER,
		Certype INTEGER NOT NULL DEFAULT 1,
		UsePrivKeyCrt INTEGER NOT NULL DEFAULT 0,
		levelenc INTEGER NOT NULL DEFAULT 4096,
		countryName TEXT,
		stateOrProvinceName TEXT,
		localityName TEXT,
		organizationName TEXT,
		organizationalUnitName TEXT,
		commonName TEXT,
		AdditionalNames TEXT,
		emailAddress TEXT,
		pks12 TEXT,
		csr TEXT,
		srca  TEXT,
		crt TEXT,
		DateFrom INTEGER,
		DateTo INTEGER,
		subjectAltName TEXT,
		subjectAltName1 TEXT,
		subjectAltName2 TEXT,
		CertificateCenterCSR TEXT,
		password TEXT)`)

	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v CREATE %v", futils.GetCalleRuntime(), err.Error()))
		return
	}

	log.Debug().Msgf("%v sslcertificates [OK]", futils.GetCalleRuntime())

	IntegerFields := []string{"AsRoot", "Generated", "ServerCert"}
	for _, InTfield := range IntegerFields {
		FieldExistCreateINT(db, "sslcertificates", InTfield)
	}
	TextFields := []string{"subjectAltName", "subjectAltName1", "subjectAltName2", "CertificateCenterCSR", "AdditionalNames",
		"subjectKeyIdentifier", "letsencrypt_dns_key", "CABundleProvider", "domains",
	}

	for _, field := range TextFields {
		FieldExistCreateTEXT(db, "sslcertificates", field)
	}
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS commonNameidx ON sslcertificates (CommonName)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS DateToidx ON sslcertificates (DateTo)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS UseLetsEncryptidx ON sslcertificates (UseLetsEncrypt)`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS DateToidx ON subcertificates (DateTo)`)

}
func ListTables(db *sql.DB) []string {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'")
	if err != nil {
		return []string{}
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return []string{}
		}
		tables = append(tables, tableName)
	}
	return tables
}
func getTableSchema(db *sql.DB, tableName string) (string, error) {
	var createStmt string
	query := fmt.Sprintf("SELECT sql FROM sqlite_master WHERE type='table' AND name='%s'", tableName)
	err := db.QueryRow(query).Scan(&createStmt)
	if err != nil {
		return "", fmt.Errorf("failed to get schema for table %s: %v", tableName, err)
	}
	return createStmt, nil
}
func BackupDatabaseSQL(sourceDBPath string, destinationDBPath string, skipRecover bool) error {

	if futils.FileExists(destinationDBPath) {
		futils.DeleteFile(destinationDBPath)
	}

	if skipRecover {
		log.Debug().Msgf("%v Checking integrity of %v", futils.GetCalleRuntime(), sourceDBPath)
		dsn := fmt.Sprintf("file:%v", sourceDBPath)
		sourceDB, err := sql.Open("sqlite3", dsn)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return nil
		}
		err = CheckDatabaseIntegrity(sourceDB)
		_ = sourceDB.Close()
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return nil
		}
		log.Debug().Msgf("%v Checking integrity of %v [OK]", futils.GetCalleRuntime(), sourceDBPath)
	}

	dsn := fmt.Sprintf("file:%v?mode=ro", sourceDBPath)
	sourceDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return fmt.Errorf("%v Error opening source database:%v", futils.GetCalleRuntime(), err)
	}
	defer func(sourceDB *sql.DB) {
		err := sourceDB.Close()
		if err != nil {

		}
	}(sourceDB)

	Tables := ListTables(sourceDB)

	destinationDB, err := sql.Open("sqlite3", destinationDBPath)
	if err != nil {
		return fmt.Errorf("%v Error opening destination database: %v", futils.GetCalleRuntime(), err)
	}
	defer func(destinationDB *sql.DB) {
		err := destinationDB.Close()
		if err != nil {

		}
	}(destinationDB)

	futils.Chmod(destinationDBPath, 0755)
	_, err = sourceDB.Exec(fmt.Sprintf("ATTACH DATABASE '%s' AS backup", destinationDBPath))
	if err != nil {
		return fmt.Errorf("%v Error attaching destination database:[%v] %v ", futils.GetCalleRuntime(), destinationDBPath, err.Error())
	}
	_, err = sourceDB.Exec("BEGIN")
	if err != nil {
		return fmt.Errorf("%v Error beginning transaction: %v", futils.GetCalleRuntime(), err)
	}

	// Copy all tables from the source database to the destination
	for _, table := range Tables {

		createStmt, err := getTableSchema(sourceDB, table)
		if err != nil {
			return fmt.Errorf("error retrieving schema for table %v: %v", table, err)
		}
		_, err = destinationDB.Exec(createStmt)
		if err != nil {
			return fmt.Errorf("error creating table %v in destination: %v", table, err)
		}

		err = copyTableData(sourceDBPath, destinationDBPath, table)
		if err != nil {
			return fmt.Errorf("%v error copying data for table %v: %v", futils.GetCalleRuntime(), table, err)
		}
	}

	return nil
}
func CheckAnRepairDB(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("%v failed to open database: %v", futils.GetCalleRuntime(), err)
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	if _, err := db.Exec("VACUUM"); err != nil {
		return fmt.Errorf("%v VACUUM failed: %v", futils.GetCalleRuntime(), err)
	}

	if _, err := db.Exec(`REINDEX`); err != nil {
		return fmt.Errorf("%v REINDEX failed: %v", futils.GetCalleRuntime(), err)
	}
	return nil
}
func copyTableData(sourceDBPath, destinationDBPath, table string) error {
	sourceDB, err := sql.Open("sqlite3", fmt.Sprintf("file:%v?mode=ro", sourceDBPath))
	if err != nil {
		return fmt.Errorf("%v error opening source database: %v", futils.GetCalleRuntime(), err)
	}
	defer func(sourceDB *sql.DB) {
		err := sourceDB.Close()
		if err != nil {

		}
	}(sourceDB)

	destinationDB, err := sql.Open("sqlite3", destinationDBPath)
	if err != nil {
		return fmt.Errorf("%v error opening destination database: %v", futils.GetCalleRuntime(), err)
	}
	defer func(destinationDB *sql.DB) {
		err := destinationDB.Close()
		if err != nil {

		}
	}(destinationDB)
	// Attach destination database as 'backup' to source
	_, err = sourceDB.Exec(fmt.Sprintf("ATTACH DATABASE '%s' AS backup", destinationDBPath))
	if err != nil {
		return fmt.Errorf("%v error attaching destination database: %v", futils.GetCalleRuntime(), err)
	}
	defer func(sourceDB *sql.DB) {
		_, err := sourceDB.Exec("DETACH DATABASE backup") // No args needed
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
	}(sourceDB)

	// Copy data from source to destination table
	_, err = sourceDB.Exec(fmt.Sprintf(`INSERT INTO backup."%v" SELECT * FROM "%v"`, table, table))
	if err != nil {
		return fmt.Errorf("%v error copying data for table %v: %v", futils.GetCalleRuntime(), table, err)
	}

	return nil
}
func RecoverSQLITEDatabase(srcDBPath, dstDBPath string) error {

	if !futils.FileExists(srcDBPath) {
		return nil
	}

	BackupedFileTEMP := fmt.Sprintf("%v.BAK", srcDBPath)
	futils.DeleteFile(BackupedFileTEMP)

	err := BackupDatabaseSQL(srcDBPath, BackupedFileTEMP, true)
	if err != nil {
		return err
	}
	err = CheckAnRepairDB(BackupedFileTEMP)
	if err != nil {
		return err
	}
	err = futils.CopyFile(BackupedFileTEMP, dstDBPath)
	if err != nil {
		return fmt.Errorf("%v error copying %v to %v %v", futils.GetCalleRuntime(), BackupedFileTEMP, dstDBPath, err)
	}

	return nil
}
func DumpSQLITEDatabase(srcDBPath, dumpFilePath string) error {
	db, err := sql.Open("sqlite3", srcDBPath+"?mode=ro")
	if err != nil {
		return fmt.Errorf("error opening database: %v", err)
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	dumpFile, err := os.Create(dumpFilePath)
	if err != nil {
		return fmt.Errorf("error creating dump file: %v", err)
	}
	defer func(dumpFile *os.File) {
		err := dumpFile.Close()
		if err != nil {

		}
	}(dumpFile)

	rows, err := db.Query("SELECT sql FROM sqlite_master WHERE type='table'")
	if err != nil {
		return fmt.Errorf("error querying database schema: %v", err)
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	_, _ = fmt.Fprintln(dumpFile, "-- Schema")
	for rows.Next() {
		var schema string
		if err := rows.Scan(&schema); err != nil {
			return fmt.Errorf("error scanning schema row: %v", err)
		}
		_, _ = fmt.Fprintln(dumpFile, schema+";")
	}

	// Retrieve the data
	_, _ = fmt.Fprintln(dumpFile, "\n-- Data")

	tables, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return fmt.Errorf("error querying table names: %v", err)
	}
	defer func(tables *sql.Rows) {
		err := tables.Close()
		if err != nil {

		}
	}(tables)

	for tables.Next() {
		var tableName string
		if err := tables.Scan(&tableName); err != nil {
			return fmt.Errorf("error scanning table name: %v", err)
		}

		// Query all rows in the table
		rows, err := db.Query(fmt.Sprintf("SELECT * FROM `%s`", tableName))
		if err != nil {
			return fmt.Errorf("error querying table %s: %v", tableName, err)
		}
		defer func(rows *sql.Rows) {
			err := rows.Close()
			if err != nil {

			}
		}(rows)

		columns, err := rows.Columns()
		if err != nil {
			return fmt.Errorf("error retrieving columns for table %s: %v", tableName, err)
		}

		for rows.Next() {
			values := make([]interface{}, len(columns))
			valuePtrs := make([]interface{}, len(columns))
			for i := range values {
				valuePtrs[i] = &values[i]
			}

			if err := rows.Scan(valuePtrs...); err != nil {
				return fmt.Errorf("error scanning row for table %s: %v", tableName, err)
			}

			// Build INSERT statement
			insertStmt := fmt.Sprintf("INSERT INTO `%s` VALUES(", tableName)
			for i, value := range values {
				if i > 0 {
					insertStmt += ", "
				}
				if value == nil {
					insertStmt += "NULL"
				} else {
					insertStmt += fmt.Sprintf("'%v'", value)
				}
			}
			insertStmt += ");"
			_, _ = fmt.Fprintln(dumpFile, insertStmt)
		}
	}
	return nil
}
func BackupSQLITEDatabase(srcDBPath, dstDBPath string) error {

	if !futils.FileExists(srcDBPath) {
		return nil
	}

	BackupedFileTEMP := fmt.Sprintf("%v.BAK", srcDBPath)
	futils.DeleteFile(BackupedFileTEMP)

	err := BackupDatabaseSQL(srcDBPath, BackupedFileTEMP, false)
	if err != nil {
		return err
	}
	err = CheckAnRepairDB(BackupedFileTEMP)
	if err != nil {
		return err
	}
	err = futils.CopyFile(BackupedFileTEMP, dstDBPath)
	if err != nil {
		return fmt.Errorf("%v error copying %v to %v %v", futils.GetCalleRuntime(), BackupedFileTEMP, dstDBPath, err)
	}

	return nil
}
func CheckifaDatabase(filename string) bool {
	sn := fmt.Sprintf("file:%v?mode=ro", filename)
	db, err := sql.Open("sqlite3", sn)
	if err != nil {
		log.Error().Msgf("%v Failed to open database:[%v] %v", futils.GetCalleRuntime(), filename, err)
		return false
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	err = db.Ping()
	if err != nil {
		log.Error().Msgf("%v Failed to ping database: [%v] %v", futils.GetCalleRuntime(), filename, err)
		return false
	}
	return true
}

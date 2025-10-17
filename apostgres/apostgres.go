package apostgres

import (
	"context"
	"csqlite"
	"database/sql"
	"errors"
	"fmt"
	"futils"
	"log/syslog"
	"notifs"
	"runtime"
	"sockets"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
)

var TimeZone string
var PgBouncerEnabled int64
var CurrentPostgreSQLTables map[string]bool

type PostgreTablesInfo struct {
	SizeBytes int64
	SizeRows  int64
}

func RestartError() {
	PgBouncerEnabled = sockets.GET_INFO_INT("PgBouncerEnabled")
	DisablePGBouncer := sockets.GET_INFO_INT("DisablePGBouncer")
	if DisablePGBouncer == 1 {
		PgBouncerEnabled = 0
	}

	if PgBouncerEnabled == 1 {
		notifs.TosyslogGen("Restarting PGBouncer", "postgres")
		_, _ = futils.ExecuteShell("/etc/init.d/pgbouncer restart")
		return
	}
	notifs.TosyslogGen("Restarting PostgreSQL", "postgres")
	_, _ = futils.ExecuteShell("/etc/init.d/artica-postgres restart")
}
func Restart() error {

	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)
	if ok {
		file := futils.Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s.%v.%d", file, fn.Name(), line)
		TheCall = strings.ReplaceAll(TheCall, "/", ".")
	}
	log.Warn().Msgf("%v Restarting PostgreSQL service using command-line... called by %v", futils.GetCalleRuntime(), TheCall)
	_, _ = futils.ExecuteMe("-restart-postgresql")
	return nil
}
func PgSizes() map[string]PostgreTablesInfo {
	zReturn := make(map[string]PostgreTablesInfo)
	Query := `SELECT table_name,total_bytes FROM (SELECT *, pg_size_pretty(total_bytes) AS total
    , pg_size_pretty(index_bytes) AS INDEX
    , pg_size_pretty(toast_bytes) AS toast
    , pg_size_pretty(table_bytes) AS TABLE
    FROM (
        SELECT *, total_bytes-index_bytes-COALESCE(toast_bytes,0) AS table_bytes FROM (
        SELECT c.oid,nspname AS table_schema, relname AS TABLE_NAME
    , c.reltuples AS row_estimate
    , pg_total_relation_size(c.oid) AS total_bytes
    , pg_indexes_size(c.oid) AS index_bytes
    , pg_total_relation_size(reltoastrelid) AS toast_bytes
    FROM pg_class c
    LEFT JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE relkind = 'r'
    ) a
    ) a) b`

	db, err := SQLConnect()

	if err != nil {
		if strings.Contains(err.Error(), "database system is shutting down") {
			return zReturn
		}
		text := fmt.Sprintf("%v: PostGreSQL, connect to database failed %v", futils.GetCalleRuntime(), err.Error())
		notifs.SquidAdminMysql(0, text, "", "PgSizes", 576)
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), text)
		return zReturn
	}

	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	CurTime := time.Now()
	log.Debug().Msgf("%v Scanning PostgreSQL tables (%v)...", futils.GetCalleRuntime(), CurTime.Format("2006-01-02 15:04:05"))
	rows, err := db.Query(Query)
	if err != nil {
		if strings.Contains(err.Error(), "s.PGSQL.6432: connect: no such file or directory") {
			notifs.TosyslogGen(fmt.Sprintf("%v: s.PGSQL.6432: connect: no such file or directory: Restarting PostgreSQL", futils.GetCalleRuntime()), "postgres")
			log.Warn().Msgf("%v Restarting PostgreSQL failed with error %v", futils.GetCalleRuntime(), err.Error())
			RestartError()
			return zReturn
		}
		if strings.Contains(err.Error(), "bad connection") {
			notifs.TosyslogGen(fmt.Sprintf("%v Bad connection", futils.GetCalleRuntime()), "postgres")
			return zReturn
		}
		if strings.Contains(err.Error(), "could not open shared memory segment") {
			notifs.TosyslogGen(fmt.Sprintf("%v could not open shared memory segment: Restarting PostgreSQL", futils.GetCalleRuntime()), "postgres")
			notifs.SquidAdminMysql(1, fmt.Sprintf("PostgreSQL Error %v action=[restart]", err.Error()), "", "PgSizes", 636)
			errCmd := Restart()
			if errCmd != nil {
				log.Error().Msgf("%v Restarting PostGreSQL failed with error %v", futils.GetCalleRuntime(), errCmd.Error())
			}
		}
		if strings.Contains(err.Error(), `database "proxydb" does not exist`) {
			log.Error().Msgf("%v PostgreSQL not correctly installed!")
			errCmd := Restart()
			if errCmd != nil {
				log.Error().Msgf("%v Restarting PostGreSQL failed with error %v", futils.GetCalleRuntime(), errCmd.Error())
			}
		}
		log.Error().Msgf("%v Query to PostreSQL failed with error [%v]", futils.GetCalleRuntime(), err.Error())
		return zReturn
	}

	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)
	SizeBytes := int64(0)
	for rows.Next() {
		var TableName string
		var Bytes int64
		err := rows.Scan(&TableName, &Bytes)
		if err != nil {
			log.Error().Msgf("%v rows.Scan to PostreSQL failed with error %v", futils.GetCalleRuntime(), err.Error())
			return zReturn
		}
		var x PostgreTablesInfo
		SizeBytes = SizeBytes + Bytes
		x.SizeBytes = Bytes
		x.SizeRows = PGCountOfRows(db, TableName)
		zReturn[TableName] = x
	}
	log.Debug().Msgf("%v Found %d tables with %d bytes", futils.GetCalleRuntime(), len(zReturn), SizeBytes)
	sockets.SET_INFO_INT("PostgreSQLTotalBytes", SizeBytes)
	return zReturn

}
func cleanUserAgent(UserAgent string) string {
	return futils.CropString(UserAgent, 254)
}
func FlushUsersAgentStats() {

	_, keys := sockets.ListKeys("UserAgent:*")
	for _, key := range keys {
		sockets.DelKey(key)
	}
	db, err := SQLConnect()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}

	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	_, _ = db.Exec("TRUNCATE TABLE useragents_days")
	_, _ = db.Exec("TRUNCATE TABLE useragents_realtime")
}
func InsertUserAgent(db *sql.DB, UserAgent string) int {
	if len(UserAgent) < 2 {
		return 0
	}
	UserAgent = cleanUserAgent(UserAgent)
	UserAgentMD5 := futils.Md5String(UserAgent)
	Key := fmt.Sprintf("UserAgent:%v", UserAgentMD5)
	err, value := sockets.GetCache(Key)
	if err == nil {
		if futils.StrToInt(value) > 0 {
			return futils.StrToInt(value)
		}
	}
	if db == nil {
		db, err = SQLConnect()
		if err != nil {
			log.Error().Msg(fmt.Sprintf("%v: Error connecting to database %v", futils.GetCalleRuntime(), err))
			return 0
		}
		defer func(db *sql.DB) {
			err := db.Close()
			if err != nil {

			}
		}(db)
	}
	Query := `INSERT INTO useragents (useragent,zmd5) VALUES ($1,$2)  ON CONFLICT DO NOTHING`
	_, err = db.Exec(Query, UserAgent, UserAgentMD5)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: Error %v %v", futils.GetCalleRuntime(), Query, err.Error()))
		return 0
	}
	var id int
	err = db.QueryRow(`SELECT id FROM useragents WHERE zmd5=$1`, UserAgentMD5).Scan(&id)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: Error %v %v", futils.GetCalleRuntime(), Query, err.Error()))
		return 0
	}
	if id > 0 {
		sockets.SetCache(Key, futils.IntToString(id))
		return id
	}
	return 0

}
func TosyslogPostgres(text string) bool {

	processname := "postgres"

	syslogger, err := syslog.New(syslog.LOG_INFO, processname)
	if err != nil {
		return false
	}
	log.Debug().Msg(text)
	_ = syslogger.Notice(text)
	_ = syslogger.Close()
	return true
}
func PGCountOfRows(db *sql.DB, tablename string) int64 {
	// Construct connection string
	if tablename == "sql_sizing" || tablename == "sql_features" || tablename == "sql_implementation_info" || tablename == "sql_parts" {
		return 0
	}
	FalseTables := []string{"sql_sizing", "sql_implementation_info", "sql_parts", "sql_features", "pg_class",
		"pg_shdepend",
		"pg_description",
		"pg_foreign_table",
		"sql_packages",
		"pg_conversion",
		"pg_init_privs",
		"pg_amproc",
		"pg_trigger",
		"pg_proc",
		"pg_namespace",
		"sql_languages",
		"pg_rewrite",
		"pg_aggregate",
		"pg_amop",
		"pg_foreign_server",
		"pg_opclass",
		"pg_transform",
		"sql_sizing_profiles",
		"pg_statistic",
		"pg_ts_template",
		"pg_inherits",
		"pg_operator",
		"pg_language",
		"pg_foreign_data_wrapper",
		"pg_opfamily",
		"pg_type",
		"pg_default_acl",
		"pg_shdescription",
		"pg_db_role_setting",
		"pg_attrdef",
		"pg_authid",
		"pg_largeobject_metadata",
		"pg_ts_dict",
		"pg_cast",
		"pg_user_mapping",
		"pg_tablespace",
		"pg_seclabel",
		"pg_am",
		"pg_enum",
		"pg_policy",
		"pg_index",
		"pg_largeobject",
		"pg_range",
		"pg_sequence",
		"pg_publication",
		"pg_partitioned_table",
		"pg_collation",
		"pg_event_trigger",
		"pg_publication_rel",
		"pg_statistic_ext",
		"pg_auth_members",
		"pg_replication_origin",
		"pg_database",
		"pg_subscription_rel",
		"pg_ts_config_map",
		"pg_subscription",
		"pg_ts_config",
		"pg_depend",
		"pg_shseclabel",
		"pg_publication_namespace",
		"pg_parameter_acl",
		"pg_statistic_ext_data",
		"pg_ts_parser",
		"pg_attribute",
		"pg_extension",
		"pg_constraint",
		"pg_pltemplate",
	}
	for _, nnotable := range FalseTables {
		if nnotable == tablename {
			return 0
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Verify connection
	if err := db.PingContext(ctx); err != nil {
		TosyslogPostgres(fmt.Sprintf("ERROR %v failed to ping database: %v", futils.GetCalleRuntime(), err.Error()))
		return 0
	}

	var count int64

	// Query for approximate count from pg_class
	query := fmt.Sprintf(`SELECT reltuples::bigint AS tcount FROM pg_class WHERE relname = '%v' AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')`, tablename)
	err := db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		TosyslogPostgres(fmt.Sprintf("ERROR %v failed to query approximate count for table %v %v", futils.GetCalleRuntime(), tablename, err.Error()))
		return 0
	}

	return count
}

func PGCountOfRowsOld(db *sql.DB, tablename string) int64 {

	type QRes struct {
		tcount int64
	}
	var qq QRes
	query := fmt.Sprintf("SELECT COUNT(*) as tcount FROM %s", tablename)
	err := db.QueryRow(query).Scan(&qq.tcount)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: Error %v %v", futils.GetCalleRuntime(), query, err.Error()))
		return 0
	}
	return qq.tcount
}

func SQLConnectRO() (*sql.DB, error) {

	PgBouncerEnabled = sockets.GET_INFO_INT("PgBouncerEnabled")
	DisablePGBouncer := sockets.GET_INFO_INT("DisablePGBouncer")
	if DisablePGBouncer == 1 {
		PgBouncerEnabled = 0
	}

	if PgBouncerEnabled == 1 {
		db, err := BouncerConnect()
		return db, err
	}
	const socketPath = "/run/ArticaStats"
	const dbname = "proxydb"
	const user = "ArticaStats"
	// Check
	connStr := fmt.Sprintf("host=%s dbname=%s user=%s sslmode=disable binary_parameters=yes options='-c default_transaction_read_only=on'", socketPath, dbname, user)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(15 * time.Minute)
	db.SetMaxOpenConns(25) // Maximum number of open connections
	db.SetMaxIdleConns(10) // Maximum number of idle connections
	if err := db.Ping(); err != nil {
		return nil, errors.New(fmt.Sprintf("Error pinging database: %v", err.Error()))
	}

	return db, nil
}
func SQLConnect() (*sql.DB, error) {
	PgBouncerEnabled = sockets.GET_INFO_INT("PgBouncerEnabled")
	DisablePGBouncer := sockets.GET_INFO_INT("DisablePGBouncer")
	if DisablePGBouncer == 1 {
		PgBouncerEnabled = 0
	}

	if PgBouncerEnabled == 1 {
		db, err := BouncerConnect()
		return db, err
	}
	const socketPath = "/run/ArticaStats"
	const dbname = "proxydb"
	const user = "ArticaStats"
	if len(TimeZone) == 0 {
		TimeZone = futils.GetTimeZone()
	}
	// Check
	connStr := fmt.Sprintf("host=%s dbname=%s user=%s sslmode=disable TimeZone=%s binary_parameters=yes options='-c default_transaction_read_only=off'", socketPath, dbname, user, TimeZone)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(15 * time.Minute)
	db.SetMaxOpenConns(25) // Maximum number of open connections
	db.SetMaxIdleConns(10) // Maximum number of idle connections
	if err := db.Ping(); err != nil {
		return nil, errors.New(fmt.Sprintf("Error pinging database: %v", err.Error()))
	}
	return db, nil
}

func IsDBClosed(db *sql.DB) bool {
	err := db.Ping()
	if err != nil {
		if errors.Is(err, sql.ErrConnDone) { // Valid for connection done
			return true
		}
		if strings.Contains(err.Error(), "database is closed") {
			return true
		}
		log.Error().Msgf("%v Ping failed, but not necessarily closed", futils.GetCalleRuntime())
	}
	return false
}
func IsINRecoveryMode() bool {
	// Open a database connection
	db, err := SQLConnect()
	if err != nil {
		return false
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	// Query pg_is_in_recovery()
	var isRecovering bool
	err = db.QueryRow("SELECT pg_is_in_recovery()").Scan(&isRecovering)
	if err != nil {
		return false
	}

	return isRecovering
}
func BouncerConnect() (*sql.DB, error) {
	const socketPath = "/run/ArticaStats"
	const dbname = "proxydb"
	const user = "ArticaStats"
	connStr := fmt.Sprintf("host=%s port=6432 dbname=%s user=%s sslmode=disable binary_parameters=yes", socketPath, dbname, user)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("BouncerConnect", err)
	}
	db.SetConnMaxLifetime(15 * time.Minute)
	db.SetMaxOpenConns(25) // Maximum number of open connections
	db.SetMaxIdleConns(10) // Maximum number of idle connections

	return db, nil
}
func CountOfRowsOf(tablename string) int64 {
	db, err := SQLConnectRO()
	if err != nil {
		log.Error().Msgf("%v %v on table %v", futils.GetCalleRuntime(), err.Error(), tablename)
		return 0
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	csqlite.ConfigureDBPool(db)
	return CountOfRows(db, tablename)
}
func CountOfRows(db *sql.DB, tablename string) int64 {

	type QRes struct {
		tcount int64
	}
	var qq QRes

	query := fmt.Sprintf("SELECT COUNT(*) as tcount FROM %s", tablename)
	err := db.QueryRow(query).Scan(&qq.tcount)
	if err != nil {
		return 0
	}
	return qq.tcount

}
func FieldExists(db *sql.DB, tableName string, FieldName string) (bool, error) {
	query := `
		SELECT column_name 
		FROM information_schema.columns 
		WHERE table_name=$1 AND column_name=$2
	`

	var result string
	err := db.QueryRow(query, tableName, FieldName).Scan(&result)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
func CreateFieldInt(db *sql.DB, tableName string, FieldName string) {
	ok, err := FieldExists(db, tableName, FieldName)
	if err != nil {

		return
	}
	if ok {
		return
	}
	zsql := fmt.Sprintf("ALTER TABLE %v ADD COLUMN %v smallint NOT NULL DEFAULT 0", tableName, FieldName)
	_, _ = db.Exec(zsql)
}
func CreateFieldBigInt(db *sql.DB, tableName string, FieldName string) {
	ok, err := FieldExists(db, tableName, FieldName)
	if err != nil {

		return
	}
	if ok {
		return
	}
	zsql := fmt.Sprintf("ALTER TABLE %v ADD COLUMN %v BIGINT NOT NULL DEFAULT 0", tableName, FieldName)
	_, _ = db.Exec(zsql)
}
func CreateFieldUnixTime(db *sql.DB, tableName string, FieldName string) {
	ok, err := FieldExists(db, tableName, FieldName)
	if err != nil {

		return
	}
	if ok {
		return
	}
	zsql := fmt.Sprintf("ALTER TABLE %v ADD COLUMN %v BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())", tableName, FieldName)
	_, _ = db.Exec(zsql)
}
func CreateFieldTEXT(db *sql.DB, tableName string, FieldName string) {
	ok, err := FieldExists(db, tableName, FieldName)
	if err != nil {

		return
	}
	if ok {
		return
	}
	zsql := fmt.Sprintf("ALTER TABLE %v ADD COLUMN %v TEXT NOT NULL DEFAULT ''", tableName, FieldName)
	_, _ = db.Exec(zsql)
}
func CreateFieldVarChar(db *sql.DB, tableName string, FieldName string, Charsize int) {
	ok, err := FieldExists(db, tableName, FieldName)
	if err != nil {

		return
	}
	if ok {
		return
	}
	zsql := fmt.Sprintf("ALTER TABLE %v ADD COLUMN %v VARCHAR(%d) NOT NULL DEFAULT ''", tableName, FieldName, Charsize)
	_, _ = db.Exec(zsql)
}
func CreateFieldVarCharUnique(db *sql.DB, tableName string, FieldName string, Charsize int) {
	ok, err := FieldExists(db, tableName, FieldName)
	if err != nil {

		return
	}
	if ok {
		return
	}
	zsql := fmt.Sprintf("ALTER TABLE %v ADD COLUMN %v VARCHAR(%d) NOT NULL DEFAULT '' UNIQUE", tableName, FieldName, Charsize)
	_, _ = db.Exec(zsql)
}
func CreateFieldTimeStamp(db *sql.DB, tableName string, FieldName string) {
	ok, err := FieldExists(db, tableName, FieldName)
	if err != nil {

		return
	}
	if ok {
		return
	}
	zsql := fmt.Sprintf("ALTER TABLE %v ADD COLUMN %v timestamp DEFAULT current_timestamp", tableName, FieldName)
	_, _ = db.Exec(zsql)
}
func SQLExecSingle(db *sql.DB, SQL string) error {
	_, err := db.Exec(SQL)
	if err != nil {
		return err
	}
	return nil
}
func GetPID() int {

	pid := futils.GetPIDFromFile("/home/ArticaStatsDB/postmaster.pid")
	if futils.ProcessExists(pid) {
		return pid
	}
	return futils.PIDOFPattern("/usr/local/ArticaStats/bin/postgres")
}
func CreateIndex(db *sql.DB, table, indexName string, fields []string) bool {

	if IsDBClosed(db) {
		db, _ = SQLConnect()
		defer func(db *sql.DB) {
			_ = db.Close()
		}(db)
	}
	keyName := fmt.Sprintf("%s_%s", table, indexName)
	if isIndexExists(db, table, keyName) {
		return true
	}
	fieldStr := sqlFields(fields)

	_, err := db.Exec(fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (%s);", keyName, table, fieldStr))
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return true
		}
		log.Error().Msgf("%v Failed to create index: %s on %s, %s", futils.GetCalleRuntime(), indexName, table, err.Error())
		return false
	}

	return true
}
func ListTablesMem(db *sql.DB) map[string]bool {

	cachedValue, found := sockets.TempGet("PostgresTables")
	if found {
		if v, ok := cachedValue.(map[string]bool); ok {
			return v
		}
	}

	v := make(map[string]bool)
	log.Debug().Msgf("%v Loading tables...", futils.GetCalleRuntime())
	rows, err := db.Query(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type= 'BASE TABLE'`)
	if err != nil {
		return v
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)
	for rows.Next() {
		var table string
		err := rows.Scan(&table)
		if err != nil {
			return v
		}
		v[table] = true
	}
	sockets.SetTemp("PostgresTables", v)
	return v
}
func sqlFields(fields []string) string {
	return strings.Join(fields, ", ")
}
func isIndexExists(db *sql.DB, table, indexName string) bool {
	// Query to check if an index exists
	query := fmt.Sprintf(`SELECT 1 FROM pg_indexes WHERE tablename = '%s' AND indexname = '%s';`, table, indexName)
	var exists int
	err := db.QueryRow(query).Scan(&exists)
	if err != nil {
		return false
	}
	return exists == 1
}

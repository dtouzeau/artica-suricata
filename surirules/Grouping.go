package surirules

import (
	"SqliteConns"
	"apostgres"
	"database/sql"
	"fmt"
	"futils"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

type ruleStats struct {
	Classtype    string `json:"classtype"`
	SourceFile   string `json:"source_file"`
	EnabledCount int    `json:"enabled_count"`
	TotalCount   int    `json:"total_count"`
}

func getRuleStatistics(db *sql.DB) (map[string]ruleStats, error) {

	// Prepare the query
	query := `SELECT COALESCE(classtype, 'unknown') AS classtype, COALESCE(source_file, 'unknown') AS source_file,
			COUNT(*) as tcount FROM rules GROUP BY classtype, source_file ORDER BY classtype, source_file
	`

	// Execute query
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	// Parse results
	stats := make(map[string]ruleStats)
	for rows.Next() {
		var stat ruleStats
		err := rows.Scan(
			&stat.Classtype,
			&stat.SourceFile,
			&stat.TotalCount,
		)
		Index := futils.Md5String(stat.Classtype + ":" + stat.SourceFile)

		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		stat.EnabledCount = getEnableCount(db, stat)
		stats[Index] = stat
	}

	// Check for errors from iterating over rows
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return stats, nil
}
func getEnableCount(db *sql.DB, r ruleStats) int {
	var zcount int
	err := db.QueryRow("SELECT COUNT(*) FROM rules WHERE classtype=? AND source_file=? AND enabled=1", r.Classtype, r.SourceFile).Scan(&zcount)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return 0
	}
	return zcount
}
func PopulatePostgreSQLCategories() error {

	dbRules, err := SqliteConns.SuricataRulesConnectRO()
	if err != nil {
		log.Error().Msgf("%v open sqlite: %v", futils.GetCalleRuntime(), err)
		return err
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(dbRules)

	pgDB, err := apostgres.SQLConnect()
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	defer func(pgDB *sql.DB) {
		_ = pgDB.Close()
	}(pgDB)

	stats, err := getRuleStatistics(dbRules)
	if err != nil {
		return fmt.Errorf("failed to get rule statistics: %w", err)
	}

	// Test connection
	if err := pgDB.Ping(); err != nil {
		return fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	// Begin transaction
	tx, err := pgDB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec("TRUNCATE TABLE suricata_categories")
	if err != nil {
		return fmt.Errorf("failed to truncate table: %w", err)
	}

	// Prepare insert statement
	stmt, err := tx.Prepare(`
		INSERT INTO suricata_categories (classtype, source_file, enabled, available)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (classtype, source_file)
		DO UPDATE SET
			enabled = EXCLUDED.enabled,
			available = EXCLUDED.available
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	// Insert all statistics
	insertedCount := 0
	for _, stat := range stats {
		log.Debug().Msgf("Inserting row: %v", stat)
		_, err := stmt.Exec(
			stat.Classtype,
			stat.SourceFile,
			stat.EnabledCount,
			stat.TotalCount,
		)
		if err != nil {
			return fmt.Errorf("failed to insert record (classtype=%s, source_file=%s): %w",
				stat.Classtype, stat.SourceFile, err)
		}
		insertedCount++
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

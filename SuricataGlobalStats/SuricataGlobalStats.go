package SuricataGlobalStats

import (
	"apostgres"
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"futils"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SuricataStats struct {
	Timestamp   time.Time
	Counter     string
	TMName      string
	Value       int64
	UptimeDays  int
	UptimeHours int
	UptimeMins  int
	UptimeSecs  int
}

func CreateSchema(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create table
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS suricata_stats (
		id BIGSERIAL PRIMARY KEY,
		timestamp TIMESTAMP NOT NULL,
		counter VARCHAR(255) NOT NULL,
		tm_name VARCHAR(100) NOT NULL,
		value BIGINT NOT NULL,
		uptime_days INTEGER,
		uptime_hours INTEGER,
		uptime_mins INTEGER,
		uptime_secs INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.ExecContext(ctx, createTableSQL); err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	// Create indexes for better query performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON suricata_stats(timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_stats_counter ON suricata_stats(counter);",
		"CREATE INDEX IF NOT EXISTS idx_stats_tm_name ON suricata_stats(tm_name);",
		"CREATE INDEX IF NOT EXISTS idx_stats_counter_timestamp ON suricata_stats(counter, timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_stats_created_at ON suricata_stats(created_at);",
	}

	for _, indexSQL := range indexes {
		if _, err := db.ExecContext(ctx, indexSQL); err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}

func Run() {
	lfile := "/var/log/suricata/stats.log"
	if !futils.FileExists(lfile) {
		return
	}
	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v Failed to connect to database: %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	stats, err := parseStatsFile(lfile)
	if err != nil {
		log.Error().Msgf("Failed to parse stats file: %v", err)
	}
	inserted, err := insertStats(db, stats)
	if err != nil {
		log.Error().Msgf("%v Failed to insert stats: %v", futils.GetCalleRuntime(), err)
	}
	futils.DeleteFile(lfile)
	log.Info().Msgf("%v Successfully inserted %d stat entries into PostgreSQL", futils.GetCalleRuntime(), inserted)
}

func parseStatsFile(filepath string) ([]SuricataStats, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var stats []SuricataStats
	scanner := bufio.NewScanner(file)

	// Regular expressions for parsing
	dateRegex := regexp.MustCompile(`Date:\s+(\d{2}/\d{2}/\d{4})\s+--\s+(\d{2}:\d{2}:\d{2})\s+\(uptime:\s+(\d+)d,\s+(\d+)h\s+(\d+)m\s+(\d+)s\)`)
	statRegex := regexp.MustCompile(`^([a-z][a-z0-9._]+)\s+\|\s+([^\|]+?)\s+\|\s+(\d+)\s*$`)

	var currentTimestamp time.Time
	var uptimeDays, uptimeHours, uptimeMins, uptimeSecs int

	for scanner.Scan() {
		line := scanner.Text()

		// Check for date line
		if matches := dateRegex.FindStringSubmatch(line); matches != nil {
			dateStr := matches[1] + " " + matches[2]
			currentTimestamp, err = time.Parse("01/02/2006 15:04:05", dateStr)
			if err != nil {
				log.Printf("Warning: Failed to parse timestamp: %v", err)
				continue
			}

			uptimeDays, _ = strconv.Atoi(matches[3])
			uptimeHours, _ = strconv.Atoi(matches[4])
			uptimeMins, _ = strconv.Atoi(matches[5])
			uptimeSecs, _ = strconv.Atoi(matches[6])
			continue
		}

		// Check for stat line
		if matches := statRegex.FindStringSubmatch(line); matches != nil {
			counter := strings.TrimSpace(matches[1])
			tmName := strings.TrimSpace(matches[2])
			value, _ := strconv.ParseInt(matches[3], 10, 64)

			stat := SuricataStats{
				Timestamp:   currentTimestamp,
				Counter:     counter,
				TMName:      tmName,
				Value:       value,
				UptimeDays:  uptimeDays,
				UptimeHours: uptimeHours,
				UptimeMins:  uptimeMins,
				UptimeSecs:  uptimeSecs,
			}
			stats = append(stats, stat)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return stats, nil
}
func insertStats(db *sql.DB, stats []SuricataStats) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO suricata_stats
		(timestamp, counter, tm_name, value, uptime_days, uptime_hours, uptime_mins, uptime_secs)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	inserted := 0
	for _, stat := range stats {
		_, err := stmt.ExecContext(ctx,
			stat.Timestamp,
			stat.Counter,
			stat.TMName,
			stat.Value,
			stat.UptimeDays,
			stat.UptimeHours,
			stat.UptimeMins,
			stat.UptimeSecs,
		)
		if err != nil {
			log.Printf("Warning: Failed to insert stat %s: %v", stat.Counter, err)
			continue
		}
		inserted++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %v", err)
	}

	return inserted, nil
}

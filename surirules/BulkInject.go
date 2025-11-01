package surirules

import (
	"SqliteConns"
	"apostgres"
	"context"
	"database/sql"
	"fmt"
	"futils"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

func RulesToPostgres() {

	reportEvery := 5000
	sdb, err := SqliteConns.SuricataRulesConnectRO()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(sdb *sql.DB) {
		_ = sdb.Close()
	}(sdb)

	pgdb, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(pgdb *sql.DB) {
		_ = pgdb.Close()

	}(pgdb)

	if err := sdb.Ping(); err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}
	if err := pgdb.Ping(); err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}

	_, err = pgdb.Exec("TRUNCATE TABLE suricata_tmp")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}

	selectCols := "sid, msg, classtype, source_file"
	q := fmt.Sprintf("SELECT %s FROM rules", selectCols)
	q = q + " ORDER BY sid"
	var rctx context.Context
	var cancelRead context.CancelFunc
	rctx, cancelRead = context.WithCancel(context.Background())

	defer cancelRead()
	var ctx context.Context
	var cancelCopy context.CancelFunc
	ctx, cancelCopy = context.WithCancel(context.Background())

	defer cancelCopy()

	tx, err := pgdb.BeginTx(ctx, nil)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}

	createTmp := `
CREATE TEMP TABLE tmp_suricata_tmp (
  signature bigint PRIMARY KEY,
  description varchar(128),
  classtype varchar(35),
  source_file varchar(40)
) ON COMMIT DROP;`
	if _, err := tx.ExecContext(ctx, createTmp); err != nil {
		_ = tx.Rollback()
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}
	stmt, err := tx.PrepareContext(ctx, pqCopyIn("tmp_suricata_tmp", "signature", "description", "classtype", "source_file"))
	if err != nil {
		_ = tx.Rollback()
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}

	rows, err := sdb.QueryContext(rctx, q)
	if err != nil {
		_ = stmt.Close()
		_ = tx.Rollback()
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()

	}(rows)

	var (
		sid        sql.NullInt64
		msg        sql.NullString
		classtype  sql.NullString
		sourceFile sql.NullString
	)

	count := 0
	for rows.Next() {
		if err := rows.Scan(&sid, &msg, &classtype, &sourceFile); err != nil {
			log.Printf("scan row error (skipping): %v", err)
			continue
		}
		if !sid.Valid {
			continue
		}
		msg = truncate(msg, 128)
		classtype = truncate(classtype, 35)
		sourceFile = truncate(sourceFile, 40)

		var description interface{}
		if msg.Valid {
			description = msg.String
		} else {
			description = nil
		}
		var classVal interface{}
		if classtype.Valid {
			classVal = classtype.String
		} else {
			classVal = nil
		}
		var srcfile interface{}
		if sourceFile.Valid {
			srcfile = sourceFile.String
		} else {
			srcfile = nil
		}
		if _, err := stmt.ExecContext(ctx, sid.Int64, description, classVal, srcfile); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
			return
		}

		count++
		if count%reportEvery == 0 {
			log.Printf("streamed %d rows...", count)
		}
	}
	if err := rows.Err(); err != nil {
		_ = stmt.Close()
		_ = tx.Rollback()
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}
	if _, err := stmt.ExecContext(ctx); err != nil {
		_ = stmt.Close()
		_ = tx.Rollback()
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}

	log.Printf("streamed total %d rows into temp table, now upserting into suricata_tmp", count)

	upsert := `
INSERT INTO suricata_tmp (signature, description, classtype, source_file)
SELECT signature, description, classtype, source_file FROM tmp_suricata_tmp
ON CONFLICT (signature) DO UPDATE
  SET description = EXCLUDED.description,
      classtype = EXCLUDED.classtype,
      source_file = EXCLUDED.source_file;
`
	if _, err := tx.ExecContext(ctx, upsert); err != nil {
		_ = tx.Rollback()
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return
	}

	log.Info().Msgf("done. total rows processed: %d", count)
}
func pqCopyIn(table string, cols ...string) string {
	colList := ""
	for i, c := range cols {
		if i > 0 {
			colList += ", "
		}
		colList += c
	}
	return fmt.Sprintf("COPY %s (%s) FROM STDIN", table, colList)
}
func truncate(s sql.NullString, max int) sql.NullString {
	if !s.Valid {
		return sql.NullString{Valid: false}
	}
	r := []rune(s.String)
	if len(r) > max {
		return sql.NullString{String: string(r[:max]), Valid: true}
	}
	return s
}

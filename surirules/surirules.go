package surirules

import (
	"SqliteConns"
	"SuriStructs"
	"SuricataACLS"
	"bufio"
	"database/sql"
	"fmt"
	"futils"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	_ "github.com/mattn/go-sqlite3" // or: _ "modernc.org/sqlite"
	"github.com/rs/zerolog/log"
)

var sidRegex = regexp.MustCompile(` sid:([0-9]+)`)
var sidRegex1 = regexp.MustCompile(`;sid:([0-9]+);`)
var classtypeRegex = regexp.MustCompile(` classtype:(.*?);`)
var classtypeRegex2 = regexp.MustCompile(`;classtype:(.*?);`)
var classtypeRegex3 = regexp.MustCompile(` iprep:.*?,(.*?),`)

type Rule struct {
	Enabled   bool
	Raw       string
	Action    string
	Proto     string
	SrcAddr   string
	SrcPort   string
	Direction string
	DstAddr   string
	DstPort   string

	GID       *int
	SID       *int
	Rev       *int
	Msg       *string
	ClassType *string
	Priority  *int

	Options [][2]string // (key, value) preserving duplicates (e.g., multiple content)
}

// ImportSuricataRulesToSQLite parses rule files and inserts into SQLite.
// The schema is created/updated if needed.
// - rules.sid is UNIQUE (multiple NULLs allowed by SQLite)
// - On sid conflict, the rule is updated and options are re-inserted (no dedupe of options)

func parseEnableds() map[int]int {
	db, err := SqliteConns.SuricataRulesConnectRO()
	if err != nil {
		log.Error().Msgf("%v open sqlite: %v", futils.GetCalleRuntime(), err)
		return map[int]int{}
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	Query := "SELECT sid,enabled FROM rules"
	rows, err := db.Query(Query)
	if err != nil {
		log.Error().Msgf("%v:%v %v", futils.GetCalleRuntime(), Query, err.Error())
		return map[int]int{}
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	res := make(map[int]int)
	for rows.Next() {
		var sid, enabled int
		err := rows.Scan(&sid, &enabled)
		if err != nil {
			continue
		}
		res[sid] = enabled
	}
	return res
}

func ImportSuricataRulesToSQLite() error {
	dbPath := "/home/artica/SQLITE/suricata-rules.db"
	futils.CreateDir("/home/artica/SQLITE")
	RootPath := "/etc/suricata/rules"
	var ruleFiles []string
	sFiles := futils.DirectoryScan(RootPath)
	for _, sFile := range sFiles {
		if !strings.HasSuffix(sFile, ".rules") {
			continue
		}
		if sFile == "local.rules" || sFile == "iprep.rules" || sFile == "emerging-retired.rules" || sFile == "Production.rules" {
			continue
		}
		ruleFiles = append(ruleFiles, RootPath+"/"+sFile)
	}

	db, err := SqliteConns.SuricataRulesConnectRW()
	if err != nil {
		log.Error().Msgf("%v open sqlite: %v", futils.GetCalleRuntime(), err)
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	if err := initSchema(db); err != nil {
		return err
	}

	futils.ChownFile(dbPath, "www-data", "www-data")
	MemConf := parseEnableds()
	_, err = db.Exec("DELETE FROM rules WHERE source_file='otx_file_rules.rules'")
	_, err = db.Exec("DELETE FROM rules WHERE source_file='threatfox_suricata.rules'")
	_, err = db.Exec("DELETE FROM rules WHERE source_file='stamus-lateral.rules'")

	if err != nil {
		log.Error().Msgf("%v Delete otx_file_rules.rules: %v", futils.GetCalleRuntime(), err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Statements:
	upsertBySidStmt, err := tx.Prepare(`
INSERT INTO rules
(enabled, raw, action, proto, src_addr, src_port, direction, dst_addr, dst_port, gid, sid, rev, msg, classtype, priority, source_file)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(sid) DO UPDATE SET
  enabled=excluded.enabled,
  raw=excluded.raw,
  action=excluded.action,
  proto=excluded.proto,
  src_addr=excluded.src_addr,
  src_port=excluded.src_port,
  direction=excluded.direction,
  dst_addr=excluded.dst_addr,
  dst_port=excluded.dst_port,
  gid=excluded.gid,
  rev=excluded.rev,
  msg=excluded.msg,
  classtype=excluded.classtype,
  priority=excluded.priority,
  source_file=excluded.source_file
`)
	if err != nil {
		return fmt.Errorf("prepare upsert-by-sid: %w", err)
	}
	defer upsertBySidStmt.Close()

	insertPlainStmt, err := tx.Prepare(`
INSERT INTO rules
(enabled, raw, action, proto, src_addr, src_port, direction, dst_addr, dst_port, gid, sid, rev, msg, classtype, priority, source_file)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
`)
	if err != nil {
		return fmt.Errorf("prepare insert-plain: %w", err)
	}
	defer insertPlainStmt.Close()

	selectIdBySidStmt, err := tx.Prepare(`SELECT id FROM rules WHERE sid=?`)
	if err != nil {
		return fmt.Errorf("prepare select-id-by-sid: %w", err)
	}
	defer selectIdBySidStmt.Close()

	insertOptStmt, err := tx.Prepare(`INSERT INTO rule_options (rule_id, key, value) VALUES (?,?,?)`)
	if err != nil {
		return fmt.Errorf("prepare insert option: %w", err)
	}
	defer insertOptStmt.Close()

	for _, path := range ruleFiles {
		log.Debug().Msgf("%v Importing %s", futils.GetCalleRuntime(), path)
		if err := importOneFile(path, tx, upsertBySidStmt, insertPlainStmt, selectIdBySidStmt, insertOptStmt); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%v commit: %w", futils.GetCalleRuntime(), err)
	}

	for sid, enabled := range MemConf {
		_, err := db.Exec(`UPDATE rules SET enabled=? WHERE sid=?`, enabled, sid)
		if err != nil {
			log.Error().Msgf("%v Update sid=%d enabled=%d: %v", futils.GetCalleRuntime(), sid, enabled, err)
		}
	}

	return nil
}

// --- schema ---

func initSchema(db *sql.DB) error {
	ddl := `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS rules (
	id INTEGER PRIMARY KEY,
	enabled INTEGER NOT NULL,
	raw TEXT NOT NULL,
	action TEXT,
	proto TEXT,
	src_addr TEXT,
	src_port TEXT,
	direction TEXT,
	dst_addr TEXT,
	dst_port TEXT,
	gid INTEGER,
	sid INTEGER UNIQUE,
	rev INTEGER,
	msg TEXT,
	classtype TEXT,
	priority INTEGER,
	source_file TEXT
);

CREATE TABLE IF NOT EXISTS rule_options (
	id INTEGER PRIMARY KEY,
	rule_id INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
	key TEXT NOT NULL,
	value TEXT
);

CREATE INDEX IF NOT EXISTS idx_rules_sid ON rules(sid);
CREATE INDEX IF NOT EXISTS idx_rules_gid_sid ON rules(gid, sid);
CREATE INDEX IF NOT EXISTS idx_rule_options_rule ON rule_options(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_options_key ON rule_options(key);
CREATE INDEX IF NOT EXISTS idx_rule_srcfile ON rules(source_file);
CREATE INDEX IF NOT EXISTS idx_rule_srcfile_classtype ON rules(source_file,classtype);
`
	_, err := db.Exec(ddl)
	return err
}

// --- file import ---

func importOneFile(
	path string,
	tx *sql.Tx,
	upsertBySidStmt, insertPlainStmt, selectIdBySidStmt, insertOptStmt *sql.Stmt,
) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 128*1024), 10*1024*1024)

	var buf strings.Builder
	var lineNo int

	flush := func(raw string) error {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil
		}
		enabled := 1

		if strings.HasPrefix(raw, "#alert ") {
			enabled = 0
			raw = strings.TrimPrefix(raw, "#")
		}
		if strings.HasPrefix(raw, "# alert ") {
			enabled = 0
			raw = strings.TrimPrefix(raw, "# ")
		}

		// Entire line commented?
		if strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "//") {
			log.Debug().Msgf("%v Skipping commented line: %q", futils.GetCalleRuntime(), raw)
			return nil
		}

		check := strings.TrimLeftFunc(raw, unicode.IsSpace)
		if strings.HasPrefix(check, "#") {
			enabled = 0
			check = strings.TrimLeft(check, "#")
			raw = strings.TrimSpace(check)
			if raw == "" {
				log.Debug().Msgf("%v Skipping commented line: %q", futils.GetCalleRuntime(), raw)
				return nil
			}
		}

		rule, err := parseRule(raw)
		if err != nil {
			log.Debug().Msgf("%v Skipping line: %q", futils.GetCalleRuntime(), raw)
			return fmt.Errorf("parse: %w", err)
		}
		rule.Enabled = enabled == 1

		// Bind common fields
		var gid, sid, rev, prio any
		if rule.GID != nil {
			gid = *rule.GID
		}
		if rule.SID != nil {
			sid = *rule.SID
		}
		if rule.Rev != nil {
			rev = *rule.Rev
		}
		if rule.Priority != nil {
			prio = *rule.Priority
		}

		var ruleID int64

		if rule.SID != nil {
			// UPSERT by sid, then SELECT id by sid
			if _, err := upsertBySidStmt.Exec(
				boolToInt(rule.Enabled),
				rule.Raw,
				nullStr(rule.Action),
				nullStr(rule.Proto),
				nullStr(rule.SrcAddr),
				nullStr(rule.SrcPort),
				nullStr(rule.Direction),
				nullStr(rule.DstAddr),
				nullStr(rule.DstPort),
				gid, sid, rev,
				nilIfEmpty(deref(rule.Msg)),
				nilIfEmpty(deref(rule.ClassType)),
				prio,
				filepath.Base(path),
			); err != nil {
				log.Debug().Msgf("%v Skipping line: %q %v", futils.GetCalleRuntime(), raw, err.Error())
				return fmt.Errorf("upsert rule: %w", err)
			}
			row := selectIdBySidStmt.QueryRow(*rule.SID)
			if err := row.Scan(&ruleID); err != nil {
				log.Debug().Msgf("%v Skipping line: %q select id by sid=%d %v", futils.GetCalleRuntime(), raw, *rule.SID, err.Error())
				return fmt.Errorf("select id by sid=%d: %w", *rule.SID, err)
			}
		} else {
			log.Debug().Msgf("%v no sid [%w]", futils.GetCalleRuntime(), raw)
			// No sid: plain insert, then get last_insert_rowid()
			if _, err := insertPlainStmt.Exec(
				boolToInt(rule.Enabled),
				rule.Raw,
				nullStr(rule.Action),
				nullStr(rule.Proto),
				nullStr(rule.SrcAddr),
				nullStr(rule.SrcPort),
				nullStr(rule.Direction),
				nullStr(rule.DstAddr),
				nullStr(rule.DstPort),
				gid, nil, rev,
				nilIfEmpty(deref(rule.Msg)),
				nilIfEmpty(deref(rule.ClassType)),
				prio,
				filepath.Base(path),
			); err != nil {
				return fmt.Errorf("insert rule (no sid): %w", err)
			}
			if err := tx.QueryRow(`SELECT last_insert_rowid();`).Scan(&ruleID); err != nil {
				return fmt.Errorf("last_insert_rowid: %w", err)
			}
		}

		// Insert options tied to explicit ruleID
		for _, kv := range rule.Options {
			k := strings.TrimSpace(kv[0])
			v := strings.TrimSpace(kv[1])
			if k == "" {
				continue
			}
			if _, err := insertOptStmt.Exec(ruleID, k, v); err != nil {
				return fmt.Errorf(`insert option %q: %w`, k, err)
			}
		}

		return nil
	}

	for sc.Scan() {
		lineNo++
		line := sc.Text()
		trim := strings.TrimRight(line, " \t\r\n")
		if strings.HasSuffix(trim, "\\") {
			buf.WriteString(strings.TrimSuffix(trim, "\\"))
			buf.WriteString(" ")
			continue
		}
		buf.WriteString(trim)
		if err := flush(buf.String()); err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		buf.Reset()
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if buf.Len() > 0 {
		if err := flush(buf.String()); err != nil {
			return fmt.Errorf("line %d (eof): %w", lineNo, err)
		}
	}
	return nil
}

func CheckRulesCounter() {

	db, err := SqliteConns.SuricataRulesConnectRW()
	if err != nil {
		log.Error().Msgf("%v open sqlite: %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	gb := SuriStructs.LoadConfig()
	err = db.QueryRow("SELECT COUNT(*) as tcount FROM rules").Scan(&gb.RulesCount)
	if err != nil {
		log.Error().Msgf("%v select rules count: %v", futils.GetCalleRuntime(), err)
		return
	}
	err = db.QueryRow("SELECT COUNT(*) as tcount FROM rules WHERE enabled=1").Scan(&gb.ActiveRules)
	if err != nil {
		log.Error().Msgf("%v select rules count: %v", futils.GetCalleRuntime(), err)
		return
	}
	acls := SuricataACLS.GetACLs()
	for _, acl := range acls {
		gb.RulesCount++
		if acl.Enabled == 1 {
			gb.ActiveRules++
		}
	}
	SuriStructs.SaveConfig(gb)

	if gb.RulesCount > 0 {
		if len(gb.Categories) == 0 {
			Classifications()
		}
	}

}

func parseRule(raw string) (Rule, error) {
	r := Rule{Raw: raw}

	lparen := strings.Index(raw, "(")
	rparen := strings.LastIndex(raw, ")")
	if lparen == -1 || rparen == -1 || rparen < lparen {
		return r, fmt.Errorf("missing or unbalanced parentheses")
	}
	header := strings.TrimSpace(raw[:lparen])
	opts := strings.TrimSpace(raw[lparen+1 : rparen])

	h := fieldsPreserveBrackets(header)
	if len(h) < 7 {
		return r, fmt.Errorf("invalid header (need 7+ tokens), got %d: %q", len(h), header)
	}
	r.Action, r.Proto = h[0], h[1]
	r.SrcAddr, r.SrcPort = h[2], h[3]
	r.Direction = h[4]
	r.DstAddr, r.DstPort = h[5], h[6]

	// options
	for _, o := range splitOptions(opts) {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		key, val, hasColon := strings.Cut(o, ":")
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(trimTrailingSemicolon(val))
		if !hasColon {
			r.Options = append(r.Options, [2]string{key, "1"})
			continue
		}
		r.Options = append(r.Options, [2]string{key, val})

		switch strings.ToLower(strings.TrimSpace(key)) {
		case "gid":
			if n, err := strconv.Atoi(stripQuotes(val)); err == nil {
				r.GID = &n
			}
		case "sid":
			if n, err := strconv.Atoi(stripQuotes(val)); err == nil {
				r.SID = &n
			}
		case "rev":
			if n, err := strconv.Atoi(stripQuotes(val)); err == nil {
				r.Rev = &n
			}
		case "msg":
			s := unquoteIf(val)
			r.Msg = &s
		case "classtype":
			s := stripQuotes(val)
			r.ClassType = &s
		case "priority":
			if n, err := strconv.Atoi(stripQuotes(val)); err == nil {
				r.Priority = &n
			}
		}
	}

	if r.SID == nil {
		sid := findSIdInrule(raw)
		if sid > 0 {
			r.SID = &sid
		} else {
			log.Debug().Msgf("%v Missing sid in rule: %q", futils.GetCalleRuntime(), raw)
		}
	}
	if r.ClassType == nil {
		classtype := findSClassTypeInrule(raw)
		r.ClassType = &classtype
	}
	if r.ClassType == nil {
		log.Debug().Msgf("%v Missing ClassType in rule: %q", futils.GetCalleRuntime(), raw)
	}

	return r, nil
}
func findSIdInrule(raw string) int {
	sid := futils.RegexGroup1(sidRegex, raw)
	if len(sid) > 0 {
		sidInt := futils.StrToInt(sid)
		return sidInt
	}
	sid = futils.RegexGroup1(sidRegex1, raw)
	if len(sid) > 0 {
		sidInt := futils.StrToInt(sid)
		return sidInt
	}

	return 0
}
func findSClassTypeInrule(raw string) string {
	sid := futils.RegexGroup1(classtypeRegex, raw)
	if len(sid) > 0 {
		return sid
	}
	sid = futils.RegexGroup1(classtypeRegex2, raw)
	if len(sid) > 0 {
		return sid
	}
	sid = futils.RegexGroup1(classtypeRegex3, raw)
	if len(sid) > 0 {
		return "reputation"
	}

	return "unknown"
}

func fieldsPreserveBrackets(s string) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	for _, r := range s {
		if unicode.IsSpace(r) && depth == 0 {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		if r == '[' {
			depth++
		} else if r == ']' && depth > 0 {
			depth--
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// splitOptions splits on ';' but respects quotes "..." and regex /.../ with escapes.
func splitOptions(s string) []string {
	var res []string
	var cur strings.Builder
	inQuote := false
	inRegex := false
	escape := false

	for _, r := range s {
		if escape {
			cur.WriteRune(r)
			escape = false
			continue
		}
		if r == '\\' {
			escape = true
			cur.WriteRune(r)
			continue
		}
		if inQuote {
			if r == '"' {
				inQuote = false
			}
			cur.WriteRune(r)
			continue
		}
		if inRegex {
			if r == '/' {
				inRegex = false
			}
			cur.WriteRune(r)
			continue
		}
		switch r {
		case '"':
			inQuote = true
			cur.WriteRune(r)
		case '/':
			// treat as regex start if outside quotes
			inRegex = true
			cur.WriteRune(r)
		case ';':
			item := strings.TrimSpace(cur.String())
			if item != "" {
				res = append(res, item)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		res = append(res, t)
	}
	return res
}

// --- helpers ---

func trimTrailingSemicolon(v string) string {
	return strings.TrimRight(v, " \t;")
}
func stripQuotes(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}
func unquoteIf(v string) string { return stripQuotes(v) }
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
func nullStr(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
func nilIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

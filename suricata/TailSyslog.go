package suricata

import (
	"apostgres"
	"database/sql"
	"encoding/json"
	"fmt"
	"futils"

	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"

	"os"
	"regexp"
	"sockets"
	"strings"
	"suricata/suricataConfig"
	"time"
)

var reFixTime = regexp.MustCompile(`([+-]\d{2})(\d{2})$`)
var classificationCache = cache.New(cache.NoExpiration, cache.NoExpiration)
var evejsonCache = cache.New(cache.NoExpiration, cache.NoExpiration)
var SignaturesCache = cache.New(cache.NoExpiration, cache.NoExpiration)
var SignaturesFirewallCache = cache.New(cache.NoExpiration, cache.NoExpiration)
var CountThreats int

type PFringInfo struct {
	Enable                    int    `json:"enable"`
	Filename                  string `json:"filename"`
	Alias                     string `json:"alias"`
	Version                   string `json:"version"`
	Description               string `json:"description"`
	Author                    string `json:"author"`
	License                   string `json:"license"`
	SrcVersion                string `json:"srcversion"`
	Depends                   string `json:"depends"`
	Retpoline                 string `json:"retpoline"`
	Name                      string `json:"name"`
	Vermagic                  string `json:"vermagic"`
	MinNumSlots               string `json:"min_num_slots"`
	PerfectRulesHashSize      string `json:"perfect_rules_hash_size"`
	EnableTxCapture           string `json:"enable_tx_capture"`
	EnableFragCoherence       string `json:"enable_frag_coherence"`
	EnableIPDefrag            string `json:"enable_ip_defrag"`
	KeepVlanOffload           string `json:"keep_vlan_offload"`
	QuickMode                 string `json:"quick_mode"`
	ForceRingLock             string `json:"force_ring_lock"`
	EnableDebug               string `json:"enable_debug"`
	TransparentModeDeprecated string `json:"transparent_mode"`
}

type Alert struct {
	Action      string `json:"action"`
	Gid         int    `json:"gid"`
	SignatureID int    `json:"signature_id"`
	Rev         int    `json:"rev"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

// Define the structure for the flow field
type Flow struct {
	PktsToServer  int    `json:"pkts_toserver"`
	PktsToClient  int    `json:"pkts_toclient"`
	BytesToServer int    `json:"bytes_toserver"`
	BytesToClient int    `json:"bytes_toclient"`
	Start         string `json:"start"`
}

// Define the main structure for the event
type SuricataEvent struct {
	Timestamp string `json:"timestamp"`
	FlowID    int64  `json:"flow_id"`
	InIface   string `json:"in_iface"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     Alert  `json:"alert"`
	Flow      Flow   `json:"flow"`
}

type Memjson struct {
	Zdate           string `json:"zdate"`
	ZdateMin        string `json:"ZdateMin"`
	EventType       string `json:"event_type"`
	SrcIP           string `json:"src_ip"`
	SrcPort         int    `json:"src_port"`
	DestPort        int    `json:"dest_port"`
	DestIP          string `json:"dest_ip"`
	Proto           string `json:"proto"`
	SignatureID     int    `json:"signature_id"`
	SignatureRev    int    `json:"signature_rev"`
	SignatureString string `json:"signature_string"`
	Category        string `json:"category"`
	Severity        int    `json:"severity"`
	Count           int    `json:"count"`
	ProxyName       string `json:"proxy_name"`
}

func TailLog(message string) {

	tb := strings.Split(message, "eve-json")
	if len(tb) != 2 {
		log.Error().Msgf("%v Out of bound [%v]", futils.GetCalleRuntime(), message)
		return
	}
	jsonData := strings.TrimSpace(tb[1])
	var mainEvent SuricataEvent

	err := json.Unmarshal([]byte(jsonData), &mainEvent)
	if err != nil {
		log.Error().Msgf("%v Error unmarshalling JSON:%v [%v]", futils.GetCalleRuntime(), err, jsonData)
		return
	}
	mainEvent.Timestamp = FixTimeFormat(mainEvent.Timestamp)
	timestamp, err := time.Parse("2006-01-02T15:04:05.999999999-07:00", mainEvent.Timestamp)
	if err != nil {
		log.Error().Msgf("%v Error parsing timestamp: %v", futils.GetCalleRuntime(), err)
		return

	}

	var m Memjson

	m.Zdate = timestamp.Format("2006-01-02 15:04:05")
	m.ZdateMin = timestamp.Format("2006-01-02 15:04:00")
	m.EventType = mainEvent.EventType
	m.SrcIP = mainEvent.SrcIP
	m.SrcPort = mainEvent.SrcPort
	m.DestPort = mainEvent.DestPort
	m.DestIP = mainEvent.DestIP
	m.Proto = mainEvent.Proto
	m.SignatureID = mainEvent.Alert.SignatureID
	m.SignatureRev = mainEvent.Alert.Rev
	m.SignatureString = mainEvent.Alert.Signature
	m.Category = mainEvent.Alert.Category
	m.Severity = mainEvent.Alert.Severity
	m.ProxyName, _ = futils.GetHostnameFqdn()
	CountThreats++
	if m.SignatureID == 0 {
		return
	}

	SignaturesCache.Set(futils.IntToString(m.SignatureID), m.SignatureString, cache.NoExpiration)

	md5 := futils.Md5String(fmt.Sprintf("%v%v%v%v%v%d", m.ZdateMin, m.SrcIP, m.Proto, m.DestIP, m.DestPort, m.SignatureID))
	value, found := evejsonCache.Get(md5)
	if found {
		retrievedData, ok := value.(Memjson)
		if !ok {
			log.Error().Msgf("%v Error retrieving data from cache", futils.GetCalleRuntime())

		}
		retrievedData.Count = retrievedData.Count + 1
		evejsonCache.Set(md5, retrievedData, cache.NoExpiration)
	} else {
		evejsonCache.Set(md5, m, cache.NoExpiration)
	}
	_, found = SignaturesFirewallCache.Get(futils.IntToString(m.SignatureID))
	if found {
		xFirewallDFeny(m.SignatureID, m.SrcIP, m.DestPort)
	}

}
func getClassification(uniq, category string) string {

	value, found := classificationCache.Get(uniq)
	if found {
		return fmt.Sprintf("%v", value)
	}
	value, found = classificationCache.Get(category)
	if found {
		return fmt.Sprintf("%v", value)
	}
	return ""
}
func LoadClassifications(Nolloop bool) {
	EnableSuricata := sockets.GET_INFO_INT("EnableSuricata")
	DisablePostGres := sockets.GET_INFO_INT("DisablePostGres")
	if EnableSuricata == 0 {
		return
	}
	if DisablePostGres == 1 {
		return
	}
	db, err := apostgres.SQLConnectRO()
	if err != nil {
		log.Error().Msgf("%v Error connecting to database: %v", futils.GetCalleRuntime(), err)
		return
	}

	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	rows, err := db.Query("SELECT id,uduniq,description FROM suricata_classifications")
	if err != nil {
		log.Error().Msgf("%v SQL Query failed: %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var count int
	for rows.Next() {
		var id int
		var uduniq, description string

		if err := rows.Scan(&id, &uduniq, &description); err != nil {
			log.Error().Msgf("%v Row scan failed: %v", futils.GetCalleRuntime(), err)
			return
		}

		descriptionLower := strings.ToLower(description)
		classificationCache.Set(uduniq, id, cache.NoExpiration)
		classificationCache.Set(descriptionLower, id, cache.NoExpiration)
		count++
	}

	if count == 0 {
		suricataConfig.ParseClassifications()
		if !Nolloop {
			LoadClassifications(Nolloop)
		}
	}
	if !Nolloop {
		loadsigFirewall(db)
	}

}
func loadsigFirewall(db *sql.DB) {
	rows, err := db.Query("SELECT signature FROM suricata_sig WHERE enabled=1 and firewall=1")
	if err != nil {
		log.Error().Msgf("%v SQL Query failed: %v", futils.GetCalleRuntime(), err)
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	for rows.Next() {
		var signature string
		if err := rows.Scan(&signature); err != nil {
			log.Error().Msgf("%v Row scan failed: %v", futils.GetCalleRuntime(), err)
			return
		}
		SignaturesFirewallCache.Set(signature, signature, cache.NoExpiration)
	}

}
func DumpCacheItems() {

	EnableSuricata := sockets.GET_INFO_INT("EnableSuricata")
	if EnableSuricata == 0 {
		return
	}

	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v Error connecting to database: %v", futils.GetCalleRuntime(), err)
		return
	}

	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
		}
	}(db)

	items := evejsonCache.Items()

	for _, item := range items {
		m, ok := item.Object.(Memjson)
		if !ok {
			continue
		}

		_, err := db.Exec(`INSERT INTO suricata_events (zDate,src_ip,dst_ip,proto,dst_port,signature,severity,xcount,proxyname) VALUES 
		($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
			m.ZdateMin, m.SrcIP, m.DestIP, m.Proto, m.DestPort, m.SignatureID, m.Severity, m.Count, m.ProxyName)
		if err != nil {
			log.Error().Msgf("%v Error inserting data into DB: %v", futils.GetCalleRuntime(), err)
		}
	}
	evejsonCache.Flush()

	items = SignaturesCache.Items()
	for sig, item := range items {
		explain, ok := item.Object.(string)
		if !ok {
			continue
		}

		if len(explain) > 128 {
			explain = explain[:128]
		}

		_, err := db.Exec(`INSERT INTO suricata_sig (signature,description,enabled) VALUES ($1,$2,1) ON CONFLICT DO NOTHING`, sig, explain)
		if err != nil {
			log.Error().Msgf("%v Error inserting data into DB: %v", futils.GetCalleRuntime(), err)
		}
	}
	SignaturesCache.Flush()
}
func xFirewallDFeny(signatureID int, srcIP string, destPort int) {
	// Set default values

	f, err := os.OpenFile("/var/log/suricata-detected.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	defer f.Close()

	// Write log entry
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("%s sig:%d %s %d\n", timestamp, signatureID, srcIP, destPort)
	if _, err := f.WriteString(logEntry); err != nil {
		fmt.Println("Error writing to log file:", err)
	}

}

func FixTimeFormat(timestamp string) string {
	// Check if the timestamp ends with a timezone offset in the format +0100 or -0700
	if len(timestamp) > 5 && (timestamp[len(timestamp)-5] == '+' || timestamp[len(timestamp)-5] == '-') {
		// Insert a colon in the timezone offset
		return timestamp[:len(timestamp)-2] + ":" + timestamp[len(timestamp)-2:]
	}
	return timestamp
}
func EveJsonPurge() {

	SuricataPurge := sockets.GET_INFO_INT("SuricataPurge")
	if SuricataPurge == 0 {
		SuricataPurge = 15
	}

	Query := fmt.Sprintf("DELETE FROM suricata_events WHERE zdate < NOW() - INTERVAL '%d days'", SuricataPurge)
	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v Error connecting to database: %v", futils.GetCalleRuntime(), err)
		return
	}

	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	_, err = db.Exec(Query)
	if err != nil {
		log.Error().Msgf("%v Error deleting data from DB: %v", futils.GetCalleRuntime(), err)
	}

}

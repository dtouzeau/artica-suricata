package LogForward

import (
	"apostgres"
	"bufio"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"futils"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

/* =========================
   Configuration (edit here)
   ========================= */

const (
	// Path that Suricata will connect to (must match suricata.yaml filename)
	InSockPath = "/run/suricata/alerts.sock"

	// Max JSON line size accepted from Suricata (1MiB default)
	MaxJSONLineBytes = 1 << 20

	// Metrics print interval
	MetricsInterval = 10 * time.Second

	// Scan interval for dumping the in-memory EveEvent map
	ScanInterval = 20 * time.Second

	// How long to wait when queue is full before dropping a line
	QueueBlockTimeout = 500 * time.Millisecond
	QueueFailed       = "/home/suricata/queue-failed"
)

var (
	Workers   = runtime.GOMAXPROCS(0)
	QueueSize = 10_000
)

/* =========================
   Internal plumbing
   ========================= */

type job struct {
	line []byte
	ts   time.Time
}
type HTTPInfo struct {
	Hostname        string `json:"hostname"`
	URL             string `json:"url"`
	HTTPUserAgent   string `json:"http_user_agent"`
	HTTPContentType string `json:"http_content_type"`
	HTTPMethod      string `json:"http_method"`
	Protocol        string `json:"protocol"` // e.g. "HTTP/1.1"
	Status          int    `json:"status"`   // 404
	Length          int    `json:"length"`   // 196
}

type metrics struct {
	mu            sync.Mutex
	acceptedLines uint64
	droppedLines  uint64
	parsedOK      uint64
	parsedErr     uint64
	activeConns   int64
}

func (m *metrics) addAccepted() { m.mu.Lock(); m.acceptedLines++; m.mu.Unlock() }
func (m *metrics) addDropped()  { m.mu.Lock(); m.droppedLines++; m.mu.Unlock() }
func (m *metrics) addPOK()      { m.mu.Lock(); m.parsedOK++; m.mu.Unlock() }
func (m *metrics) addPErr()     { m.mu.Lock(); m.parsedErr++; m.mu.Unlock() }
func (m *metrics) incConns()    { m.mu.Lock(); m.activeConns++; m.mu.Unlock() }
func (m *metrics) decConns()    { m.mu.Lock(); m.activeConns--; m.mu.Unlock() }
func (m *metrics) snapshot() (a, d, ok, er uint64, c int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acceptedLines, m.droppedLines, m.parsedOK, m.parsedErr, m.activeConns
}

/* =========================
   EVE JSON structures
   - Extend as needed (HTTP/TLS/DNS typed sub-structs, etc.)
   ========================= */

type EveEvent struct {
	Timestamp    string          `json:"timestamp"`
	EventType    string          `json:"event_type"`
	SrcIP        string          `json:"src_ip,omitempty"`
	SrcPort      *int            `json:"src_port,omitempty"`
	DstIP        string          `json:"dst_ip,omitempty"`
	DstPort      *int            `json:"dst_port,omitempty"`
	Proto        string          `json:"proto,omitempty"`
	InIface      string          `json:"in_iface,omitempty"`
	FlowID       *uint64         `json:"flow_id,omitempty"`
	TxID         *uint64         `json:"tx_id,omitempty"`
	CommunityID  *string         `json:"community_id,omitempty"`
	Alert        *EveAlert       `json:"alert,omitempty"`
	HTTP         *HTTPInfo       `json:"http,omitempty"`
	TLS          json.RawMessage `json:"tls,omitempty"`
	DNS          json.RawMessage `json:"dns,omitempty"`
	Flow         json.RawMessage `json:"flow,omitempty"`
	UnhandledRaw json.RawMessage `json:"-"`
	Count        int             `json:"Count"`
	ProxyName    string          `json:"ProxyName"`
}

type EveAlert struct {
	Signature   string   `json:"signature"`
	SignatureID int      `json:"signature_id"`
	Category    string   `json:"category"`
	Severity    int      `json:"severity"`
	Action      string   `json:"action,omitempty"` // allowed/blocked (depends on mode)
	GID         int      `json:"gid,omitempty"`
	Rev         int      `json:"rev,omitempty"`
	Metadata    []string `json:"metadata,omitempty"`
	Rule        string   `json:"rule,omitempty"`
}

/* =========================
   Event store (MD5 → *EveEvent) + scanner
   ========================= */

var eventStore = struct {
	mu sync.Mutex
	m  map[string]*EveEvent
}{m: make(map[string]*EveEvent)}

// eventHash returns md5 hex of the JSON-marshaled event.
func eventHash(ev *EveEvent) (string, []byte, error) {
	ev.Timestamp = ""
	ev.Count = 0
	b, err := json.Marshal(ev)
	if err != nil {
		return "", nil, err
	}
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:]), b, nil
}

// LogAllEventsAndClear logs every EveEvent currently in the map.
// If clear==true, it empties the map afterwards.
func LogAllEventsAndClear(clear bool) {
	eventStore.mu.Lock()
	ProxyName := futils.LocalFQDN()

	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v Error connecting to database: %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	snap := make(map[string]*EveEvent, len(eventStore.m))
	for k, v := range eventStore.m {
		snap[k] = v
	}
	if clear {
		eventStore.m = make(map[string]*EveEvent)
	}
	eventStore.mu.Unlock()

	// Emit logs outside the lock
	for k, ev := range snap {
		b, err := json.Marshal(ev)
		if err != nil {
			log.Warn().Msgf("marshal event %s: %v", k, err)
			continue
		}
		ev.ProxyName = ProxyName
		log.Info().Msgf("EVE[%s]: %s", k, string(b))
	}
}
func injectToDB(db *sql.DB, m *EveEvent) bool {

	_, err := db.Exec(`INSERT INTO suricata_events (zDate,src_ip,dst_ip,proto,dst_port,signature,severity,xcount,proxyname) VALUES 
		($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
		m.Timestamp, m.SrcIP, m.DstIP, m.Proto, m.DstPort, m.Alert.SignatureID, m.Alert.Severity, m.Count, m.ProxyName)
	if err == nil {
		return true
	}
	log.Error().Msgf("%v Error inserting into database: %v", futils.GetCalleRuntime(), err)

	b, err := json.Marshal(m)
	if err != nil {
		log.Error().Msgf("%v Error marshaling event: %v", futils.GetCalleRuntime(), err)
		return false
	}
	// save into disk in order to return back later ( see cron function )
	sFname := futils.Md5String(string(b))
	fname := "/home/suricata/queue-failed/" + sFname + ".json"
	if futils.FileExists(fname) {
		return false
	}
	futils.CreateDir(QueueFailed)
	err = futils.FilePutContents(fname, string(b))
	if err != nil {
		log.Error().Msgf("%v Error writing to file: %v", futils.GetCalleRuntime(), err)
		return false
	}
	return false

}

func ParseQueueFailed() {

	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v Error connecting to database: %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	if !futils.IsDirDirectory(QueueFailed) {
		return
	}
	files := futils.DirectoryScan(QueueFailed)
	for _, sfile := range files {
		fullPath := QueueFailed + "/" + sfile
		if !strings.HasSuffix(sfile, ".json") {
			futils.DeleteFile(fullPath)
			continue
		}

		MinutesLive := futils.FileTimeMin(fullPath)
		// if TTL > 240 -> aborting completely
		if MinutesLive > 240 {
			futils.DeleteFile(fullPath)
			continue
		}
		var ev *EveEvent
		data := futils.FileGetContents(fullPath)
		err := json.Unmarshal([]byte(data), &ev)
		if err != nil {
			futils.DeleteFile(fullPath)
			log.Error().Msgf("%v Error unmarshaling file: %v", futils.GetCalleRuntime(), err)
			continue
		}
		if injectToDB(db, ev) {
			futils.DeleteFile(fullPath)
		}
	}

}
func parseLine(b []byte) (*EveEvent, error) {
	var ev EveEvent
	if err := json.Unmarshal(b, &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

// handleEvent stores the event in the MD5-keyed map and logs compact info for alerts.
func handleEvent(ev *EveEvent) {
	Count := ev.Count
	h, _, err := eventHash(ev)
	if err != nil {
		log.Warn().Msgf("event hash error: %v", err)
		return
	}

	if len(ev.EventType) == 0 {
		log.Warn().Msgf("event type missing: %v", err)
		return
	}

	eventStore.mu.Lock()
	ev.Timestamp = futils.TimeStampToString()
	if _, exists := eventStore.m[h]; exists {
		eventStore.m[h].Count += Count
		eventStore.mu.Unlock()
		return
	}
	eventStore.m[h] = ev
	eventStore.mu.Unlock()

}
func Start() {
	// Prepare listener socket (remove stale, bind, chmod)
	_ = os.Remove(InSockPath)

	ln, err := net.Listen("unix", InSockPath)
	if err != nil {
		log.Error().Msgf("%v listen(%s): %v", futils.GetCalleRuntime(), InSockPath, err)
		return // critical: don't continue with a nil listener
	}
	defer ln.Close()

	if err := os.Chmod(InSockPath, 0660); err != nil {
		log.Error().Msgf("%v chmod(%s): %v", futils.GetCalleRuntime(), InSockPath, err)
		// Optional: return if perms are critical for Suricata to connect
	}

	// Graceful shutdown via SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	queue := make(chan job, QueueSize)
	var wg sync.WaitGroup
	var m metrics

	// Worker pool
	for i := 0; i < Workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j, ok := <-queue:
					if !ok {
						return
					}
					ev, err := parseLine(j.line)
					if err != nil {
						m.addPErr()
						continue
					}
					m.addPOK()
					handleEvent(ev)
				}
			}
		}(i)
	}

	// Metrics printer
	go func() {
		t := time.NewTicker(MetricsInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a, d, ok, er, c := m.snapshot()
				log.Info().Msgf("metrics: accepted=%d dropped=%d parsed_ok=%d parsed_err=%d active_conns=%d", a, d, ok, er, c)
			}
		}
	}()

	// Periodic scan-and-log of all stored events every 20s (no clear)
	go func() {
		t := time.NewTicker(ScanInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				LogAllEventsAndClear(false) // set to true to empty the map after logging
			}
		}
	}()

	log.Info().Msgf("suri-forwarder-parse: listening on %s; workers=%d queue=%d", InSockPath, Workers, QueueSize)

	// Accept loop
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// listener closed or context canceled → exit loop
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					return
				}
				log.Warn().Msgf("accept: %v", err)
				continue
			}
			m.incConns()
			go func(c net.Conn) {
				defer func() {
					_ = c.Close()
					m.decConns()
				}()
				if err := handleConn(ctx, c, queue, &m); err != nil && ctx.Err() == nil {
					log.Warn().Msgf("%v conn handler: %v", futils.GetCalleRuntime(), err)
				}
			}(conn)
		}
	}()

	// Wait for signal, then drain
	<-ctx.Done()
	log.Warn().Msgf("%v shutting down…", futils.GetCalleRuntime())
	_ = ln.Close()
	time.Sleep(300 * time.Millisecond) // let in-flight scanner writes finish
	close(queue)
	wg.Wait()
	log.Info().Msg("bye.")
}
func handleConn(ctx context.Context, c net.Conn, queue chan<- job, m *metrics) error {
	sc := bufio.NewScanner(c)
	buf := make([]byte, 0, 256*1024) // initial buffer
	sc.Buffer(buf, MaxJSONLineBytes)

	for sc.Scan() {
		line := sc.Bytes()
		cp := make([]byte, len(line)) // copy because Scanner reuses buffer
		copy(cp, line)

		j := job{line: cp, ts: time.Now()}

		// Non-blocking enqueue, short wait, else drop (backpressure)
		select {
		case queue <- j:
			m.addAccepted()
		default:
			select {
			case queue <- j:
				m.addAccepted()
			case <-time.After(QueueBlockTimeout):
				m.addDropped()
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("scan: %w", err)
	}
	return nil
}

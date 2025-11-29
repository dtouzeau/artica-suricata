package LogForward

import (
	"LogForward/FileBeatForwarder"
	"LogForward/LogStruct"
	"SuriStructs"
	"SuriTables"
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
	"ipclass"
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

var DroppedEvents int64
var ReceivedEvents int64
var GlobalConfig SuriStructs.SuriDaemon
var FileBeatFw *FileBeatForwarder.FileBeatForwarder

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
)

var (
	Workers     = runtime.GOMAXPROCS(0)
	QueueSize   = 10_000
	AlertsCount int64
)

/* =========================
   Internal plumbing
   ========================= */

type job struct {
	line []byte
	ts   time.Time
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

/* =========================
   Event store (MD5 → *LogStruct.EveEvent) + scanner
   ========================= */

var eventStore = struct {
	mu sync.Mutex
	m  map[string]*LogStruct.EveEvent
}{m: make(map[string]*LogStruct.EveEvent)}

// eventHash returns md5 hex of the JSON-marshaled event.
func eventHash(ev *LogStruct.EveEvent) (string, []byte, error) {
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

	snap := make(map[string]*LogStruct.EveEvent, len(eventStore.m))
	for k, v := range eventStore.m {
		snap[k] = v
	}
	if clear {
		eventStore.m = make(map[string]*LogStruct.EveEvent)
	}
	eventStore.mu.Unlock()

	// Emit logs outside the lock
	for k, ev := range snap {
		b, err := json.Marshal(ev)
		if err != nil {
			log.Warn().Msgf("%v marshal event %s: %v", futils.GetCalleRuntime(), k, err)
			continue
		}
		ev.ProxyName = ProxyName
		if ev.EventType == "alert" {
			AlertsCount++
			injectToDB(db, ev)
			continue
		}

		log.Info().Msgf("%v EVE[%s]: %s", futils.GetCalleRuntime(), k, string(b))
	}
}
func injectToDB(db *sql.DB, m *LogStruct.EveEvent) bool {

	// Parse RFC3339 timestamp from Suricata EVE JSON
	var sTime string
	if len(m.Timestamp) > 0 {
		// Try to parse RFC3339 format (e.g., "2025-11-24T19:30:16.123456+0100")
		t, err := time.Parse(time.RFC3339Nano, m.Timestamp)
		if err != nil {
			// Fallback: try RFC3339 without nanoseconds
			t, err = time.Parse(time.RFC3339, m.Timestamp)
			if err != nil {
				//log.Warn().Msgf("%v Failed to parse timestamp '%s': %v (using current time)", futils.GetCalleRuntime(), m.Timestamp, err)
				sTime = time.Now().Format("2006-01-02 15:04:05")
			} else {
				sTime = t.Format("2006-01-02 15:04:05")
			}
		} else {
			sTime = t.Format("2006-01-02 15:04:05")
		}
	} else {
		sTime = time.Now().Format("2006-01-02 15:04:05")
	}

	// Handle both dest_ip and dst_ip (Suricata uses dest_ip, but keep backwards compatibility)
	destIP := m.DestIP
	if len(destIP) == 0 {
		destIP = m.DstIP
	}
	if !ipclass.IsIPAddress(destIP) {
		destIP = "0.0.0.0"
	}

	if m.DstPort == nil {
		m.DstPort = new(int)
	}

	_, err := db.Exec(`INSERT INTO suricata_events (zDate,src_ip,dst_ip,proto,dst_port,signature,severity,xcount,proxyname) VALUES
		($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
		sTime, m.SrcIP, destIP, m.Proto, m.DstPort, m.Alert.SignatureID, m.Alert.Severity, m.Count, m.ProxyName)
	if err == nil {
		return true
	}

	sqlog := fmt.Sprintf("INSERT INTO suricata_events (zDate,src_ip,dst_ip,proto,dst_port,signature,severity,xcount,proxyname) VALUES ('%v','%v','%v','%v','%v','%v','%v','%v','%v') ON CONFLICT DO NOTHING", sTime, m.SrcIP, destIP, m.Proto, m.DstPort, m.Alert.SignatureID, m.Alert.Severity, m.Count, m.ProxyName)

	log.Error().Msgf("%v Error inserting into database: %v", futils.GetCalleRuntime(), err)
	log.Error().Msg(sqlog)
	Cfg := SuriStructs.LoadConfig()

	if strings.Contains(err.Error(), "does not exist") {
		SuriTables.Check()
		_, err = db.Exec(`INSERT INTO suricata_events (zDate,src_ip,dst_ip,proto,dst_port,signature,severity,xcount,proxyname) VALUES
		($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
			sTime, m.SrcIP, destIP, m.Proto, m.DstPort, m.Alert.SignatureID, m.Alert.Severity, m.Count, m.ProxyName)
		if err == nil {
			return true
		}
	}

	if Cfg.UseQueueFailed == 0 {
		return true
	}

	b, err := json.Marshal(m)
	if err != nil {
		log.Error().Msgf("%v Error marshaling event: %v", futils.GetCalleRuntime(), err)
		return false
	}
	// save into disk in order to return back later ( see cron function )
	sFname := futils.Md5String(string(b))
	fname := Cfg.QueueFailed + "/" + sFname + ".json"
	if futils.FileExists(fname) {
		return false
	}

	futils.CreateDir(Cfg.QueueFailed)
	err = futils.FilePutContents(fname, string(b))
	if err != nil {
		log.Error().Msgf("%v Error writing to file: %v", futils.GetCalleRuntime(), err)
		return false
	}
	return false

}
func CleanQueueFailed() {
	Cfg := SuriStructs.LoadConfig()
	if len(Cfg.QueueFailed) < 4 {
		log.Debug().Msgf("%v QueueFailed path is too short: %v", futils.GetCalleRuntime(), Cfg.QueueFailed)
		return
	}
	if !futils.IsDirDirectory(Cfg.QueueFailed) {
		log.Debug().Msgf("%v QueueFailed path is not a directory: %v", futils.GetCalleRuntime(), Cfg.QueueFailed)
		return
	}
	files := futils.DirectoryScan(Cfg.QueueFailed)
	for _, sfile := range files {
		fullPath := Cfg.QueueFailed + "/" + sfile
		log.Debug().Msgf("%v remove %v", futils.GetCalleRuntime(), fullPath)
		futils.DeleteFile(fullPath)
	}

}
func ParseQueueFailed() {
	Cfg := SuriStructs.LoadConfig()
	if Cfg.UseQueueFailed == 0 {
		CleanQueueFailed()
		return
	}

	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v Error connecting to database: %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	if !futils.IsDirDirectory(Cfg.QueueFailed) {
		return
	}
	files := futils.DirectoryScan(Cfg.QueueFailed)
	for _, sfile := range files {
		fullPath := Cfg.QueueFailed + "/" + sfile
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
		var ev *LogStruct.EveEvent
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
func parseLine(b []byte) (*LogStruct.EveEvent, error) {
	//log.Info().Msgf("%v [DEBUG] parsing line: %s", futils.GetCalleRuntime(), string(b))
	var ev LogStruct.EveEvent
	if err := json.Unmarshal(b, &ev); err != nil {
		// Log first 300 chars of the problematic JSON for debugging
		preview := string(b)
		if len(preview) > 500 {
			preview = preview[:500] + "..."
		}
		log.Error().Msgf("%v JSON unmarshal error: %v | Data preview: [%s]", futils.GetCalleRuntime(), err, preview)
		return nil, err
	}
	return &ev, nil
}

// handleEvent stores the event in the MD5-keyed map and logs compact info for alerts.
func handleEvent(ev *LogStruct.EveEvent) {
	Count := ev.Count
	ReceivedEvents++

	// Handle both dest_ip and dst_ip for display
	destIP := ev.DestIP
	if len(destIP) == 0 {
		destIP = ev.DstIP
	}

	// Enhanced logging for ICMP alerts
	eventDesc := ev.SrcIP + " -> " + destIP
	if ev.ICMPType != nil && ev.ICMPCode != nil {
		eventDesc += fmt.Sprintf(" (ICMP type=%d code=%d)", *ev.ICMPType, *ev.ICMPCode)
	}
	log.Info().Msgf("%v event[%v]: %v", futils.GetCalleRuntime(), ev.EventType, eventDesc)

	if ev.EventType != "alert" {
		if GlobalConfig.EveLogsType[ev.EventType] == 0 {
			DroppedEvents++
			return
		}
	}

	h, _, err := eventHash(ev)
	if err != nil {
		log.Warn().Msgf("%v event hash error: %v", futils.GetCalleRuntime(), err)
		return
	}

	if len(ev.EventType) == 0 {
		log.Warn().Msgf("%v event type missing", futils.GetCalleRuntime())
		return
	}

	// Validate alert events have Alert field
	if ev.EventType == "alert" && ev.Alert == nil {
		log.Warn().Msgf("%v alert event missing alert field: %s -> %s", futils.GetCalleRuntime(), ev.SrcIP, destIP)
		return
	}
	if FileBeatFw != nil {
		if err := FileBeatFw.ProcessEvent(*ev); err != nil {
			log.Warn().Msgf("%v FileBeat forwarding failed (event_type=%s): %v", futils.GetCalleRuntime(), ev.EventType, err)
		}
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
	GlobalConfig = SuriStructs.LoadConfig()
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

	if GlobalConfig.Filebeat.Enabled == 1 {

		config := &FileBeatForwarder.Config{
			UnixSocketPath: GlobalConfig.Filebeat.UnixSocket,
			ReconnectWait:  time.Duration(5) * time.Second,
			BufferSize:     4096,
			WriteTimeout:   time.Duration(5) * time.Second,
			MaxRetries:     3,
		}

		FileBeatFw = FileBeatForwarder.NewFileBeatForwarder(config)

		// Initial connection attempt
		if err := FileBeatFw.Connect(); err != nil {
			log.Warn().Msgf("Initial Filebeat connection failed: %v (will retry on first event)", err)
		}
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
				log.Info().Msgf("%v metrics: accepted=%d dropped=%d parsed_ok=%d parsed_err=%d active_conns=%d", futils.GetCalleRuntime(), a, d, ok, er, c)
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

	log.Info().Msgf("%v listening on %s; workers=%d queue=%d", futils.GetCalleRuntime(), InSockPath, Workers, QueueSize)

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

	if FileBeatFw != nil {
		FileBeatFw.LogStats()
		FileBeatFw.Disconnect()
	}

	time.Sleep(300 * time.Millisecond) // let in-flight scanner writes finish
	close(queue)
	wg.Wait()
	log.Info().Msgf("%v bye.", futils.GetCalleRuntime())
}
func ReloadConfig() {
	GlobalConfig = SuriStructs.LoadConfig()
	log.Info().Msgf("%v done", futils.GetCalleRuntime())
	log.Info().Msgf("%v Wazuh integration=%d", futils.GetCalleRuntime(), GlobalConfig.Wazuh.Enabled)
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

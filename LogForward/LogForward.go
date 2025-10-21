package LogForward

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
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

	// How long to wait when queue is full before dropping a line
	QueueBlockTimeout = 500 * time.Millisecond
)

var (
	// Number of worker goroutines to parse & handle events
	Workers = runtime.GOMAXPROCS(0)

	// Bounded queue size for pending lines
	QueueSize = 10_000
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
	HTTP         json.RawMessage `json:"http,omitempty"`
	TLS          json.RawMessage `json:"tls,omitempty"`
	DNS          json.RawMessage `json:"dns,omitempty"`
	Flow         json.RawMessage `json:"flow,omitempty"`
	UnhandledRaw json.RawMessage `json:"-"`
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

func parseLine(b []byte) (*EveEvent, error) {
	var ev EveEvent
	if err := json.Unmarshal(b, &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

// handleEvent is your hook: DB write, Redis, ipset, logs, etc.
func handleEvent(ev *EveEvent) {
	// Example: compact log for alerts only
	if ev.EventType == "alert" && ev.Alert != nil {
		log.Printf(`ALERT sig="%s" sid=%d sev=%d src=%s dst=%s`,
			ev.Alert.Signature, ev.Alert.SignatureID, ev.Alert.Severity, ev.SrcIP, ev.DstIP)
	}
}

/* =========================
   Main
   ========================= */

func Start() {
	// Prepare listener socket (remove stale, bind, chmod)
	_ = os.Remove(InSockPath)
	ln, err := net.Listen("unix", InSockPath)
	if err != nil {
		log.Error().Msgf("%v listen(%s): %v", futils.GetCalleRuntime(), InSockPath, err)
	}
	defer func(ln net.Listener) {
		_ = ln.Close()

	}(ln)
	_ = os.Chmod(InSockPath, 0660)

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

	log.Info().Msgf("suri-forwarder-parse: listening on %s; workers=%d queue=%d", InSockPath, Workers, QueueSize)

	// Accept loop
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					return
				}
				log.Info().Msgf("accept: %v", err)
				continue
			}
			m.incConns()
			go func(c net.Conn) {
				defer func() {
					_ = c.Close()
					m.decConns()
				}()
				if err := handleConn(ctx, c, queue, &m); err != nil && ctx.Err() == nil {
					log.Info().Msgf("%v conn handler: %v", futils.GetCalleRuntime(), err)
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
	log.Printf("bye.")
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

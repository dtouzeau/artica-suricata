package WazuhForwarder

import (
	"LogForward/LogStruct"
	"encoding/json"
	"fmt"
	"futils"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Config holds the application configuration
type Config struct {
	UnixSocketPath string
	ReconnectWait  time.Duration
	BufferSize     int
	WriteTimeout   time.Duration // Timeout for write operations
	MaxRetries     int           // Maximum connection retry attempts
}

// WazuhForwarder manages the connection and forwarding to Wazuh
type WazuhForwarder struct {
	config          *Config
	conn            net.Conn
	connMu          sync.Mutex   // Protects conn
	eventCount      atomic.Int64 // Total events sent
	errorCount      atomic.Int64 // Total errors
	reconnectCount  atomic.Int64 // Total reconnection attempts
	lastConnectTime time.Time
	isConnected     atomic.Bool
}

// NewWazuhForwarder creates a new forwarder instance
func NewWazuhForwarder(config *Config) *WazuhForwarder {
	// Set defaults if not specified
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 5 * time.Second
	}
	if config.ReconnectWait == 0 {
		config.ReconnectWait = 5 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}

	wf := &WazuhForwarder{
		config:          config,
		lastConnectTime: time.Now(),
	}
	wf.isConnected.Store(false)

	log.Info().Msgf("%v Wazuh forwarder initialized: socket=%s, timeout=%v, retries=%d",
		futils.GetCalleRuntime(), config.UnixSocketPath, config.WriteTimeout, config.MaxRetries)

	return wf
}

// Connect establishes connection to Wazuh Unix socket with retries
func (w *WazuhForwarder) Connect() error {
	w.connMu.Lock()
	defer w.connMu.Unlock()

	// Close existing connection if any
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}

	var lastErr error
	for attempt := 1; attempt <= w.config.MaxRetries; attempt++ {
		conn, err := net.Dial("unix", w.config.UnixSocketPath)
		if err == nil {
			w.conn = conn
			w.lastConnectTime = time.Now()
			w.isConnected.Store(true)
			w.reconnectCount.Add(1)
			log.Info().Msgf("%v Connected to Wazuh socket: %s (attempt %d/%d)",
				futils.GetCalleRuntime(), w.config.UnixSocketPath, attempt, w.config.MaxRetries)
			return nil
		}

		lastErr = err
		if attempt < w.config.MaxRetries {
			log.Warn().Msgf("%v Connection attempt %d/%d failed: %v, retrying in %v",
				futils.GetCalleRuntime(), attempt, w.config.MaxRetries, err, w.config.ReconnectWait)
			time.Sleep(w.config.ReconnectWait)
		}
	}

	w.isConnected.Store(false)
	return fmt.Errorf("failed to connect to Wazuh after %d attempts: %v", w.config.MaxRetries, lastErr)
}

// Disconnect closes the connection to Wazuh
func (w *WazuhForwarder) Disconnect() {
	w.connMu.Lock()
	defer w.connMu.Unlock()

	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
		w.isConnected.Store(false)
		log.Info().Msgf("%v Disconnected from Wazuh", futils.GetCalleRuntime())
	}
}

// IsConnected returns the current connection status
func (w *WazuhForwarder) IsConnected() bool {
	return w.isConnected.Load()
}

// SendEvent sends a single event to Wazuh with automatic reconnection
func (w *WazuhForwarder) SendEvent(eventJSON []byte) error {
	// Ensure we have a connection
	w.connMu.Lock()
	if w.conn == nil {
		w.connMu.Unlock()
		if err := w.Connect(); err != nil {
			w.errorCount.Add(1)
			return err
		}
		w.connMu.Lock()
	}
	conn := w.conn
	w.connMu.Unlock()

	// Wazuh expects newline-delimited JSON
	message := append(eventJSON, '\n')

	// Set write deadline to prevent hanging
	if err := conn.SetWriteDeadline(time.Now().Add(w.config.WriteTimeout)); err != nil {
		w.errorCount.Add(1)
		log.Warn().Msgf("%v Failed to set write deadline: %v", futils.GetCalleRuntime(), err)
	}

	n, err := conn.Write(message)
	if err != nil {
		w.errorCount.Add(1)
		w.isConnected.Store(false)
		log.Warn().Msgf("%v Write error (will reconnect): %v", futils.GetCalleRuntime(), err)
		w.Disconnect()

		// Attempt immediate reconnection
		if reconnErr := w.Connect(); reconnErr != nil {
			return fmt.Errorf("failed to send event and reconnect failed: %v (original: %v)", reconnErr, err)
		}

		// Retry write after reconnection
		w.connMu.Lock()
		if w.conn != nil {
			_ = w.conn.SetWriteDeadline(time.Now().Add(w.config.WriteTimeout))
			n, err = w.conn.Write(message)
			w.connMu.Unlock()
			if err != nil {
				w.errorCount.Add(1)
				return fmt.Errorf("retry write failed: %v", err)
			}
		} else {
			w.connMu.Unlock()
			return fmt.Errorf("connection lost after reconnect attempt")
		}
	}

	if n != len(message) {
		w.errorCount.Add(1)
		return fmt.Errorf("incomplete write: sent %d/%d bytes", n, len(message))
	}

	w.eventCount.Add(1)
	return nil
}

// ProcessEvent processes and enriches a Suricata event before sending
func (w *WazuhForwarder) ProcessEvent(event LogStruct.EveEvent) error {
	// Marshal the event to JSON first
	eventJSON, err := json.Marshal(event)
	if err != nil {
		w.errorCount.Add(1)
		return fmt.Errorf("failed to marshal event: %v", err)
	}

	// Unmarshal into raw map to preserve all fields and add enrichments
	var rawEvent map[string]interface{}
	if err := json.Unmarshal(eventJSON, &rawEvent); err != nil {
		w.errorCount.Add(1)
		return fmt.Errorf("failed to parse event: %v", err)
	}

	// Add metadata for Wazuh integration
	rawEvent["integration"] = "suricata"

	// Use nested map for integration metadata (Wazuh standard format)
	integrationMeta := map[string]string{
		"name": "suricata-eve-forwarder",
		"type": "ids",
	}
	rawEvent["integration_metadata"] = integrationMeta

	// Re-marshal with enrichments
	enrichedJSON, err := json.Marshal(rawEvent)
	if err != nil {
		w.errorCount.Add(1)
		return fmt.Errorf("failed to marshal enriched event: %v", err)
	}

	// Send to Wazuh
	return w.SendEvent(enrichedJSON)
}

// GetStats returns current forwarder statistics
func (w *WazuhForwarder) GetStats() (eventsSent, errors, reconnects int64, connected bool, uptime time.Duration) {
	return w.eventCount.Load(),
		w.errorCount.Load(),
		w.reconnectCount.Load(),
		w.isConnected.Load(),
		time.Since(w.lastConnectTime)
}

// LogStats logs current statistics
func (w *WazuhForwarder) LogStats() {
	events, errs, reconns, connected, uptime := w.GetStats()
	status := "disconnected"
	if connected {
		status = "connected"
	}
	log.Info().Msgf("%v Wazuh stats: status=%s, events=%d, errors=%d, reconnects=%d, uptime=%v",
		futils.GetCalleRuntime(), status, events, errs, reconns, uptime)
}

// ResetStats resets all counters (useful for testing)

func (w *WazuhForwarder) ResetStats() {
	w.eventCount.Store(0)
	w.errorCount.Store(0)
	w.reconnectCount.Store(0)
	log.Debug().Msgf("%v Statistics reset", futils.GetCalleRuntime())
}

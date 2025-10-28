package surisock

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"futils"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Top-level reply envelope.
type Reply struct {
	Return  string  `json:"return"`  // "OK" or "NOK"
	Message Message `json:"message"` // payload
}

// ==== Message root ====

type Message struct {
	Uptime       int64         `json:"uptime"`
	Capture      Capture       `json:"capture"`
	Decoder      Decoder       `json:"decoder"`
	TCP          TCPStats      `json:"tcp"`
	Flow         FlowStats     `json:"flow"`
	Defrag       DefragStats   `json:"defrag"`
	FlowBypassed FlowBypassed  `json:"flow_bypassed"`
	Detect       DetectStats   `json:"detect"`
	AppLayer     AppLayerStats `json:"app_layer"`
	Memcap       MemcapStats   `json:"memcap"`
	HTTP         HTTPStats     `json:"http"`
	FTP          MemOnly       `json:"ftp"`
	IPPair       MemCap        `json:"ippair"`
	Host         MemCap        `json:"host"`
	FileStore    FileStore     `json:"file_store"`

	// Per-thread sections keyed by thread name (e.g., "W#01-eth0", "FM#01", "FR#01", ...).
	Threads map[string]ThreadSnapshot `json:"threads"`

	// Additional named sections present in your sample:
	FM01   *FMSection    `json:"FM#01,omitempty"`
	FR01   *FRSection    `json:"FR#01,omitempty"`
	Global *GlobalTotals `json:"Global,omitempty"`
}

// ==== Basic leaf structs ====
type Capture struct {
	KernelPackets int64 `json:"kernel_packets"`
	KernelDrops   int64 `json:"kernel_drops"`
	Bypassed      int64 `json:"bypassed"`
}
type Decoder struct {
	Pkts             int64 `json:"pkts"`
	Bytes            int64 `json:"bytes"`
	Invalid          int64 `json:"invalid"`
	IPv4             int64 `json:"ipv4"`
	IPv6             int64 `json:"ipv6"`
	Ethernet         int64 `json:"ethernet"`
	ARP              int64 `json:"arp"`
	UnknownEthertype int64 `json:"unknown_ethertype"`
	Chdlc            int64 `json:"chdlc"`
	Raw              int64 `json:"raw"`
	Null             int64 `json:"null"`
	Sll              int64 `json:"sll"`
	Sll2             int64 `json:"sll2"`
	TCP              int64 `json:"tcp"`
	UDP              int64 `json:"udp"`
	SCTP             int64 `json:"sctp"`
	ESP              int64 `json:"esp"`
	ICMPv4           int64 `json:"icmpv4"`
	ICMPv6           int64 `json:"icmpv6"`
	PPP              int64 `json:"ppp"`
	PPPoE            int64 `json:"pppoe"`
	Geneve           int64 `json:"geneve"`
	GRE              int64 `json:"gre"`
	VLAN             int64 `json:"vlan"`
	VLANQinQ         int64 `json:"vlan_qinq"`
	VLANQinQinQ      int64 `json:"vlan_qinqinq"`
	VXLAN            int64 `json:"vxlan"`
	Vntag            int64 `json:"vntag"`
	IEEE8021ah       int64 `json:"ieee8021ah"`
	Teredo           int64 `json:"teredo"`
	IPv4InIPv4       int64 `json:"ipv4_in_ipv4"`
	IPv6InIPv4       int64 `json:"ipv6_in_ipv4"`
	IPv4InIPv6       int64 `json:"ipv4_in_ipv6"`
	IPv6InIPv6       int64 `json:"ipv6_in_ipv6"`
	MPLS             int64 `json:"mpls"`
	AvgPktSize       int64 `json:"avg_pkt_size"`
	MaxPktSize       int64 `json:"max_pkt_size"`
	MaxMacAddrsSrc   int64 `json:"max_mac_addrs_src"`
	MaxMacAddrsDst   int64 `json:"max_mac_addrs_dst"`
	ERSPAN           int64 `json:"erspan"`
	NSH              int64 `json:"nsh"`
	TooManyLayers    int64 `json:"too_many_layers"`

	// Very wide nested counters; keep as maps of maps for flexibility.
	// e.g. "event": { "ipv4": {"pkt_too_small":0, ...}, "icmpv4": {...}, ... }
	Event map[string]map[string]int64 `json:"event"`
}
type TCPStats struct {
	SYN                   int64 `json:"syn"`
	SYNACK                int64 `json:"synack"`
	RST                   int64 `json:"rst"`
	URG                   int64 `json:"urg"`
	ActiveSessions        int64 `json:"active_sessions"`
	Sessions              int64 `json:"sessions"`
	SsnMemcapDrop         int64 `json:"ssn_memcap_drop"`
	SsnFromCache          int64 `json:"ssn_from_cache"`
	SsnFromPool           int64 `json:"ssn_from_pool"`
	Pseudo                int64 `json:"pseudo"`
	InvalidChecksum       int64 `json:"invalid_checksum"`
	MidstreamPickups      int64 `json:"midstream_pickups"`
	PktOnWrongThread      int64 `json:"pkt_on_wrong_thread"`
	AckUnseenData         int64 `json:"ack_unseen_data"`
	SegmentMemcapDrop     int64 `json:"segment_memcap_drop"`
	SegmentFromCache      int64 `json:"segment_from_cache"`
	SegmentFromPool       int64 `json:"segment_from_pool"`
	StreamDepthReached    int64 `json:"stream_depth_reached"`
	ReassemblyGap         int64 `json:"reassembly_gap"`
	Overlap               int64 `json:"overlap"`
	OverlapDiffData       int64 `json:"overlap_diff_data"`
	InsertDataNormalFail  int64 `json:"insert_data_normal_fail"`
	InsertDataOverlapFail int64 `json:"insert_data_overlap_fail"`
	UrgentOOBData         int64 `json:"urgent_oob_data"`
	MemUse                int64 `json:"memuse,omitempty"`
	ReassemblyMemUse      int64 `json:"reassembly_memuse,omitempty"`
}
type FlowStats struct {
	Memcap            int64 `json:"memcap"`
	Total             int64 `json:"total"`
	Active            int64 `json:"active"`
	TCP               int64 `json:"tcp"`
	UDP               int64 `json:"udp"`
	ICMPv4            int64 `json:"icmpv4"`
	ICMPv6            int64 `json:"icmpv6"`
	TCPReuse          int64 `json:"tcp_reuse"`
	Elephant          int64 `json:"elephant"`
	GetUsed           int64 `json:"get_used"`
	GetUsedEval       int64 `json:"get_used_eval"`
	GetUsedEvalReject int64 `json:"get_used_eval_reject"`
	GetUsedEvalBusy   int64 `json:"get_used_eval_busy"`
	GetUsedFailed     int64 `json:"get_used_failed"`

	WRK              WRKStats      `json:"wrk"`
	End              EndStats      `json:"end"`
	Mgr              MgrStats      `json:"mgr"`
	Spare            int64         `json:"spare"`
	EmergModeEntered int64         `json:"emerg_mode_entered"`
	EmergModeOver    int64         `json:"emerg_mode_over"`
	Recycler         RecyclerStats `json:"recycler"`
	MemUse           int64         `json:"memuse,omitempty"`
}
type WRKStats struct {
	SpareSyncAvg          int64 `json:"spare_sync_avg"`
	SpareSync             int64 `json:"spare_sync"`
	SpareSyncIncomplete   int64 `json:"spare_sync_incomplete"`
	SpareSyncEmpty        int64 `json:"spare_sync_empty"`
	FlowsEvictedNeedsWork int64 `json:"flows_evicted_needs_work"`
	FlowsEvictedPktInject int64 `json:"flows_evicted_pkt_inject"`
	FlowsEvicted          int64 `json:"flows_evicted"`
	FlowsInjected         int64 `json:"flows_injected"`
	FlowsInjectedMax      int64 `json:"flows_injected_max"`
}
type EndStats struct {
	State      FlowState    `json:"state"`
	TCPState   FlowTCPState `json:"tcp_state"`
	TCPLiberal int64        `json:"tcp_liberal"`
}
type FlowState struct {
	New             int64 `json:"new"`
	Established     int64 `json:"established"`
	Closed          int64 `json:"closed"`
	LocalBypassed   int64 `json:"local_bypassed"`
	CaptureBypassed int64 `json:"capture_bypassed"`
}
type FlowTCPState struct {
	None        int64 `json:"none"`
	SynSent     int64 `json:"syn_sent"`
	SynRecv     int64 `json:"syn_recv"`
	Established int64 `json:"established"`
	FinWait1    int64 `json:"fin_wait1"`
	FinWait2    int64 `json:"fin_wait2"`
	TimeWait    int64 `json:"time_wait"`
	LastAck     int64 `json:"last_ack"`
	CloseWait   int64 `json:"close_wait"`
	Closing     int64 `json:"closing"`
	Closed      int64 `json:"closed"`
}
type MgrStats struct {
	FullHashPass          int64 `json:"full_hash_pass"`
	RowsPerSec            int64 `json:"rows_per_sec"`
	RowsMaxLen            int64 `json:"rows_maxlen"`
	FlowsChecked          int64 `json:"flows_checked"`
	FlowsNoTimeout        int64 `json:"flows_notimeout"`
	FlowsTimeout          int64 `json:"flows_timeout"`
	FlowsEvicted          int64 `json:"flows_evicted"`
	FlowsEvictedNeedsWork int64 `json:"flows_evicted_needs_work"`
}
type RecyclerStats struct {
	Recycled int64 `json:"recycled"`
	QueueAvg int64 `json:"queue_avg"`
	QueueMax int64 `json:"queue_max"`
}
type DefragStats struct {
	IPv4               FragPair `json:"ipv4"`
	IPv6               FragPair `json:"ipv6"`
	MaxTrackersReached int64    `json:"max_trackers_reached"`
	MaxFragsReached    int64    `json:"max_frags_reached"`
	TrackerSoftReuse   int64    `json:"tracker_soft_reuse"`
	TrackerHardReuse   int64    `json:"tracker_hard_reuse"`
	WRK                struct {
		TrackerTimeout int64 `json:"tracker_timeout"`
	} `json:"wrk"`
	Mgr struct {
		TrackerTimeout int64 `json:"tracker_timeout"`
	} `json:"mgr"`
	MemUse int64 `json:"memuse"`
}
type FragPair struct {
	Fragments   int64 `json:"fragments"`
	Reassembled int64 `json:"reassembled"`
}
type FlowBypassed struct {
	LocalPkts         int64 `json:"local_pkts"`
	LocalBytes        int64 `json:"local_bytes"`
	LocalCapturePkts  int64 `json:"local_capture_pkts"`
	LocalCaptureBytes int64 `json:"local_capture_bytes"`
	Closed            int64 `json:"closed"`
	Pkts              int64 `json:"pkts"`
	Bytes             int64 `json:"bytes"`
}
type DetectStats struct {
	Engines []struct {
		ID           int64  `json:"id"`
		LastReload   string `json:"last_reload"`
		RulesLoaded  int64  `json:"rules_loaded"`
		RulesFailed  int64  `json:"rules_failed"`
		RulesSkipped int64  `json:"rules_skipped"`
	} `json:"engines"`
	Alert              int64 `json:"alert"`
	AlertQueueOverflow int64 `json:"alert_queue_overflow"`
	AlertsSuppressed   int64 `json:"alerts_suppressed"`
	Lua                struct {
		Errors                 int64 `json:"errors"`
		BlockedFunctionErrors  int64 `json:"blocked_function_errors"`
		InstructionLimitErrors int64 `json:"instruction_limit_errors"`
		MemoryLimitErrors      int64 `json:"memory_limit_errors"`
	} `json:"lua"`
}
type AppLayerStats struct {
	Flow         map[string]int64            `json:"flow"`  // e.g. http, tls, ssh, dns_udp, ...
	Error        map[string]map[string]int64 `json:"error"` // error categories per proto
	Tx           map[string]int64            `json:"tx"`    // transactions per app
	Expectations int64                       `json:"expectations"`
}
type MemcapStats struct {
	Pressure    int64 `json:"pressure"`
	PressureMax int64 `json:"pressure_max"`
}
type HTTPStats struct {
	MemUse    int64 `json:"memuse"`
	MemCap    int64 `json:"memcap"`
	ByteRange struct {
		MemUse int64 `json:"memuse"`
		MemCap int64 `json:"memcap"`
	} `json:"byterange"`
}

// Simple holders reused elsewhere.
type MemOnly struct {
	MemUse int64 `json:"memuse"`
	MemCap int64 `json:"memcap"`
}
type MemCap struct {
	MemUse int64 `json:"memuse"`
	MemCap int64 `json:"memcap"`
}
type FileStore struct {
	OpenFiles int64 `json:"open_files"`
}

// ==== Per-thread snapshot ====
type ThreadSnapshot struct {
	Capture      *Capture       `json:"capture,omitempty"`
	Decoder      *Decoder       `json:"decoder,omitempty"`
	TCP          *TCPStats      `json:"tcp,omitempty"`
	Flow         *FlowStats     `json:"flow,omitempty"`
	Defrag       *DefragStats   `json:"defrag,omitempty"`
	FlowBypassed *FlowBypassed  `json:"flow_bypassed,omitempty"`
	Detect       *DetectStats   `json:"detect,omitempty"`
	AppLayer     *AppLayerStats `json:"app_layer,omitempty"`
	// Some thread blocks (FM#/FR#) only include subsets; unknown extras here:
	Extra json.RawMessage `json:"-"`
}

// ==== Extra named sections from your JSON ====
type FMSection struct {
	Flow struct {
		Mgr              MgrStats `json:"mgr"`
		Spare            int64    `json:"spare"`
		EmergModeEntered int64    `json:"emerg_mode_entered"`
		EmergModeOver    int64    `json:"emerg_mode_over"`
	} `json:"flow"`
	FlowBypassed struct {
		Closed int64 `json:"closed"`
		Pkts   int64 `json:"pkts"`
		Bytes  int64 `json:"bytes"`
	} `json:"flow_bypassed"`
	Memcap MemcapStats `json:"memcap"`
	Defrag struct {
		Mgr struct {
			TrackerTimeout int64 `json:"tracker_timeout"`
		} `json:"mgr"`
		MemUse int64 `json:"memuse"`
	} `json:"defrag"`
}
type FRSection struct {
	TCP struct {
		ActiveSessions int64 `json:"active_sessions"`
	} `json:"tcp"`
	Flow struct {
		Active   int64         `json:"active"`
		End      EndStats      `json:"end"`
		Recycler RecyclerStats `json:"recycler"`
	} `json:"flow"`
}
type GlobalTotals struct {
	TCP struct {
		MemUse           int64 `json:"memuse"`
		ReassemblyMemUse int64 `json:"reassembly_memuse"`
	} `json:"tcp"`
	HTTP     HTTPStats `json:"http"`
	FTP      MemOnly   `json:"ftp"`
	AppLayer struct {
		Expectations int64 `json:"expectations"`
	} `json:"app_layer"`
	IPPair    MemCap    `json:"ippair"`
	Host      MemCap    `json:"host"`
	FileStore FileStore `json:"file_store"`
	Flow      struct {
		MemUse int64 `json:"memuse"`
	} `json:"flow"`
}

/*helloVersion = "0.1" // per docs*/
const helloVersion = "0.2" // per docs
// Default UNIX command socket path.
const SocketPath = "/run/suricata/suricata.sock"

// Common reply envelope from Suricata socket.
type SCReply struct {
	Return  string                 `json:"return"` // "OK" or "NOK"
	Message json.RawMessage        `json:"message,omitempty"`
	Data    map[string]interface{} `json:"data,omitempty"` // optional payload
	Raw     json.RawMessage        `json:"-"`              // raw line we got back (for troubleshooting)
}

// Command sends one JSON command and decodes one reply.
func Command(ctx context.Context, socket, cmd string, args map[string]any, timeout time.Duration) (*SCReply, error) {
	if socket == "" {
		socket = SocketPath
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	uc := conn.(*net.UnixConn)
	w := bufio.NewWriter(conn)
	r := bufio.NewReader(conn)

	writeLine := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if _, err = w.Write(b); err != nil {
			return err
		}
		if err = w.WriteByte('\n'); err != nil {
			return err
		}
		return w.Flush()
	}
	readReply := func(dst any) error {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return err
		}
		return json.Unmarshal(line, dst)
	}

	// 1) handshake (0.2)
	if err := writeLine(map[string]any{"version": helloVersion}); err != nil {
		return nil, fmt.Errorf("handshake write: %w", err)
	}
	var hello SCReply
	if err := readReply(&hello); err != nil {
		return nil, fmt.Errorf("handshake read: %w", err)
	}
	if strings.ToUpper(hello.Return) != "OK" {
		return nil, fmt.Errorf("handshake NOK: %s", hello.Message)
	}

	// 2) command (arguments is an OBJECT)
	req := map[string]any{"command": cmd}
	if args == nil {
		args = map[string]any{}
	}
	req["arguments"] = args
	if err := writeLine(req); err != nil {
		return nil, fmt.Errorf("request write: %w", err)
	}
	_ = uc.CloseWrite() // we’re done sending; let server flush

	var resp SCReply
	if err := readReply(&resp); err != nil {
		return nil, fmt.Errorf("reply read: %w", err)
	}
	if strings.ToUpper(resp.Return) != "OK" {
		return &resp, fmt.Errorf("NOK: %s", resp.Message)
	}
	return &resp, nil
}
func writeJSONLine(w *bufio.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err = w.Write(b); err != nil {
		return err
	}
	if err = w.WriteByte('\n'); err != nil {
		return err
	}
	return w.Flush()
}

func readJSONLine(r *bufio.Reader, v any) error {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

/* --------------------------------------------------------------------------
   Zero-arg helpers (no parameters). Each returns the raw SCReply so you can
   inspect Return/Message/Data as your Suricata version provides.
   -------------------------------------------------------------------------- */

func Shutdown(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "shutdown", nil, 30*time.Second)
}
func CommandList(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "command-list", nil, 10*time.Second)
}
func Help(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "help", nil, 10*time.Second)
}
func Version(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "version", nil, 10*time.Second)
}
func Uptime(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "uptime", nil, 10*time.Second)
}
func RunningMode(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "running-mode", nil, 10*time.Second)
}
func CaptureMode(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "capture-mode", nil, 10*time.Second)
}
func DumpCounters(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "dump-counters", nil, 20*time.Second)
}
func ReloadRules(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "reload-rules", nil, 30*time.Second)
}
func RulesetReloadRules(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "ruleset-reload-rules", nil, 30*time.Second)
}
func RulesetReloadNonBlocking(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "ruleset-reload-nonblocking", nil, 10*time.Second)
}
func RulesetReloadTime(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "ruleset-reload-time", nil, 10*time.Second)
}
func RulesetStats(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "ruleset-stats", nil, 10*time.Second)
}
func RulesetFailedRules(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "ruleset-failed-rules", nil, 10*time.Second)
}
func ReopenLogFiles(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "reopen-log-files", nil, 10*time.Second)
}
func MemcapShow(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "memcap-show", nil, 10*time.Second)
}
func MemcapList(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "memcap-list", nil, 10*time.Second)
}
func DatasetDump(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "dataset-dump", nil, 20*time.Second)
}
func DatasetClear(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "dataset-clear", nil, 20*time.Second)
}
func IfaceList(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "iface-list", nil, 10*time.Second)
}
func IfaceBypassedStat(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "iface-bypassed-stat", nil, 10*time.Second)
}
func EbpfBypassedStat(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "ebpf-bypassed-stat", nil, 10*time.Second)
}
func GetStats() Message {
	zctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rep, err := DumpCounters(zctx)
	if err != nil {
		log.Error().Msgf("dump-counters: %v %v", futils.GetCalleRuntime(), err)
		return Message{}
	}
	if rep != nil {
		var f Message
		if err := json.Unmarshal(rep.Message, &f); err != nil {
			log.Error().Msgf("dump-counters: %v %v", futils.GetCalleRuntime(), err)
			return Message{}
		}
		return f
	}
	return Message{}
}

/* --------------------------------------------------------------------------
   Parameterized helpers. For maximum compatibility, each also has a
   WithParams(...) variant that takes arbitrary map[string]any.
   -------------------------------------------------------------------------- */

// conf-get: fetch a config key.
func ConfGet(ctx context.Context, key string) (*SCReply, error) {
	return Command(ctx, SocketPath, "conf-get", map[string]any{"key": key}, 10*time.Second)
}
func ConfGetWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "conf-get", params, 10*time.Second)
}

// register-tenant-handler / unregister-tenant-handler
func RegisterTenantHandler(ctx context.Context, handler string) (*SCReply, error) {
	return Command(ctx, SocketPath, "register-tenant-handler", map[string]any{"handler": handler}, 15*time.Second)
}
func RegisterTenantHandlerWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "register-tenant-handler", params, 15*time.Second)
}
func UnregisterTenantHandler(ctx context.Context, handler string) (*SCReply, error) {
	return Command(ctx, SocketPath, "unregister-tenant-handler", map[string]any{"handler": handler}, 15*time.Second)
}
func UnregisterTenantHandlerWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "unregister-tenant-handler", params, 15*time.Second)
}

// register-tenant / unregister-tenant / reload-tenant(s)
func RegisterTenant(ctx context.Context, id string, cfg any) (*SCReply, error) {
	return Command(ctx, SocketPath, "register-tenant", map[string]any{"id": id, "config": cfg}, 20*time.Second)
}
func RegisterTenantWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "register-tenant", params, 20*time.Second)
}
func ReloadTenant(ctx context.Context, id string) (*SCReply, error) {
	return Command(ctx, SocketPath, "reload-tenant", map[string]any{"id": id}, 20*time.Second)
}
func ReloadTenantWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "reload-tenant", params, 20*time.Second)
}
func ReloadTenants(ctx context.Context) (*SCReply, error) {
	return Command(ctx, SocketPath, "reload-tenants", nil, 30*time.Second)
}
func UnregisterTenant(ctx context.Context, id string) (*SCReply, error) {
	return Command(ctx, SocketPath, "unregister-tenant", map[string]any{"id": id}, 20*time.Second)
}
func UnregisterTenantWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "unregister-tenant", params, 20*time.Second)
}

// hostbit operations
func AddHostbit(ctx context.Context, ip, bit string) (*SCReply, error) {
	return Command(ctx, SocketPath, "add-hostbit", map[string]any{"ip": ip, "hostbit": bit}, 10*time.Second)
}
func AddHostbitWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "add-hostbit", params, 10*time.Second)
}
func RemoveHostbit(ctx context.Context, ip, bit string) (*SCReply, error) {
	return Command(ctx, SocketPath, "remove-hostbit", map[string]any{"ip": ip, "hostbit": bit}, 10*time.Second)
}
func RemoveHostbitWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "remove-hostbit", params, 10*time.Second)
}
func ListHostbit(ctx context.Context, ip string) (*SCReply, error) {
	return Command(ctx, SocketPath, "list-hostbit", map[string]any{"ip": ip}, 10*time.Second)
}
func ListHostbitWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "list-hostbit", params, 10*time.Second)
}

// memcap-set/show/list
func MemcapSet(ctx context.Context, name string, value string) (*SCReply, error) {
	return Command(ctx, SocketPath, "memcap-set", map[string]any{"name": name, "value": value}, 10*time.Second)
}
func MemcapSetWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "memcap-set", params, 10*time.Second)
}

// dataset operations
func DatasetAdd(ctx context.Context, set, value string) (*SCReply, error) {
	return Command(ctx, SocketPath, "dataset-add", map[string]any{"dataset": set, "value": value}, 10*time.Second)
}
func DatasetAddWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "dataset-add", params, 10*time.Second)
}
func DatasetRemove(ctx context.Context, set, value string) (*SCReply, error) {
	return Command(ctx, SocketPath, "dataset-remove", map[string]any{"dataset": set, "value": value}, 10*time.Second)
}
func DatasetRemoveWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "dataset-remove", params, 10*time.Second)
}
func DatasetAddJSON(ctx context.Context, set string, jsonValue any) (*SCReply, error) {
	return Command(ctx, SocketPath, "dataset-add-json", map[string]any{"dataset": set, "value": jsonValue}, 10*time.Second)
}
func DatasetAddJSONWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "dataset-add-json", params, 10*time.Second)
}
func DatasetLookup(ctx context.Context, set, value string) (*SCReply, error) {
	return Command(ctx, SocketPath, "dataset-lookup", map[string]any{"dataset": set, "value": value}, 10*time.Second)
}
func DatasetLookupWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "dataset-lookup", params, 10*time.Second)
}

// get-flow-stats-by-id
func GetFlowStatsByID(ctx context.Context, id uint64) (*SCReply, error) {
	return Command(ctx, SocketPath, "get-flow-stats-by-id", map[string]any{"id": id}, 10*time.Second)
}
func GetFlowStatsByIDWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "get-flow-stats-by-id", params, 10*time.Second)
}

// iface-stat (usually requires iface name)
func IfaceStat(ctx context.Context, iface string) (*SCReply, error) {
	return Command(ctx, SocketPath, "iface-stat", map[string]any{"iface": iface}, 10*time.Second)
}
func IfaceStatWithParams(ctx context.Context, params map[string]any) (*SCReply, error) {
	return Command(ctx, SocketPath, "iface-stat", params, 10*time.Second)
}

/* --------------------------------------------------------------------------
   Also expose a fully generic executor for any future/unknown commands.
   -------------------------------------------------------------------------- */

func Exec(ctx context.Context, cmd string, params map[string]any, timeout time.Duration) (*SCReply, error) {
	return Command(ctx, SocketPath, cmd, params, timeout)
}

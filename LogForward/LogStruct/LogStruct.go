package LogStruct

import "encoding/json"

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
type DNSQuery struct {
	RRName string `json:"rrname"`
	RRType string `json:"rrtype"`
}

type DNSAnswer struct {
	RRName string `json:"rrname"`
	RRType string `json:"rrtype"`
	TTL    int    `json:"ttl"`
	RData  string `json:"rdata"`
}
type DNSEntry struct {
	Version int    `json:"version"` // 3
	Type    string `json:"type"`    // "response"
	TxID    int    `json:"tx_id"`
	ID      int    `json:"id"`
	Flags   string `json:"flags"` // "8180"
	QR      bool   `json:"qr"`
	RD      bool   `json:"rd"`
	RA      bool   `json:"ra"`
	Opcode  int    `json:"opcode"`
	Rcode   string `json:"rcode"` // "NOERROR"

	Queries []DNSQuery          `json:"queries"`
	Answers []DNSAnswer         `json:"answers"`
	Grouped map[string][]string `json:"grouped"` // e.g. {"A": ["66.249.65.174"]}
}
type JA3Info struct {
	Hash   string `json:"hash"`
	String string `json:"string"`
}

type TLSInfo struct {
	SessionResumed bool     `json:"session_resumed,omitempty"`
	Version        string   `json:"version,omitempty"` // e.g., "TLS 1.2", "TLS 1.3"
	JA3            *JA3Info `json:"ja3,omitempty"`
	JA3S           *JA3Info `json:"ja3s,omitempty"`
	JA4            string   `json:"ja4,omitempty"`
	ClientALPNs    []string `json:"client_alpns,omitempty"`
	ServerALPNs    []string `json:"server_alpns,omitempty"`
	SNI            string   `json:"sni,omitempty"`         // Server Name Indication
	Fingerprint    string   `json:"fingerprint,omitempty"` // Certificate fingerprint
	Serial         string   `json:"serial,omitempty"`      // Certificate serial
	Subject        string   `json:"subject,omitempty"`     // Certificate subject
	Issuer         string   `json:"issuerdn,omitempty"`    // Certificate issuer
	NotBefore      string   `json:"notbefore,omitempty"`   // Certificate validity start
	NotAfter       string   `json:"notafter,omitempty"`    // Certificate validity end
}

type EveEvent struct {
	Timestamp    string          `json:"timestamp"`
	EventType    string          `json:"event_type"`
	SrcIP        string          `json:"src_ip,omitempty"`
	SrcPort      *int            `json:"src_port,omitempty"`
	DestIP       string          `json:"dest_ip,omitempty"` // Suricata uses "dest_ip"
	DstIP        string          `json:"dst_ip,omitempty"`  // Keep for backwards compatibility
	DstPort      *int            `json:"dst_port,omitempty"`
	Proto        string          `json:"proto,omitempty"`
	InIface      string          `json:"in_iface,omitempty"`
	FlowID       *uint64         `json:"flow_id,omitempty"`
	TxID         *uint64         `json:"tx_id,omitempty"`
	CommunityID  *string         `json:"community_id,omitempty"`
	IPVersion    *int            `json:"ip_v,omitempty"`
	ICMPType     *int            `json:"icmp_type,omitempty"`
	ICMPCode     *int            `json:"icmp_code,omitempty"`
	PktSrc       string          `json:"pkt_src,omitempty"`
	Direction    string          `json:"direction,omitempty"`
	Alert        *EveAlert       `json:"alert,omitempty"`
	HTTP         *HTTPInfo       `json:"http,omitempty"`
	TLS          *TLSInfo        `json:"tls,omitempty"`
	DNS          *DNSEntry       `json:"dns,omitempty"`
	NDPI         *NDPI           `json:"ndpi,omitempty"`
	Flow         json.RawMessage `json:"flow,omitempty"`
	UnhandledRaw json.RawMessage `json:"-"`
	Count        int             `json:"Count"`
	ProxyName    string          `json:"ProxyName"`
}
type NDPI struct {
	Protocol   string `json:"protocol"`
	Category   string `json:"category"`
	Confidence string `json:"confidence"`
}

type EveAlert struct {
	Signature   string              `json:"signature"`
	SignatureID int                 `json:"signature_id"`
	Category    string              `json:"category"`
	Severity    int                 `json:"severity"`
	Action      string              `json:"action,omitempty"` // allowed/blocked (depends on mode)
	GID         int                 `json:"gid,omitempty"`
	Rev         int                 `json:"rev,omitempty"`
	Metadata    map[string][]string `json:"metadata,omitempty"` // Map of metadata key -> values
	Rule        string              `json:"rule,omitempty"`
}

package SuriConf

import (
	"BPFfilter"
	"LogForward"
	"PFRing"
	"PFRingIfaces"
	"SqliteConns"
	"SuriStructs"
	"apostgres"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"csqlite"
	"database/sql"
	"fmt"
	"futils"
	"ipclass"
	"logsink"
	"notifs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sockets"
	"strings"
	"suricata/SuricataTools"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

const LockFile = "/etc/suricata/suricata.lock"
const DumpRulesPF = "dumprules.progress"

var ClassificationsRegex = regexp.MustCompile(`^config classification:\s+(.+?),(.+?),([0-9]+)`)

func fixClassificationsFile() {

	if futils.FileExists("/etc/suricata/rules/classification.config") {
		futils.CopyFile("/etc/suricata/rules/classification.config", "/etc/suricata/classification.config")
		return
	}
	if futils.FileExists("/etc/suricata/classification.config") {
		futils.CopyFile("/etc/suricata/classification.config", "/etc/suricata/rules/classification.config")
	}
}

func Build(BuildRules bool) error {

	if futils.FileExists(LockFile) {
		Mins := futils.FileTimeMin(LockFile)
		if Mins < 5 {
			return fmt.Errorf("suricata configuration is locked by another process since %d minutes ago", Mins)
		}
	}
	futils.TouchFile(LockFile)
	defer futils.DeleteFile(LockFile)

	if futils.IsDirDirectory("/etc/suricata/suricata") {
		cp := futils.FindProgram("cp")
		_, _ = futils.ExecuteShell(fmt.Sprintf("%v -rf /etc/suricata/suricata/* /etc/suricata/", cp))
		_ = futils.RmRF("/etc/suricata/suricata")
	}

	TempFiles := []string{"/etc/suricata/suricata.builded.yaml",
		"/etc/suricata/threshold.temp.config",
	}

	futils.CreateDir("/etc/suricata/iprep")
	futils.CreateDir("/etc/suricata/rules")
	//
	notifs.BuildProgress(53, "Classification...", "suricata.reconfigure.progress")
	fixClassificationsFile()

	if BuildRules {
		notifs.BuildProgress(54, "{rules}", "suricata.reconfigure.progress")
		err := DumpRules()
		if err != nil {
			return err
		}
	}
	Gconf := SuriStructs.LoadConfig()
	PfRingSo := PFRing.PFringSoPath()
	notifs.BuildProgress(55, "{reconfiguring}", "suricata.reconfigure.progress")
	if len(PfRingSo) < 3 {
		log.Error().Msgf("%v pfring.so not found: [%v]", futils.GetCalleRuntime(), PfRingSo)
		futils.DeleteFile("/etc/suricata/suricata.yaml")
		return fmt.Errorf("pfring.so not found: [%v]", PfRingSo)
	}
	log.Info().Msgf("%v pfring.so path=[%v]", futils.GetCalleRuntime(), PfRingSo)

	// Constructing the configuration file contents
	var f []string
	f = append(f, "%YAML 1.1", "---")
	f = append(f, "max-pending-packets: 2048")
	f = append(f, "host-mode: sniffer-only")
	f = append(f, "default-log-dir: /var/log/suricata/")
	f = append(f, ``)
	f = append(f, `plugins:`)
	f = append(f, fmt.Sprintf("  - %v", PfRingSo))
	f = append(f, ``)
	f = append(f, `stats:`)
	f = append(f, `  enabled: yes`)
	f = append(f, `  interval: 300`)
	f = append(f, ``)
	f = append(f, "outputs:")
	f = append(f, "  - eve-log:")
	f = append(f, "      enabled: yes")
	f = append(f, "      filetype: unix_stream")
	f = append(f, "      filename: /run/suricata/alerts.sock")
	f = append(f, "      format: json")
	f = append(f, "      types:")
	f = append(f, fmt.Sprintf("        - %v", "alert"))

	for ztype, value := range Gconf.EveLogsType {
		if ztype == "alert" {
			continue
		}
		if value == 0 {
			continue
		}
		f = append(f, fmt.Sprintf("        - %v", ztype))
	}
	f = append(f, "        - http2:")
	f = append(f, "            extended: yes")
	f = append(f, "        - http:")
	f = append(f, "            extended: yes")
	f = append(f, "        - tls:")
	f = append(f, "            extended: yes")
	f = append(f, "        - files:")
	f = append(f, "            force-magic: no")
	f = append(f, "            force-md5: no")
	f = append(f, ``)
	f = append(f, `      xff:`)
	f = append(f, `        enabled: no`)
	f = append(f, `        mode: extra-data`)
	f = append(f, `        header: X-Forwarded-For `)
	f = append(f, ``)
	f = append(f, `  - http-log:`)
	f = append(f, `      enabled: no`)
	f = append(f, `      filename: http.log`)
	f = append(f, `      append: yes`)
	f = append(f, `      #extended: yes     # enable this for extended logging information`)
	f = append(f, `      #custom: yes       # enabled the custom logging format (defined by customformat)`)
	f = append(f, `      #customformat: "%{%D-%H:%M:%S}t.%z %{X-Forwarded-For}i %H %m %h %u %s %B %a:%p -> %A:%P"`)
	f = append(f, `      #filetype: regular # 'regular', 'unix_stream' or 'unix_dgram'`)
	f = append(f, ``)
	f = append(f, `  # a line based log of TLS handshake parameters (no alerts)`)
	f = append(f, `  - tls-log:`)
	f = append(f, `      enabled: no  # Log TLS connections.`)
	f = append(f, `      filename: tls.log # File to store TLS logs.`)
	f = append(f, `      append: yes`)
	f = append(f, `      #filetype: regular # 'regular', 'unix_stream' or 'unix_dgram'`)
	f = append(f, `      #extended: yes # Log extended information like fingerprint`)
	f = append(f, `      certs-log-dir: certs # directory to store the certificates files`)
	f = append(f, ``)
	f = append(f, `  # a line based log of DNS requests and/or replies (no alerts)`)
	f = append(f, `  - dns-log:`)
	f = append(f, `      enabled: no`)
	f = append(f, `      filename: dns.log`)
	f = append(f, `      append: yes`)
	f = append(f, `      #filetype: regular # 'regular', 'unix_stream' or 'unix_dgram'`)
	f = append(f, ``)
	f = append(f, `  - pcap-info:`)
	f = append(f, `      enabled: no`)
	f = append(f, ``)
	f = append(f, `  - pcap-log:`)
	f = append(f, `      enabled:  no`)
	f = append(f, `      filename: log.pcap`)
	f = append(f, `      limit: 1000mb`)
	f = append(f, `      max-files: 2000`)
	f = append(f, `      mode: normal`)
	f = append(f, `      use-stream-depth: no`)
	f = append(f, ``)
	f = append(f, `  - alert-debug:`)
	f = append(f, `      enabled: no`)
	f = append(f, `      filename: alert-debug.log`)
	f = append(f, `      append: yes`)
	f = append(f, `      filetype: regular`)
	f = append(f, ``)
	f = append(f, `  - alert-prelude:`)
	f = append(f, `      enabled: no`)
	f = append(f, `      profile: suricata`)
	f = append(f, `      log-packet-content: no`)
	f = append(f, `      log-packet-header: yes`)
	f = append(f, ``)
	f = append(f, `  - stats:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `      filename: stats.log`)
	f = append(f, `      interval: 300`)
	f = append(f, `      append: no`)
	f = append(f, ``)
	f = append(f, `  # a line based information for dropped packets in IPS mode`)
	f = append(f, `  - drop:`)
	f = append(f, `      enabled: no`)
	f = append(f, `      filename: drop.log`)
	f = append(f, `      append: yes`)
	f = append(f, `      filetype: regular`)
	f = append(f, ``)
	f = append(f, `  - file-store:`)
	f = append(f, `      enabled: no       # set to yes to enable`)
	f = append(f, `      log-dir: files    # directory to store the files`)
	f = append(f, `      force-magic: no   # force logging magic on all stored files`)
	f = append(f, `      force-md5: no     # force logging of md5 checksums`)
	f = append(f, `      #waldo: file.waldo # waldo file to store the file_id across runs`)
	f = append(f, ``)

	SuricatatrackfilesEnabled := "no"
	SuricataTrackFiles := sockets.GET_INFO_INT("SuricataTrackFiles")
	if SuricataTrackFiles == 1 {
		SuricatatrackfilesEnabled = "yes"
	}
	f = append(f, `  - file-log:`)
	f = append(f, fmt.Sprintf("      enabled: %v", SuricatatrackfilesEnabled))
	f = append(f, `      filename: files-json.log`)
	f = append(f, `      append: yes`)
	f = append(f, `      filetype: regular`)
	f = append(f, `      force-magic: yes`)
	f = append(f, `      force-md5: yes`)
	f = append(f, ``)
	f = append(f, `magic-file: /usr/share/file/magic`)
	f = append(f, ``)
	f = append(f, `nfq:`)
	f = append(f, ``)
	f = append(f, `nflog:`)
	f = append(f, `  - group: 2`)
	f = append(f, `    buffer-size: 18432`)
	f = append(f, `  - group: default`)
	f = append(f, `    qthreshold: 1`)
	f = append(f, `    qtimeout: 100`)
	f = append(f, `    max-size: 20000`)
	f = append(f, ``)
	f = append(f, `legacy:`)
	f = append(f, `  uricontent: enabled`)
	f = append(f, ``)
	f = append(f, `detect-engine:`)
	f = append(f, `  - profile: medium`)
	f = append(f, `  - custom-values:`)
	f = append(f, `      toclient-src-groups: 2`)
	f = append(f, `      toclient-dst-groups: 2`)
	f = append(f, `      toclient-sp-groups: 2`)
	f = append(f, `      toclient-dp-groups: 3`)
	f = append(f, `      toserver-src-groups: 2`)
	f = append(f, `      toserver-dst-groups: 4`)
	f = append(f, `      toserver-sp-groups: 2`)
	f = append(f, `      toserver-dp-groups: 25`)
	f = append(f, `  - sgh-mpm-context: auto`)
	f = append(f, `  - inspection-recursion-limit: 3000`)
	f = append(f, ``)
	f = append(f, `threading:`)
	f = append(f, `  set-cpu-affinity: yes`)
	f = append(f, ``)
	f = append(f, `  cpu-affinity:`)
	f = append(f, `    - management-cpu-set:`)
	f = append(f, `        cpu: [ "all" ]`)
	f = append(f, ``)
	f = append(f, `    - receive-cpu-set:`)
	f = append(f, `        cpu: [ 0 ]  # include only these cpus in affinity settings`)
	f = append(f, ``)
	f = append(f, `    - decode-cpu-set:`)
	f = append(f, `        cpu: [ 0, 1 ]`)
	f = append(f, `        mode: "balanced"`)
	f = append(f, ``)
	f = append(f, `    - stream-cpu-set:`)
	f = append(f, `        cpu: [ "0-1" ]`)
	f = append(f, ``)
	f = append(f, `    - detect-cpu-set:`)
	f = append(f, `        cpu: [ "all" ]`)
	f = append(f, `        mode: "exclusive"`)
	f = append(f, `        prio:`)
	f = append(f, `          low: [ 0 ]`)
	f = append(f, `          medium: [ "1-2" ]`)
	f = append(f, `          high: [ 3 ]`)
	f = append(f, `          default: "medium"`)
	f = append(f, ``)
	f = append(f, `    - verdict-cpu-set:`)
	f = append(f, `        cpu: [ 0 ]`)
	f = append(f, `        prio:`)
	f = append(f, `          default: "high"`)
	f = append(f, `    - reject-cpu-set:`)
	f = append(f, `        cpu: [ 0 ]`)
	f = append(f, `        prio:`)
	f = append(f, `          default: "low"`)
	f = append(f, `    - output-cpu-set:`)
	f = append(f, `        cpu: [ "all" ]`)
	f = append(f, `        prio:`)
	f = append(f, `           default: "medium"`)
	f = append(f, `  #`)
	f = append(f, `  detect-thread-ratio: 1.5`)
	f = append(f, ``)
	f = append(f, `# Cuda configuration.`)
	f = append(f, `cuda:`)
	f = append(f, `  mpm:`)
	f = append(f, `    data-buffer-size-min-limit: 0`)
	f = append(f, `    data-buffer-size-max-limit: 1500`)
	f = append(f, `    cudabuffer-buffer-size: 500mb`)
	f = append(f, `    gpu-transfer-size: 50mb`)
	f = append(f, `    batching-timeout: 2000`)
	f = append(f, `    device-id: 0`)
	f = append(f, `    cuda-streams: 2`)
	f = append(f, ``)
	notifs.BuildProgress(56, "{reconfiguring} HyperScan", "suricata.reconfigure.progress")
	_, algo := hyperScan()
	f = append(f, fmt.Sprintf("mpm-algo: %v", algo))
	f = append(f, ``)
	f = append(f, `pattern-matcher:`)
	f = append(f, `  - b2gc:`)
	f = append(f, `      search-algo: B2gSearchBNDMq`)
	f = append(f, `      hash-size: low`)
	f = append(f, `      bf-size: medium`)
	f = append(f, `  - b2gm:`)
	f = append(f, `      search-algo: B2gSearchBNDMq`)
	f = append(f, `      hash-size: low`)
	f = append(f, `      bf-size: medium`)
	f = append(f, `  - b2g:`)
	f = append(f, `      search-algo: B2gSearchBNDMq`)
	f = append(f, `      hash-size: low`)
	f = append(f, `      bf-size: medium`)
	f = append(f, `  - b3g:`)
	f = append(f, `      search-algo: B3gSearchBNDMq`)
	f = append(f, `      hash-size: low`)
	f = append(f, `      bf-size: medium`)
	f = append(f, `  - wumanber:`)
	f = append(f, `      hash-size: low`)
	f = append(f, `      bf-size: medium`)
	f = append(f, ``)
	f = append(f, `# Defrag settings:`)
	f = append(f, ``)
	f = append(f, `defrag:`)
	f = append(f, `  memcap: 32mb`)
	f = append(f, `  hash-size: 65536`)
	f = append(f, `  trackers: 65535 # number of defragmented flows to follow`)
	f = append(f, `  max-frags: 65535 # number of fragments to keep (higher than trackers)`)
	f = append(f, `  prealloc: yes`)
	f = append(f, `  timeout: 60`)
	f = append(f, ``)
	f = append(f, ``)
	f = append(f, `flow:`)
	f = append(f, `  memcap: 64mb`)
	f = append(f, `  hash-size: 65536`)
	f = append(f, `  prealloc: 10000`)
	f = append(f, `  emergency-recovery: 30`)
	f = append(f, ``)
	f = append(f, `vlan:`)
	f = append(f, `  use-for-tracking: true`)
	f = append(f, ``)
	f = append(f, ``)
	f = append(f, `flow-timeouts:`)
	f = append(f, ``)
	f = append(f, `  default:`)
	f = append(f, `    new: 30`)
	f = append(f, `    established: 300`)
	f = append(f, `    closed: 0`)
	f = append(f, `    emergency-new: 10`)
	f = append(f, `    emergency-established: 100`)
	f = append(f, `    emergency-closed: 0`)
	f = append(f, `  tcp:`)
	f = append(f, `    new: 60`)
	f = append(f, `    established: 3600`)
	f = append(f, `    closed: 120`)
	f = append(f, `    emergency-new: 10`)
	f = append(f, `    emergency-established: 300`)
	f = append(f, `    emergency-closed: 20`)
	f = append(f, `  udp:`)
	f = append(f, `    new: 30`)
	f = append(f, `    established: 300`)
	f = append(f, `    emergency-new: 10`)
	f = append(f, `    emergency-established: 100`)
	f = append(f, `  icmp:`)
	f = append(f, `    new: 30`)
	f = append(f, `    established: 300`)
	f = append(f, `    emergency-new: 10`)
	f = append(f, `    emergency-established: 100`)
	f = append(f, ``)
	f = append(f, `# Stream engine settings. Here the TCP stream tracking and reassembly`)
	f = append(f, `# engine is configured.`)
	f = append(f, `#`)
	f = append(f, `stream:`)
	f = append(f, `  memcap: 32mb`)
	f = append(f, `  checksum-validation: no      # reject wrong csums`)
	f = append(f, `  inline: auto                  # auto will use inline mode in IPS mode, yes or no set it statically`)
	f = append(f, `  reassembly:`)
	f = append(f, `    memcap: 128mb`)
	f = append(f, `    depth: 1mb                  # reassemble 1mb into a stream`)
	f = append(f, `    toserver-chunk-size: 2560`)
	f = append(f, `    toclient-chunk-size: 2560`)
	f = append(f, `    randomize-chunk-size: yes`)
	f = append(f, ``)
	f = append(f, `host:`)
	f = append(f, `  hash-size: 4096`)
	f = append(f, `  prealloc: 1000`)
	f = append(f, `  memcap: 16777216`)
	f = append(f, ``)

	f = append(f, `logging:`)
	f = append(f, ``)
	f = append(f, `  default-log-level: notice`)
	f = append(f, `  default-output-filter:`)
	f = append(f, ``)
	f = append(f, `  outputs:`)
	f = append(f, `  - console:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `  - file:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `      filename: /var/log/suricata.log`)
	f = append(f, `  - syslog:`)
	f = append(f, `      enabled: no`)
	f = append(f, `      facility: syslog`)
	f = append(f, `      format: "[%i] <%d> -- "`)
	f = append(f, ``)
	f = append(f, `# Tilera mpipe configuration. for use on Tilera TILE-Gx.`)
	f = append(f, `mpipe:`)
	f = append(f, ``)
	f = append(f, `  load-balance: dynamic`)
	f = append(f, `  iqueue-packets: 2048`)
	f = append(f, `  inputs:`)
	f = append(f, `  - interface: xgbe2`)
	f = append(f, `  - interface: xgbe3`)
	f = append(f, `  - interface: xgbe4`)
	f = append(f, ``)
	f = append(f, ``)
	f = append(f, `  # Relative weight of memory for packets of each mPipe buffer size.`)
	f = append(f, `  stack:`)
	f = append(f, `    size128: 0`)
	f = append(f, `    size256: 9`)
	f = append(f, `    size512: 0`)
	f = append(f, `    size1024: 0`)
	f = append(f, `    size1664: 7`)
	f = append(f, `    size4096: 0`)
	f = append(f, `    size10386: 0`)
	f = append(f, `    size16384: 0`)
	f = append(f, PFRingIfaces.Build())
	f = append(f, `default-rule-path: /etc/suricata/rules`)
	f = append(f, "rule-files:")
	//f = append(f, writePersoRule())
	RulePath := "/etc/suricata/rules"
	futils.CreateDir(RulePath)
	f = append(f, " - Production.rules")
	f = append(f, " - iprep.rules")
	f = append(f, "")
	f = append(f, "classification-file: /etc/suricata/rules/classification.config")
	f = append(f, "reference-config-file: /etc/suricata/reference.config")
	f = append(f, "")
	if !futils.FileExists("/etc/suricata/rules/Production.rules") {
		futils.TouchFile("/etc/suricata/rules/Production.rules")
	}

	f = append(f, AllVars())
	f = append(f, `# IP Reputation`)
	f = append(f, `reputation-categories-file: /etc/suricata/iprep/categories.org`)
	f = append(f, `default-reputation-path: /etc/suricata/iprep`)
	f = append(f, `reputation-files:`)

	reputationFiles := []string{"alienvault.list", "emergingthreatspro.list", "usom.list",
		"firehol_level1.list", "blocklist_de_strongips.list", "cibadguys.list", "otx.list", "dsipv4.list",
	}
	notifs.BuildProgress(57, "{reconfiguring} {reputations}", "suricata.reconfigure.progress")
	for _, fname := range reputationFiles {
		if !futils.FileExists(fmt.Sprintf("%v/%v", "/etc/suricata/iprep", fname)) {
			futils.TouchFile(fmt.Sprintf("%v/%v", "/etc/suricata/iprep", fname))
		}
		f = append(f, fmt.Sprintf("  - %v", fname))
	}
	notifs.BuildProgress(58, "{reconfiguring} {reputations}", "suricata.reconfigure.progress")
	IPRepRules()
	notifs.BuildProgress(59, "{reconfiguring} {categories}", "suricata.reconfigure.progress")
	IPRepCategories()
	HostOsPolicy := []string{}
	AllLocalIPs := ipclass.AllLocalIPs()
	for _, ip := range AllLocalIPs {
		if ipclass.IsIPv6(ip) {
			HostOsPolicy = append(HostOsPolicy, `"`+ip+`"`)
			continue
		}
		HostOsPolicy = append(HostOsPolicy, ip)
	}

	f = append(f, `# Host specific policies for defragmentation and TCP stream`)
	f = append(f, `# reassembly.  The host OS lookup is done using a radix tree, just`)
	f = append(f, `# like a routing table so the most specific entry matches.`)
	f = append(f, `host-os-policy:`)
	f = append(f, `  # Make the default policy windows.`)
	f = append(f, `  windows: [0.0.0.0/0]`)
	f = append(f, `  bsd: []`)
	f = append(f, `  bsd-right: []`)
	f = append(f, `  old-linux: []`)
	f = append(f, fmt.Sprintf("  linux: [%v]", strings.Join(HostOsPolicy, ",")))
	f = append(f, `  old-solaris: []`)
	f = append(f, `  solaris: []`)
	f = append(f, `  hpux10: []`)
	f = append(f, `  hpux11: []`)
	f = append(f, `  irix: []`)
	f = append(f, `  macos: []`)
	f = append(f, `  vista: []`)
	f = append(f, `  windows2k3: []`)
	f = append(f, ``)
	f = append(f, ``)
	f = append(f, `# Limit for the maximum number of asn1 frames to decode (default 256)`)
	f = append(f, `asn1-max-frames: 256`)
	f = append(f, ``)
	f = append(f, `engine-analysis:`)
	f = append(f, `  rules-fast-pattern: yes`)
	f = append(f, `  rules: yes`)
	f = append(f, ``)
	f = append(f, `#recursion and match limits for PCRE where supported`)
	f = append(f, `pcre:`)
	f = append(f, `  match-limit: 3500`)
	f = append(f, `  match-limit-recursion: 1500`)
	f = append(f, ``)
	f = append(f, `threshold-file: /etc/suricata/threshold.config`)
	f = append(f, ``)
	f = append(f, `app-layer:`)
	f = append(f, `  protocols:`)
	if Gconf.NDPIOK {
		if Gconf.NDPIEnabled == 1 {
			f = append(f, `    ndpi:`)
			f = append(f, `      enabled: yes`)
		}
	}

	f = append(f, `    tls:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `      detection-ports:`)
	f = append(f, `        dp: 443`)
	f = append(f, `    dcerpc:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    ftp:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    ssh:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    smtp:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    imap:`)
	f = append(f, `      enabled: detection-only`)
	f = append(f, `    msn:`)
	f = append(f, `      enabled: detection-only`)
	f = append(f, `    smb:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `      detection-ports:`)
	f = append(f, `        dp: 139`)
	f = append(f, `    dns:`)
	f = append(f, `      global-memcap: 16mb`)
	f = append(f, `      state-memcap: 512kb`)
	f = append(f, `      request-flood: 500`)
	f = append(f, `      tcp:`)
	f = append(f, `        enabled: yes`)
	f = append(f, `        detection-ports:`)
	f = append(f, `          dp: 53`)
	f = append(f, `      udp:`)
	f = append(f, `        enabled: yes`)
	f = append(f, `        detection-ports:`)
	f = append(f, `          dp: 53`)
	f = append(f, `    tftp:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    snmp:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    sip:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    rfb:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    rdp:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    ntp:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    nfs:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    mqtt:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    modbus:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    krb5:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    ikev2:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    http2:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    enip:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    dnp3:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    dhcp:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `    http:`)
	f = append(f, `      enabled: yes`)
	f = append(f, `      # memcap: 64mb`)
	f = append(f, ``)
	f = append(f, `      libhtp:`)
	f = append(f, `         default-config:`)
	f = append(f, `           personality: IDS`)
	f = append(f, `           request-body-limit: 3072`)
	f = append(f, `           response-body-limit: 3072`)
	f = append(f, `           request-body-minimal-inspect-size: 32kb`)
	f = append(f, `           request-body-inspect-window: 4kb`)
	f = append(f, `           response-body-minimal-inspect-size: 32kb`)
	f = append(f, `           response-body-inspect-window: 4kb`)
	f = append(f, `           #randomize-inspection-sizes: yes`)
	f = append(f, `           #randomize-inspection-range: 10`)
	f = append(f, `           double-decode-path: no`)
	f = append(f, `           double-decode-query: no`)
	f = append(f, ``)
	f = append(f, `         server-config:`)
	f = append(f, ``)
	f = append(f, `profiling:`)
	f = append(f, `  # 1000 received.`)
	f = append(f, `  #sample-rate: 1000`)
	f = append(f, ``)
	f = append(f, `  # rule profiling`)
	f = append(f, `  rules:`)
	f = append(f, `    enabled: yes`)
	f = append(f, `    filename: rule_perf.log`)
	f = append(f, `    append: yes`)
	f = append(f, `    sort: avgticks`)
	f = append(f, `    limit: 100`)
	f = append(f, ``)
	f = append(f, `  keywords:`)
	f = append(f, `    enabled: yes`)
	f = append(f, `    filename: keyword_perf.log`)
	f = append(f, `    append: yes`)
	f = append(f, ``)
	f = append(f, `  packets:`)
	f = append(f, `    enabled: yes`)
	f = append(f, `    filename: packet_stats.log`)
	f = append(f, `    append: yes`)
	f = append(f, ``)
	f = append(f, `    csv:`)
	f = append(f, `      enabled: no`)
	f = append(f, `      filename: packet_stats.csv`)
	f = append(f, ``)
	f = append(f, `  # profiling of locking. Only available when Suricata was built with`)
	f = append(f, `  # --enable-profiling-locks.`)
	f = append(f, `  locks:`)
	f = append(f, `    enabled: no`)
	f = append(f, `    filename: lock_stats.log`)
	f = append(f, `    append: yes`)
	f = append(f, ``)
	f = append(f, ``)
	f = append(f, `coredump:`)
	f = append(f, `  max-dump: unlimited`)
	f = append(f, ``)
	f = append(f, `napatech:`)
	f = append(f, `    hba: -1`)
	f = append(f, `    use-all-streams: yes`)
	f = append(f, `    streams: [1, 2, 3]`)
	f = append(f, ``)
	futils.CreateDir("/run/suricata")
	f = append(f, `unix-command:`)
	f = append(f, `    enabled: yes`)
	f = append(f, `    filename: /run/suricata/suricata.sock`)
	f = append(f, ``)
	f = append(f, `#include: include1.yaml`)
	f = append(f, `#include: include2.yaml`)
	f = append(f, ``)

	tmpfile := "/etc/suricata/suricata.builded.yaml"
	log.Debug().Msgf("%v Saving %v", futils.GetCalleRuntime(), tmpfile)
	_ = futils.FilePutContents(tmpfile, strings.Join(f, "\n"))
	//SuricataTools.FixDuplicateRules()
	log.Debug().Msgf("%v threshold", futils.GetCalleRuntime())
	_ = threshold()
	log.Debug().Msgf("%v Buildsyslog", futils.GetCalleRuntime())
	Buildsyslog()
	LogForward.ReloadConfig()
	SourcesFiles := []string{"/etc/suricata/suricata.yaml",
		"/etc/suricata/threshold.config"}
	var md51 string
	var md52 string
	for _, fPath := range TempFiles {
		md51 = md51 + futils.MD5File(fPath)
	}
	for _, fPath := range SourcesFiles {
		md52 = md52 + futils.MD5File(fPath)
	}

	if md51 == md52 {
		return nil
	}
	notifs.BuildProgress(75, "{reconfiguring} {checking}", "suricata.reconfigure.progress")
	log.Debug().Msgf("%v CheckConfig", futils.GetCalleRuntime())
	err := CheckConfig(tmpfile)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return err
	}
	_ = futils.FilePutContents("/etc/suricata/suricata.yaml", strings.Join(f, "\n"))

	futils.DeleteFile(tmpfile)
	_ = futils.CopyFile("/etc/suricata/threshold.temp.config", "/etc/suricata/threshold.config")

	return nil
}
func AllVars() string {
	Gconf := SuriStructs.LoadConfig()
	TrustedNets := BPFfilter.TrustedNets()
	trustedNet := TrustedNets

	homeNet := Gconf.HomeNets
	homeNet["127.0.0.0/8"] = SuriStructs.HomeNets{Negative: 0, Enabled: 1}

	var HOME_NET []string
	var z []string
	for ips, Conf := range homeNet {
		ips = strings.TrimSpace(ips)
		if ips == "" {
			continue
		}
		if Conf.Enabled == 0 {
			continue
		}
		if !ipclass.IsValidIPorCDIRorRange(ips) {
			continue
		}
		if ips == "0.0.0.0" {
			continue
		}
		if ips == "0.0.0.0/0" {
			continue
		}
		if Conf.Negative == 1 {
			ips = "!" + ips
		}
		HOME_NET = append(HOME_NET, ips)
	}
	for ips, _ := range trustedNet {
		ips = strings.TrimSpace(ips)
		if ips == "" {
			continue
		}
		if !ipclass.IsValidIPorCDIRorRange(ips) {
			continue
		}
		if ips == "0.0.0.0" {
			continue
		}
		if ips == "0.0.0.0/0" {
			continue
		}
		z = append(z, ips)
	}

	if len(HOME_NET) == 0 {
		HOME_NET = []string{"127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"}
	}
	var f []string
	f = append(f, `# Holds variables that would be used by the engine.`)
	f = append(f, `vars:`)
	f = append(f, `  address-groups:`)
	f = append(f, fmt.Sprintf("    HOME_NET: \"[%v]\"", strings.Join(HOME_NET, ",")))
	f = append(f, fmt.Sprintf("    TRUSTED_NET: \"[%v]\"", strings.Join(z, ",")))
	f = append(f, `    EXTERNAL_NET: "!$HOME_NET"`)
	f = append(f, `    HTTP_SERVERS: "$HOME_NET"`)
	f = append(f, `    SMTP_SERVERS: "$HOME_NET"`)
	f = append(f, `    SQL_SERVERS: "$HOME_NET"`)
	f = append(f, `    DNS_SERVERS: "$HOME_NET"`)
	f = append(f, `    TELNET_SERVERS: "$HOME_NET"`)
	f = append(f, `    AIM_SERVERS: "$EXTERNAL_NET"`)
	f = append(f, `    DNP3_SERVER: "$HOME_NET"`)
	f = append(f, `    DNP3_CLIENT: "$HOME_NET"`)
	f = append(f, `    MODBUS_CLIENT: "$HOME_NET"`)
	f = append(f, `    MODBUS_SERVER: "$HOME_NET"`)
	f = append(f, `    ENIP_CLIENT: "$HOME_NET"`)
	f = append(f, `    ENIP_SERVER: "$HOME_NET"`)
	f = append(f, ``)
	f = append(f, `  port-groups:`)
	f = append(f, fmt.Sprintf("    HTTP_PORTS: \"[%v]\"", strings.Join(getHttpPorts(), ",")))
	f = append(f, `    SHELLCODE_PORTS: "!80"`)
	f = append(f, `    ORACLE_PORTS: 1521`)
	f = append(f, `    SSH_PORTS: 22`)
	f = append(f, `    DNP3_PORTS: 20000`)
	f = append(f, `    FILE_DATA_PORTS: "[110,143]"`)
	f = append(f, ``)
	return strings.Join(f, "\n")
}

func threshold() error {
	var suppressRules []string
	err, sigs := SuricataTools.GetDisabledSignatures()
	if err != nil {
		return err
	}
	for _, signature := range sigs {
		suppressRules = append(suppressRules, fmt.Sprintf("suppress gen_id 1, sig_id %s", signature))
	}
	suppressRulesContent := strings.Join(suppressRules, "\n") + "\n"
	err = futils.FilePutContents("/etc/suricata/threshold.temp.config", suppressRulesContent)
	return err
}
func IPRepRules() {

	gbconf := SuriStructs.LoadConfig()

	rules := []string{
		"alert tcp any any -> any any (msg:\"Bad reputation: Alien Vault reputation IPs\"; iprep:any,alienvault,=,127; sid:10001; rev:1;)",
		"alert tcp any any -> any any (msg:\"Bad reputation: Emerging Threats Pro reputation file\"; iprep:any,emergingthreatspro,=,127; sid:10002; rev:1;)",
		"alert tcp any any -> any any (msg:\"Bad reputation: Usom IP Blacklist\"; iprep:any,usom,=,127; sid:10003; rev:1;)",
		"alert tcp any any -> any any (msg:\"Bad reputation: Firehol level 1 reputation list\"; iprep:any,firehol1,=,127; sid:10004; rev:1;)",
		"alert tcp any any -> any any (msg:\"Bad reputation: Firehol strong\"; iprep:any,firehol_strong,=,127; sid:10005; rev:1;)",
		"alert tcp any any -> any any (msg:\"Bad reputation: CINS Army List\"; iprep:any,cins,=,127; sid:10006; rev:1;)",
		"alert ip $HOME_NET any -> any any (msg:\"OTX internal host talking to host known in pulse\"; flow:to_server; iprep:dst,Pulse,>,30; sid:41414141; rev:1;)",
	}
	if gbconf.DataShieldIPv4Blocklist == 1 {
		rules = append(rules, "alert tcp any any -> any any (msg:\"Bad reputation: Data-Shield IPv4 Blocklist\"; iprep:any,dsipv4,=,127; sid:10007; rev:1;)")
	}

	// Join the rules into a single string with newlines
	rulesContent := strings.Join(rules, "\n")
	rulesFilePath := "/etc/suricata/rules/iprep.rules"
	_ = futils.FilePutContents(rulesFilePath, rulesContent)
}
func IPRepCategories() {
	// Define the categories
	categories := []string{
		"1,alienvault,Alien Vault reputation IPs",
		"2,emergingthreatspro,Emerging Threats Pro reputation file",
		"3,usom,Usom IP Blacklist",
		"4,firehol1,Firehol level 1 reputation list",
		"5,firehol_strong,Firehol more than 5.000 attacks during 2 months",
		"6,cins,CINS Army List",
		"7,dsipv4,Data-Shield IPv4 Blocklist",
		"41,Pulse,OTX community identified IP address",
	}
	categoriesContent := strings.Join(categories, "\n")
	categoriesFilePath := "/etc/suricata/iprep/categories.org"
	_ = futils.FilePutContents(categoriesFilePath, categoriesContent)
}

type SuriIfaces struct {
	IFaceName string
	threads   int
}

func hyperScan() (bool, string) {
	// Read the content of /proc/cpuinfo
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		fmt.Println("Error opening /proc/cpuinfo:", err)
		return false, "ac"
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	var flags string
	mpmAlgo := "hs"
	hyperScanSupported := false
	HyperScanNotCompiled := sockets.GET_INFO_INT("HyperScanNotCompiled")
	if HyperScanNotCompiled == 1 {
		return false, "ac"
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "flags") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				flags = strings.TrimSpace(parts[1])
			}
		}
	}
	flagArray := strings.Split(flags, " ")
	for _, flag := range flagArray {
		flag = strings.TrimSpace(flag)
		if flag == "" {
			continue
		}
		if flag == "ssse3" {
			hyperScanSupported = true
			break
		}
	}

	if !hyperScanSupported {
		mpmAlgo = "ac"
	}
	return hyperScanSupported, mpmAlgo

}

func writePersoRule() string {
	var f []string
	filePath := "/etc/suricata/rules/local.rules"
	f = append(f, " - local.rules")
	myrule := `alert tcp any any -> any any ( app-layer-protocol:ssh; flow:to_server,established; msg:"SSH session detected"; classtype:policy-violation; sid:1000001; rev:1; )`
	_ = futils.FilePutContents(filePath, myrule+"\n")
	return strings.Join(f, "\n")
}

func PatchTables() {
	db, err := SqliteConns.SuricataConnectRW()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS suricata_rules_packages ( rulefile TEXT NOT NULL PRIMARY KEY , category TEXT NOT NULL, enabled INTEGER DEFAULT 0)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS suricata_interfaces ( interface TEXT  PRIMARY KEY, threads INTEGER NOT NULL DEFAULT 0, enable INTEGER NOT NULL DEFAULT 1 )`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS dummytable (ID INTEGER PRIMARY KEY AUTOINCREMENT,CommonName TEXT UNIQUE)`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}
	csqlite.FieldExistCreateINT(db, "suricata_interfaces", "WantIPv6")
	csqlite.FieldExistCreateINT(db, "suricata_interfaces", "WhiteInternalNets")
	csqlite.FieldExistCreateINT(db, "suricata_interfaces", "NoBrodcast")
	csqlite.FieldExistCreateINT(db, "suricata_interfaces", "NoMulticast")
	csqlite.FieldExistCreateINT(db, "suricata_interfaces", "NoARP")
	csqlite.FieldExistCreateINT(db, "suricata_interfaces", "OnlyNewTCP")
	csqlite.FieldExistCreateTEXTVal(db, "suricata_interfaces", "PortsTCP", "*")
	csqlite.FieldExistCreateTEXTVal(db, "suricata_interfaces", "PortsUDP", "*")
	csqlite.FieldExistCreateINT(db, "suricata_rules_packages", "rulesnumber")

	suricata_rules_packages_count := csqlite.CountRows(db, "suricata_rules_packages")

	if suricata_rules_packages_count == 0 {
		_, err = db.Exec(`INSERT OR IGNORE INTO suricata_rules_packages (rulefile,enabled,category) VALUES
		('botcc.rules',0,'DMZ'),
		('ciarmy.rules',0,'DMZ'),
		('compromised.rules','0','DMZ'),
		('drop.rules',1,'DMZ'),
		('emerging-activex.rules',1,'WEB'),
		('emerging-attack_response.rules',1,'ALL'),
		('emerging-chat.rules',0,'WEB'),
		('emerging-current_events.rules',0,'ALL'),
		('emerging-dns.rules',0,'DMZ'),
		('emerging-dos.rules',0,'DMZ'),
		('emerging-exploit.rules',0,'DMZ'),
		('emerging-ftp.rules',0,'DMZ'),
		('emerging-games.rules',0,'ALL'),
		('emerging-icmp_info.rules',0,'ALL'),
		('emerging-icmp.rules',0,'ALL'),
		('emerging-imap.rules',0,'DMZ'),
		('emerging-inappropriate.rules',0,'WEB'),
		('emerging-malware.rules',1,'WEB'),
		('emerging-mobile_malware.rules',0,'WEB'),
		('emerging-netbios.rules',0,'ALL'),
		('emerging-p2p.rules',0,'WEB'),
		('emerging-policy.rules',1,'WEB'),
		('emerging-pop3.rules',0,'DMZ'),
		('emerging-rpc.rules',0,'ALL'),
		('emerging-scada.rules',0,'ALL'),
		('emerging-scan.rules',1,'ALL'),
		('emerging-shellcode.rules',1,'ALL'),
		('emerging-smtp.rules',0,'DMZ'),
		('emerging-snmp.rules',0,'ALL'),
		('emerging-sql.rules',0,'ALL'),
		('emerging-telnet.rules',0,'ALL'),
		('emerging-tftp.rules',0,'ALL'),
		('emerging-trojan.rules',1,'ALL'),
		('emerging-user_agents.rules',0,'ALL'),
		('emerging-voip.rules',0,'ALL'),
		('emerging-web_client.rules',1,'HTTP'),
		('emerging-web_server.rules',0,'HTTP'),
		('emerging-web_specific_apps.rules',0,'HTTP'),
		('emerging-worm.rules',1,'ALL'),
		('tor.rules',0,'ALL'),
		('decoder-events.rules',0,'ALL'),
		('stream-events.rules',0,'ALL'),
		('http-events.rules',0,'HTTP'),
		('smtp-events.rules',0,'DMZ'),
		('dns-events.rules',0,'DMZ'),
		('tls-events.rules',0,'DMZ')`)

	}

}

func DumpRules() error {
	db, err := SqliteConns.SuricataRulesConnectRO()
	if err != nil {
		notifs.BuildProgress(110, err.Error(), DumpRulesPF)
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return err
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	outPath := "/etc/suricata/rules/Production.rules"
	notifs.BuildProgress(5, "{building}", DumpRulesPF)
	n, err := dumpEnabledRules(db, outPath)
	if err != nil {
		notifs.BuildProgress(110, err.Error(), DumpRulesPF)
		log.Error().Msgf("%v dump rules failed %v", futils.GetCalleRuntime(), err.Error())
		return err
	}
	log.Info().Msgf("%v wrote %d rules", futils.GetCalleRuntime(), n)
	notifs.BuildProgress(100, "{success}", DumpRulesPF)
	return nil
}
func dumpEnabledRules(db *sql.DB, outPath string) (written int, err error) {

	var Max int
	err1 := db.QueryRow(`SELECT count(*) as tcount FROM rules WHERE enabled = 1;`).Scan(&Max)
	if err1 != nil {
		return 0, fmt.Errorf("query rules: %w", err1)
	}
	if Max == 0 {
		return 0, nil
	}
	log.Info().Msgf("%v %d rules to dump", futils.GetCalleRuntime(), Max)

	const q = `SELECT raw FROM rules WHERE enabled = 1 ORDER BY sid;`
	rows, err := db.Query(q)
	if err != nil {
		return 0, fmt.Errorf("query rules: %w", err)
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".rules-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()

	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	w := bufio.NewWriterSize(tmp, 256*1024) // 256 KiB buffer
	C := 0
	oldprc := 0
	for rows.Next() {
		var raw string
		C++

		prc := int(int(float64(C) / float64(Max) * 100))
		if prc != oldprc {
			oldprc = prc
			notifs.BuildProgress(55, fmt.Sprintf("{rules}: %v%% %d/%d", prc, C, Max), "suricata.reconfigure.progress")
			if prc > 5 && prc < 95 {
				notifs.BuildProgress(prc, fmt.Sprintf("%d/%d", C, Max), DumpRulesPF)
			}
		}

		if err = rows.Scan(&raw); err != nil {
			return written, fmt.Errorf("scan row: %w", err)
		}
		// Ensure each rule ends with exactly one newline
		if _, err = w.WriteString(raw); err != nil {
			return written, fmt.Errorf("write rule: %w", err)
		}
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			if err = w.WriteByte('\n'); err != nil {
				return written, fmt.Errorf("write newline: %w", err)
			}
		}
		written++
	}
	if err = rows.Err(); err != nil {
		return written, fmt.Errorf("rows err: %w", err)
	}
	if err = w.Flush(); err != nil {
		return written, fmt.Errorf("flush: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return written, fmt.Errorf("fsync: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return written, fmt.Errorf("close: %w", err)
	}
	if err = os.Chmod(tmpPath, 0o644); err != nil {
		return written, fmt.Errorf("chmod temp: %w", err)
	}
	if err = os.Rename(tmpPath, outPath); err != nil {
		return written, fmt.Errorf("atomic rename %s -> %s: %w", tmpPath, outPath, err)
	}
	return written, nil
}
func getHttpPorts() []string {
	HttpPorts := make(map[int]bool)
	HttpPorts[80] = true
	SquidPort := SquidPorts()
	for _, port := range SquidPort {
		HttpPorts[port] = true
	}
	var res []string
	for zPort, _ := range HttpPorts {
		res = append(res, futils.IntToString(zPort))
	}
	return res

}
func SquidPorts() []int {
	SQUIDEnable := sockets.GET_INFO_INT("SQUIDEnable")

	if SQUIDEnable == 0 {
		return []int{}
	}
	db, err := sql.Open("sqlite3", "/home/artica/SQLITE/proxy.db?mode=ro")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []int{}
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	csqlite.ConfigureDBPool(db)
	sqlStatement := `SELECT port FROM proxy_ports WHERE enabled = 1`

	rows, err := db.Query(sqlStatement)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []int{}
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {

		}
	}(rows)

	var Res []int
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			return []int{}
		}

		// Skip port 80
		if port == 80 {
			continue
		}

		// Only add positive ports
		if port > 0 {
			Res = append(Res, port)
		}
	}
	return Res
}
func classficationPath() string {

	f := []string{"/etc/suricata/rules/classification.config",
		"/var/lib/suricata/rules/classification.config", "/usr/share/suricata/classification.config"}
	for _, fpath := range f {
		if futils.FileExists(fpath) {
			return fpath
		}
	}
	return "/etc/suricata/rules/classification.config"
}
func buildClassification() {
	fileContent, err := os.ReadFile(classficationPath())
	if err != nil {
		log.Error().Msgf("%v failed to read classification.config: %v", futils.GetCalleRuntime(), err)
		return
	}
	conn, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v failed to connect to database: %v", futils.GetCalleRuntime(), err)
		return
	}
	defer func(conn *sql.DB) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)

	lines := strings.Split(string(fileContent), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		shortname, description, priority := futils.RegexGroup3(ClassificationsRegex, line)
		if len(shortname) > 1 {

			uduniq := fmt.Sprintf("%x", md5.Sum([]byte(description)))

			_, err := conn.Exec(`INSERT INTO suricata_classifications (uduniq, shortname, description, priority) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, uduniq, shortname, description, priority)
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			}

		}
	}

}
func runSuricataSelfTest(TargetFile string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	suricata := futils.FindProgram("suricata")
	cmd := exec.CommandContext(ctx,
		suricata,
		"-v",
		"-c", TargetFile,
		"-T",
	)

	// Put the process in its own group so we can kill the group if we time out.
	// (exec.CommandContext only kills the direct child, not children-of-child.)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	// Start the command
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start suricata: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		// Completed (success or failure). Return whatever output we captured.
		if err != nil {
			// Include Suricata’s output in the error for easier debugging.
			return buf.String(), fmt.Errorf("suricata test failed: %w", err)
		}
		return buf.String(), nil

	case <-ctx.Done():
		// Timed out; kill the entire process group.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // best-effort
		<-done                                              // wait for Wait() to return
		return buf.String(), fmt.Errorf("timeout after 5 minutes: %w", ctx.Err())
	}
}
func CheckConfig(TargetFile string) error {

	out, err := runSuricataSelfTest(TargetFile)
	if err != nil {
		log.Error().Msgf("%v %v but continue analyzing...", futils.GetCalleRuntime(), err.Error())
	}

	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		log.Info().Msgf("%v [%v]", futils.GetCalleRuntime(), line)

		if strings.Contains(line, `Hyperscan (hs) support for mpm-algo is not compiled`) {
			sockets.SET_INFO_INT("HyperScanNotCompiled", 1)
			return fmt.Errorf("%v disabling HyperScan (not compiled), please reconfigure", futils.GetCalleRuntime())
		}

		if strings.HasPrefix(line, "Error:") {
			return fmt.Errorf(line)
		}
		if strings.Contains(line, "Configuration provided was successfully") {
			return nil
		}
	}
	return fmt.Errorf(out)

}
func Buildsyslog() {

	md51 := ""
	targetFile := "/etc/rsyslog.d/00_suricata.conf"
	SourceFile := "/var/log/suricata/eve.json"
	if futils.FileExists(targetFile) {
		md51 = futils.MD5File(targetFile)
	}
	var f []string

	f = append(f, fmt.Sprintf("\tif  ($programname =='suricata') then {"))
	f = append(f, Buildlocalsyslogfile("/var/log/suricata/suricata-service.log"))
	f = append(f, fmt.Sprintf("\t\tstop"))
	f = append(f, fmt.Sprintf("\t}"))
	f = append(f, "")
	f = append(f, "# Suricata parse file")
	f = append(f, fmt.Sprintf("input(type=\"imfile\" file=\"%v\" Tag=\"eve-json\" reopenOnTruncate=\"on\")", SourceFile))
	f = append(f, "")
	f = append(f, "template(name=\"SuricataEveJsonTPL\" type=\"string\" string=\"<%PRI%>%TIMESTAMP% %syslogtag:1:32%%msg:::sp-if-no-1st-sp%%msg%\")")
	f = append(f, "if  ($programname =='eve-json') then {")
	Queues := logsink.QueuesConfig()
	f = append(f, "\taction(name=\"SuricataEveJson\" template=\"SuricataEveJsonTPL\" type=\"omfwd\" queue.type=\"linkedlist\" queue.filename=\"SuricataEveJson\" "+Queues+" queue.maxDiskSpace=\"10M\" queue.spoolDirectory=\"/home/artica/syslog/spool\" action.resumeRetryCount=\"-1\" action.reportSuspension=\"on\" queue.saveOnShutdown=\"on\" target=\"127.0.0.1\" port=\"5516\" protocol=\"udp\")")
	f = append(f, "\t&stop")
	f = append(f, "}")
	f = append(f, "")
	_ = futils.FilePutContents(targetFile, strings.Join(f, "\n"))

	md52 := futils.MD5File(targetFile)
	if md51 == md52 {
		log.Debug().Msgf("%v: %v [UNCHANGED]", futils.GetCalleRuntime(), targetFile)
		return
	}
	log.Info().Msgf("%v: %v [UPDATED]", futils.GetCalleRuntime(), targetFile)
	logsink.Restart()

}
func Buildlocalsyslogfile(tfile string) string {
	futils.CreateDir(filepath.Dir(tfile))
	return fmt.Sprintf("\taction(type=\"omfile\" dirCreateMode=\"0700\" FileCreateMode=\"0755\" File=\"%v\" ioBufferSize=\"128k\" flushOnTXEnd=\"off\" asyncWriting=\"on\")", tfile)
}

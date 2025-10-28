package PFRingIfaces

import (
	"BPFfilter"
	"SqliteConns"
	"database/sql"
	"fmt"
	"futils"
	"ipclass"
	"sockets"
	"strings"

	"github.com/rs/zerolog/log"
)

func Load() []BPFfilter.Settings {
	db, err := SqliteConns.SuricataConnectRO()
	if err != nil {
		return []BPFfilter.Settings{}
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	rows, err := db.Query("SELECT interface,threads,WantIPv6,WhiteInternalNets,NoBrodcast,NoMulticast,NoARP,OnlyNewTCP,PortsTCP,PortsUDP FROM suricata_interfaces WHERE enable=1")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return []BPFfilter.Settings{}
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var Res []BPFfilter.Settings
	for rows.Next() {
		var interfaceName string
		var threads, WantIPv6, WhiteInternalNets, NoBrodcast, NoMulticast, NoARP, OnlyNewTCP sql.NullInt32
		var PortsTCP, PortsUDP sql.NullString
		err = rows.Scan(&interfaceName, &threads, &WantIPv6, &WhiteInternalNets, &NoBrodcast, &NoMulticast, &NoARP, &OnlyNewTCP, &PortsTCP, &PortsUDP)
		if err != nil {
			log.Error().Msgf("%v Failed to scan row: %v", futils.GetCalleRuntime(), err)
			continue
		}

		if !ipclass.IsInterfaceExists(interfaceName) {
			log.Error().Msgf("%v Interface:%s Failed", futils.GetCalleRuntime(), interfaceName)
			continue
		}
		var ifac BPFfilter.Settings
		ifac.Iface = interfaceName
		ifac.Threads = int(threads.Int32)
		ifac.WantIPv6 = futils.Int32NilToBool(WantIPv6)
		ifac.WhiteInternalNets = futils.Int32NilToInt(WhiteInternalNets)
		ifac.NoBrodcast = futils.Int32NilToBool(NoBrodcast)
		ifac.NoMulticast = futils.Int32NilToBool(NoMulticast)
		ifac.NoARP = futils.Int32NilToBool(NoARP)
		ifac.OnlyNewTCP = futils.Int32NilToBool(OnlyNewTCP)
		ifac.PortsTCPStr = PortsTCP.String
		ifac.PortsUDPStr = PortsUDP.String
		Res = append(Res, ifac)
	}
	return Res
}
func Build() string {
	var f []string
	ifaces := Load()
	f = append(f, fmt.Sprintf("# Listen Interfaces here: PFRING (%v)", futils.GetCalleRuntime()))
	f = append(f, fmt.Sprintf("# %v Listen Interfaces", futils.GetCalleRuntime()))
	f = append(f, "# PF_RING configuration. for use with native PF_RING support")
	f = append(f, "# for more info see https://www.ntop.org/PF_RING.html")

	clid := 100
	c := 0
	f = append(f, "pfring:")

	suricataInterface := sockets.GET_INFO_STR("SuricataInterface")
	if suricataInterface == "" {
		suricataInterface = ipclass.DefaultInterface()
	}
	TrustedNets := BPFfilter.TrustedNets()
	// Iterate over query results
	for _, iface := range ifaces {
		if !ipclass.IsInterfaceExists(iface.Iface) {
			continue
		}
		clid--
		threadCount := "auto"
		iface.TrustedNets = TrustedNets
		if iface.Threads > 0 {
			threadCount = futils.IntToString(iface.Threads)
		}
		if !ipclass.IsInterfaceExists(suricataInterface) {
			f = append(f, fmt.Sprintf("# %s not found inside the system", suricataInterface))
			continue
		}

		f = append(f, fmt.Sprintf("  - interface: %v", iface.Iface))
		f = append(f, fmt.Sprintf("    cluster-id: %d", clid))
		f = append(f, fmt.Sprintf("    cluster-type: cluster_flow"))
		f = append(f, fmt.Sprintf("    defrag: yes"))
		f = append(f, fmt.Sprintf("    use-mmap: yes"))
		f = append(f, fmt.Sprintf("    tpacket-v3: yes"))
		f = append(f, fmt.Sprintf("    copy-mode: ips"))
		f = append(f, fmt.Sprintf("    ring-size: 200000"))
		f = append(f, fmt.Sprintf("    buffer-size: 32768"))
		f = append(f, fmt.Sprintf("    enable-zc: no"))
		f = append(f, fmt.Sprintf("    threads: %v", threadCount))
		filter := BPFfilter.Build(iface)
		f = append(f, fmt.Sprintf("    bpf-filter: \"%v\"", filter))
		f = append(f, "")
		c++
	}

	if c == 0 {
		f = append(f, fmt.Sprintf("# no interface set, use the default %s", suricataInterface))
		threadCount := "auto"
		f = append(f, fmt.Sprintf("  - interface: %s", suricataInterface))
		f = append(f, fmt.Sprintf("    cluster-id: %d", clid))
		f = append(f, fmt.Sprintf("    cluster-type: cluster_flow"))
		f = append(f, fmt.Sprintf("    defrag: yes"))
		f = append(f, fmt.Sprintf("    use-mmap: yes"))
		f = append(f, fmt.Sprintf("    tpacket-v3: yes"))
		f = append(f, fmt.Sprintf("    copy-mode: ips"))
		f = append(f, fmt.Sprintf("    ring-size: 200000"))
		f = append(f, fmt.Sprintf("    buffer-size: 32768"))
		f = append(f, fmt.Sprintf("    enable-zc: no"))
		f = append(f, fmt.Sprintf("    threads: %v", threadCount))
		f = append(f, fmt.Sprintf("    # If you also want to see TLS/SNI on :443:"))
		f = append(f, fmt.Sprintf("    bpf-filter: \"tcp and port 443\""))
		f = append(f, "")

	}

	return strings.Join(f, "\n")
}

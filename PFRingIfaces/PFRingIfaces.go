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
func ConfiguredIfaces() []BPFfilter.Settings {
	var res []BPFfilter.Settings

	ifaces := Load()
	if len(ifaces) < 1 {
		suricataInterface := sockets.GET_INFO_STR("SuricataInterface")
		if suricataInterface == "" {
			suricataInterface = ipclass.DefaultInterface()
			var f BPFfilter.Settings
			f.Iface = suricataInterface
			res = append(res, f)
			return res
		}
	}

	for _, iface := range ifaces {
		if !ipclass.IsInterfaceExists(iface.Iface) {
			continue
		}
		ifaceStatus := ipclass.GetInterfaceState(iface.Iface)
		log.Info().Msgf("%v Interface:%s Status:%s", futils.GetCalleRuntime(), iface.Iface, ifaceStatus)
		if ifaceStatus != "up" {
			continue
		}

		res = append(res, iface)
	}
	return res
}

func Build() string {
	var f []string
	ifaces := ConfiguredIfaces()
	f = append(f, fmt.Sprintf("# Listen Interfaces here: PFRING (%v)", futils.GetCalleRuntime()))
	f = append(f, fmt.Sprintf("# %v Listen Interfaces", futils.GetCalleRuntime()))
	f = append(f, "# PF_RING configuration. for use with native PF_RING support")
	f = append(f, "# for more info see https://www.ntop.org/PF_RING.html")

	clid := 100
	c := 0
	f = append(f, "pfring:")

	TrustedNets := BPFfilter.TrustedNets()

	for _, iface := range ifaces {
		clid--
		threadCount := "auto"
		iface.TrustedNets = TrustedNets
		if iface.Threads > 0 {
			threadCount = futils.IntToString(iface.Threads)
		}
		f = append(f, fmt.Sprintf("  - interface: %v", iface.Iface))
		f = append(f, fmt.Sprintf("    cluster-id: %d", clid))
		f = append(f, fmt.Sprintf("    cluster-type: cluster_flow"))
		f = append(f, fmt.Sprintf("    defrag: yes"))
		f = append(f, fmt.Sprintf("    ring-size: 200000"))
		f = append(f, fmt.Sprintf("    buffer-size: 32768"))
		f = append(f, fmt.Sprintf("    enable-zc: no"))
		f = append(f, fmt.Sprintf("    threads: %v", threadCount))
		filter := BPFfilter.Build(iface)
		f = append(f, fmt.Sprintf("    bpf-filter: \"%v\"", filter))
		f = append(f, "")
		c++
	}

	return strings.Join(f, "\n")
}

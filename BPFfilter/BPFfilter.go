package BPFfilter

import (
	"database/sql"
	"fmt"
	"futils"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type Settings struct {
	Iface             string
	PortsTCP          []int
	PortsUDP          []int
	PortsTCPStr       string
	PortsUDPStr       string
	WantIPv6          bool
	WhiteInternalNets int
	NoBrodcast        bool
	NoMulticast       bool
	NoARP             bool
	OnlyNewTCP        bool
	Threads           int
	TrustedNets       map[string]bool
}

func Build(Params Settings) string {
	var and []string
	if Params.WantIPv6 {
		and = append(and, "(ip or ip6)")
	} else {
		and = append(and, "ip")
	}
	Params.PortsTCP, _ = ParsePorts(Params.PortsTCPStr)
	Params.PortsUDP, _ = ParsePorts(Params.PortsUDPStr)

	switch {
	case len(Params.PortsTCP) > 0 && len(Params.PortsUDP) > 0:
		and = append(and, "(tcp or udp)")
	case len(Params.PortsTCP) > 0:
		and = append(and, "tcp")
	case len(Params.PortsUDP) > 0:
		and = append(and, "udp")
	}

	var pc []string
	for _, p := range Params.PortsTCP {
		pc = append(pc, fmt.Sprintf("tcp port %d", p))
	}
	for _, p := range Params.PortsUDP {
		pc = append(pc, fmt.Sprintf("udp port %d", p))
	}
	if len(pc) > 0 {
		and = append(and, "("+strings.Join(pc, " or ")+")")
	}
	var AndNets []string
	AndNets = append(AndNets, "src net 127.0.0.0/8")

	if Params.WhiteInternalNets == 1 {
		for n := range Params.TrustedNets {
			AndNets = append(AndNets, fmt.Sprintf("src net %s", n))
		}
		and = append(and, "not ("+strings.Join(AndNets, " or ")+")")
	}
	extra := extraPerfs(Params)
	and = append(and, extra...)
	return strings.Join(and, " and ")
}

func extraPerfs(Params Settings) []string {
	var f []string
	if Params.NoBrodcast {
		f = append(f, "ether broadcast")
	}
	if Params.NoMulticast {
		f = append(f, "ether multicast")
	}
	if Params.NoARP {
		f = append(f, "arp")
	}
	f = append(f, "net 224.0.0.0/4")
	var extra []string
	extra = append(extra, "not ("+strings.Join(f, " or ")+")")
	if Params.OnlyNewTCP {
		Orudp := ""
		if len(Params.PortsUDP) > 0 {
			Orudp = "or udp"
		}
		extra = append(extra, futils.Trim(fmt.Sprintf("(tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn) %v", Orudp)))
	}
	return extra

}
func TrustedNets() map[string]bool {
	zNet := make(map[string]bool)

	if !futils.FileExists("/home/artica/SQLITE/interfaces.db") {
		return zNet
	}
	dsn := fmt.Sprintf("file:%v?mode=ro&_busy_timeout=5000", "/home/artica/SQLITE/interfaces.db")
	db, err := sql.Open("sqlite3", dsn)

	if err != nil {
		log.Error().Msgf("%v %v", err.Error())
		return zNet
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	err = db.Ping()
	if err != nil {
		log.Error().Msgf("%v %v", err.Error())
		return zNet
	}

	Query := "SELECT ipaddr FROM networks_infos WHERE trusted=1 AND enabled=1"
	rows, err := db.Query(Query)
	if err != nil {
		log.Error().Msgf("%v:%v %v", futils.GetCalleRuntime(), Query, err.Error())
		_ = db.Close()
		return zNet
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		var ipaddr string
		err := rows.Scan(&ipaddr)
		if err != nil {
			log.Error().Msgf("%v: Error while scanning row %v", futils.GetCalleRuntime(), err.Error())
			_ = rows.Close()
			_ = db.Close()
			return zNet
		}

		pattern := ipaddr
		pattern = strings.ReplaceAll(pattern, "/255.255.255.0", "/24")

		if pattern == "0.0.0.0/0.0.0.0" {
			continue
		}
		zNet[pattern] = true

	}
	return zNet
}
func ParsePorts(pattern string) ([]int, error) {
	const minPort, maxPort = 0, 65535
	pattern = strings.ReplaceAll(pattern, " ", ",")
	pattern = strings.ReplaceAll(pattern, ";", ",")
	pattern = strings.ReplaceAll(pattern, "\n", ",")
	if strings.Contains(pattern, "*") {
		return []int{}, nil
	}
	clean := func(s string) string {
		return strings.TrimFunc(s, unicode.IsSpace)
	}
	var (
		set  = make(map[int]struct{}, 1024)
		errs []string
	)

	items := strings.Split(pattern, ",")
	for _, raw := range items {
		item := clean(raw)
		if item == "" {
			continue
		}

		// Range?
		if dash := strings.IndexRune(item, '-'); dash >= 0 {
			left := strings.TrimSpace(item[:dash])
			right := strings.TrimSpace(item[dash+1:])

			var (
				start, end int
				err        error
			)

			// Open-ended start
			if left == "" {
				start = minPort
			} else {
				start, err = strconv.Atoi(left)
				if err != nil {
					errs = append(errs, fmt.Sprintf("invalid start %q in %q", left, item))
					continue
				}
			}

			// Open-ended end
			if right == "" {
				end = maxPort
			} else {
				end, err = strconv.Atoi(right)
				if err != nil {
					errs = append(errs, fmt.Sprintf("invalid end %q in %q", right, item))
					continue
				}
			}

			// Clamp and normalize
			if start < minPort {
				start = minPort
			}
			if end > maxPort {
				end = maxPort
			}
			if start > end {
				start, end = end, start // allow reversed ranges
			}

			for p := start; p <= end; p++ {
				set[p] = struct{}{}
			}
			continue
		}

		val, err := strconv.Atoi(item)
		if err != nil {
			errs = append(errs, fmt.Sprintf("invalid port %q", item))
			continue
		}
		if val < minPort || val > maxPort {
			errs = append(errs, fmt.Sprintf("port %d out of range [0..65535]", val))
			continue
		}
		set[val] = struct{}{}
	}
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	if len(errs) > 0 {
		return ports, fmt.Errorf(strings.Join(errs, "; "))
	}
	return ports, nil
}

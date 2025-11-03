package PortsGrouping

import (
	"fmt"
	"futils"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

const (
	minPort = 1
	maxPort = 65535
)

type interval struct{ lo, hi int }

// GroupPorts converts tokens like []string{"80","1024-2048","!90","!88"}
// into a single model-grouping string, e.g. "[80,1024:2048,![88,90]]".
func GroupPorts(tokens []string) string {
	var inc []interval
	exclSingles := map[int]struct{}{}

	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		neg := strings.HasPrefix(t, "!")
		if neg {
			t = strings.TrimSpace(t[1:])
		}

		lo, hi, err := parsePortOrRange(t)
		if err != nil {
			log.Error().Msgf("%v failed to parse port or range: %v bad token  %v", futils.GetCalleRuntime(), t, err.Error())
			return ""
		}

		if neg {
			if lo == hi {
				exclSingles[lo] = struct{}{}
			} else {
				// For excluded ranges, just mark every point would be expensive;
				// instead, we'll handle by splitting inclusions once we build them.
				// To keep this simple and fast, we split *after* merging inclusions.
				// Represent excluded ranges by a special negative interval.
				// For now, support single-port excludes only (most common).
				log.Error().Msgf("%v failed to parse port or range: %v range exclusions %d-%d not supported in this version", futils.GetCalleRuntime(), t, lo, hi)
				return ""
			}
			continue
		}

		inc = append(inc, interval{lo, hi})
	}

	if len(inc) == 0 {
		inc = []interval{{minPort, maxPort}}
	}

	inc = mergeIntervals(inc)
	inc, exInRange := applySingleExclusions(inc, exclSingles)

	// Build output pieces
	var parts []string
	for _, iv := range inc {
		switch {
		case iv.lo == iv.hi:
			parts = append(parts, fmt.Sprintf("%d", iv.lo))
		case iv.lo == minPort && iv.hi == maxPort:
			parts = append(parts, "1:")
		case iv.hi == maxPort:
			parts = append(parts, fmt.Sprintf("%d:", iv.lo))
		default:
			parts = append(parts, fmt.Sprintf("%d:%d", iv.lo, iv.hi))
		}
	}
	var final []string
	for i, iv := range inc {
		base := parts[i]
		if xs, ok := exInRange[keyFor(iv)]; ok && len(xs) > 0 {
			sort.Ints(xs)
			if iv.lo == iv.hi {
				final = append(final, base)
			} else {
				var sb strings.Builder
				sb.WriteString(base)
				sb.WriteString(",![")
				for j, p := range xs {
					if j > 0 {
						sb.WriteString(",")
					}
					sb.WriteString(strconv.Itoa(p))
				}
				sb.WriteString("]")
				final = append(final, sb.String())
			}
		} else {
			final = append(final, base)
		}
	}
	return "[" + strings.Join(final, ",") + "]"
}

func parsePortOrRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("empty")
	}
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		if len(parts) != 2 {
			return 0, 0, fmt.Errorf("invalid range %q", s)
		}
		lo, err := parsePort(parts[0])
		if err != nil {
			return 0, 0, err
		}
		hiStr := strings.TrimSpace(parts[1])
		var hi int
		if hiStr == "" {
			hi = maxPort
		} else {
			hi, err = parsePort(hiStr)
			if err != nil {
				return 0, 0, err
			}
		}
		if lo > hi {
			return 0, 0, fmt.Errorf("range start > end in %q", s)
		}
		return lo, hi, nil
	}
	p, err := parsePort(s)
	if err != nil {
		return 0, 0, err
	}
	return p, p, nil
}

func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not a number: %q", s)
	}
	if n < minPort || n > maxPort {
		return 0, fmt.Errorf("port out of range: %d", n)
	}
	return n, nil
}

func mergeIntervals(a []interval) []interval {
	if len(a) == 0 {
		return a
	}
	sort.Slice(a, func(i, j int) bool {
		if a[i].lo != a[j].lo {
			return a[i].lo < a[j].lo
		}
		return a[i].hi < a[j].hi
	})
	out := make([]interval, 0, len(a))
	cur := a[0]
	for i := 1; i < len(a); i++ {
		if a[i].lo <= cur.hi+1 {
			if a[i].hi > cur.hi {
				cur.hi = a[i].hi
			}
			continue
		}
		out = append(out, cur)
		cur = a[i]
	}
	out = append(out, cur)
	return out
}

func keyFor(iv interval) string { return fmt.Sprintf("%d-%d", iv.lo, iv.hi) }

// Split intervals around single-port exclusions where possible.
// If a single exclusion lies at boundaries, it’s just omitted.
// For exclusions strictly inside a range, we keep the range intact
// and attach the exclusion list to that range (for rendering).
func applySingleExclusions(incs []interval, excl map[int]struct{}) ([]interval, map[string][]int) {
	if len(excl) == 0 {
		return incs, map[string][]int{}
	}

	exMap := map[string][]int{}
	var out []interval

	for _, iv := range incs {
		// Collect exclusions inside iv
		var inside []int
		for p := range excl {
			if p >= iv.lo && p <= iv.hi {
				inside = append(inside, p)
			}
		}
		if len(inside) == 0 {
			out = append(out, iv)
			continue
		}
		sort.Ints(inside)
		start := iv.lo
		for _, p := range inside {
			if p > start {
				out = append(out, interval{start, p - 1})
			}
			start = p + 1
		}
		if start <= iv.hi {
			out = append(out, interval{start, iv.hi})
		}
		exMap[keyFor(iv)] = inside
	}
	out = mergeIntervals(out)
	return out, exMap
}
func ExpandPortRange(s string) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	// Single port?
	if !strings.Contains(s, "-") {
		port, err := strconv.Atoi(s)
		if err != nil {
			return nil
		}
		if port < 1 || port > 65535 {
			return nil
		}
		return []int{port}
	}

	// Range: "start-end"
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return nil
	}

	start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	endStr := strings.TrimSpace(parts[1])
	end := 65535 // open-ended (like "1024-")
	var err2 error
	if endStr != "" {
		end, err2 = strconv.Atoi(endStr)
	}

	if err1 != nil || (endStr != "" && err2 != nil) {
		return nil
	}
	if start < 1 || start > 65535 || end < 1 || end > 65535 {
		return nil
	}
	if end < start {
		return nil
	}

	// Generate list
	count := end - start + 1
	ports := make([]int, 0, count)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ports
}

package afirewall

import (
	"SqliteConns"
	"database/sql"
	"fmt"
	"futils"
	"strings"
)

func BuildShScript(Lines []string, path string) {

	var CONF []string
	CONF = append(CONF, "#!/bin/sh")
	CONF = append(CONF, strings.Join(Lines, "\n"))
	CONF = append(CONF, "\n")
	_ = futils.FilePutContents(path, strings.Join(CONF, "\n"))
	futils.Chmod(path, 0755)
}

func AntiDDos() error {
	iptables := "/usr/sbin/iptables" // Adjust this path as needed
	TargetScript := "/home/artica/firewall/antiddos.sh"

	db, err := SqliteConns.InterfacesConnectRO()
	if err != nil {
		return fmt.Errorf("%v failed to open database: %v", futils.GetCalleRuntime(), err)
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)

	// Execute SQL query
	rows, err := db.Query("SELECT Interface FROM nics WHERE isFW=1 AND AntiDDOS=1")
	if err != nil {
		return fmt.Errorf("%v failed to execute query: %v", futils.GetCalleRuntime(), err)
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var interfaces []string
	for rows.Next() {
		var iface string
		if err := rows.Scan(&iface); err != nil {
			return fmt.Errorf("%v failed to scan row: %v", futils.GetCalleRuntime(), err)
		}
		interfaces = append(interfaces, iface)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("%v error iterating over rows: %v", futils.GetCalleRuntime(), err)
	}

	f := []string{fmt.Sprintf("#\tAnti-DDOS for %d interfaces", len(interfaces))}
	if len(interfaces) == 0 {
		BuildShScript(f, TargetScript)
		return nil
	}

	deny := " -j SMART_REJECT"
	mangle := "-t mangle -A PREROUTING"
	contrkn := "-m conntrack --ctstate NEW"
	drop := " -j DROP || true"

	for _, iface := range interfaces {
		group := "in_" + iface
		comment := fmt.Sprintf("-m comment --comment \"DDOS_%s\"", iface)
		f = append(f, fmt.Sprintf("echo \"DDOS: Drop invalid packets\""))

		f = append(f, fmt.Sprintf("#\tDrop invalid packets"))
		f = append(f, fmt.Sprintf("%s %s -i %s -m conntrack --ctstate INVALID %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, "")

		f = append(f, fmt.Sprintf("echo \"DDOS: Drop TCP packets that are new and are not SYN\""))
		f = append(f, fmt.Sprintf("#\tDrop TCP packets that are new and are not SYN"))
		f = append(f, fmt.Sprintf("%s %s -i %s -p tcp ! --syn %s %s%s", iptables, mangle, iface, contrkn, comment, drop))
		f = append(f, " ")
		f = append(f, fmt.Sprintf("#\tDrop SYN packets with suspicious MSS value"))
		f = append(f, fmt.Sprintf("echo \"DDOS: Drop SYN packets with suspicious MSS value\""))
		f = append(f, fmt.Sprintf("%s %s -i %s -p tcp %s -m tcpmss ! --mss 536:65535 %s%s", iptables, mangle, iface, contrkn, comment, drop))
		f = append(f, "")
		f = append(f, fmt.Sprintf("#\tBlock packets with bogus TCP flags"))
		f = append(f, fmt.Sprintf("echo \"DDOS: Block packets with bogus TCP flags\""))
		f = append(f, fmt.Sprintf("%s %s -i %s -p tcp --tcp-flags FIN,SYN FIN,SYN %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -p tcp --tcp-flags SYN,RST SYN,RST %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -p tcp --tcp-flags FIN,RST FIN,RST %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -p tcp --tcp-flags FIN,ACK FIN %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -p tcp --tcp-flags ACK,URG URG %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -p tcp --tcp-flags ACK,PSH PSH %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -p tcp --tcp-flags ALL NONE %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, "")
		f = append(f, fmt.Sprintf("#\tBlock spoofed packets"))
		f = append(f, fmt.Sprintf("echo \"DDOS: Block spoofed packets\""))
		f = append(f, fmt.Sprintf("%s %s -i %s -s 224.0.0.0/3 %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -s 169.254.0.0/16 %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -s 172.16.0.0/12 %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -s 192.0.2.0/24 %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -s 192.168.0.0/16 %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -s 10.0.0.0/8 %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -s 0.0.0.0/8 %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, fmt.Sprintf("%s %s -i %s -s 240.0.0.0/5 %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, "")
		f = append(f, fmt.Sprintf("#\tDrop fragments in all chains"))
		f = append(f, fmt.Sprintf("%s %s -i %s -f %s%s", iptables, mangle, iface, comment, drop))
		f = append(f, "")
		f = append(f, fmt.Sprintf("#\tLimit connections per source IP"))
		f = append(f, fmt.Sprintf("%s -A %s -p tcp -m connlimit --connlimit-above 111 %s%s", iptables, group, comment, deny))
		f = append(f, "")
		f = append(f, fmt.Sprintf("#\tLimit RST packets ### "))
		f = append(f, fmt.Sprintf("%s -A %s -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 %s -j ACCEPT", iptables, group, comment))
		f = append(f, fmt.Sprintf("%s -A %s -p tcp --tcp-flags RST RST %s%s", iptables, group, comment, deny))
		f = append(f, "")
		f = append(f, fmt.Sprintf("#\tLimit new TCP connections per second per source IP ### "))
		f = append(f, fmt.Sprintf("%s -A %s -p tcp %s -m limit --limit 60/s --limit-burst 20 %s -j ACCEPT", iptables, group, contrkn, comment))
		f = append(f, fmt.Sprintf("%s -A %s -p tcp %s %s%s", iptables, group, contrkn, comment, deny))
		f = append(f, "")
		f = append(f, fmt.Sprintf("#\tUse SYNPROXY on all ports (disables connection limiting rule) ### "))
		f = append(f, "#\tProtection against port scanning")
		f = append(f, fmt.Sprintf("%s -N port-scanning ", iptables))
		f = append(f, fmt.Sprintf("%s -A port-scanning -i %s -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 %s -j RETURN", iptables, iface, comment))
		f = append(f, fmt.Sprintf("%s -A port-scanning %s%s", iptables, comment, deny))
	}
	BuildShScript(f, TargetScript)
	return nil
}

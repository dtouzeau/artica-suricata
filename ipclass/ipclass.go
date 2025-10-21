package ipclass

import (
	"fmt"
	"futils"
	"net"
	"os"
	"path"
	"regexp"
	"runtime"
	"sockets"
	"strconv"
	"strings"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

var ipv4Regex = regexp.MustCompile(`^(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)
var ipclassPatternFind3 = regexp.MustCompile(`^([0-9.]+)-([0-9.]+)$`)

type IfStatus struct {
	Link      string
	Index     int
	MTU       int
	MacAddr   string
	MainIface string
	IpAddr    string
	Flag      string
	State     string
	Error     error
	TxBytes   uint64
	RxBytes   uint64
	Drops     uint64
}

func AllLocalIPs() []string {
	var ips []string
	EnableipV6 := sockets.GET_INFO_INT("EnableipV6")
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	// Iterate over all interfaces
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return ips
		}

		// Iterate over all addresses for the interface
		for _, addr := range addrs {
			var ip net.IP

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Append IP to slice, excluding loopback and undefined addresses
			if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				if EnableipV6 == 0 {
					if IsIPv6(ip.String()) {
						continue
					}
				}
				ips = append(ips, ip.String())
			}
		}
	}

	return ips
}
func IsIPv6(address string) bool {
	address = strings.TrimSpace(address)
	if ipv4Regex.MatchString(address) {
		return false
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	// If To4() returns nil, it means the address is not IPv4, so it's IPv6
	return ip.To4() == nil
}
func ExtractIPFromIpPort(ipstr string) string {
	ipstr = strings.TrimSpace(ipstr)
	Uri := fmt.Sprintf("http://%s", ipstr)
	return futils.ExtractHostnameFromURL(Uri)

}
func IsValidIPorCDIRorRange(s string) bool {
	if strings.Contains(s, "/") {
		if isValidCIDR(s) {
			return true
		}
	}

	if net.ParseIP(s) != nil {
		return true
	}
	if futils.RegexFind(ipclassPatternFind3, s) {
		return true
	}
	return false
}
func isValidCIDR(cidrStr string) bool {
	_, _, err := net.ParseCIDR(cidrStr)
	return err == nil
}
func GetNetworkInterface(ip net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			var ipAddr net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ipAddr = v.IP
			case *net.IPAddr:
				ipAddr = v.IP
			}

			if ipAddr.Equal(ip) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for IP %s", ip.String())
}
func GetOutboundIP() (net.IP, error) {
	conn, err := net.Dial("tcp", "8.8.4.4:443")
	if err != nil {
		return nil, err
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	return localAddr.IP, nil
}
func DetectsInternetOutgoingInterface() string {
	ip, err := GetOutboundIP()
	if err != nil {
		log.Debug().Msg(fmt.Sprintf("%v Failed to get outbound IP %v", futils.GetCalleRuntime(), err.Error()))
		return ""
	}

	iface, err := GetNetworkInterface(ip)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v Failed to get network interface: %v", futils.GetCalleRuntime(), err.Error()))
		return ""
	}

	return iface.Name
}
func AllInterfacesAndAliases() []string {
	// List all network interfaces
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}

	var interfaces []string

	// Iterate through each interface
	for _, link := range links {
		linkName := link.Attrs().Name
		interfaces = append(interfaces, linkName)
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr.Label != "" && addr.Label != linkName {
				interfaces = append(interfaces, addr.Label)
			}
		}
	}

	return interfaces
}
func DefaultInterface() string {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return ""
	}
	for _, route := range routes {
		if route.Dst == nil { // Default route has a nil Dst
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return ""
			}
			return link.Attrs().Name
		}
	}

	iface := DetectsInternetOutgoingInterface()
	if len(iface) > 0 {
		return iface
	}

	Interfaces := AllInterfacesAndAliases()
	if len(Interfaces) == 0 {
		return ""
	}
	for _, iface := range Interfaces {
		if iface == "lo" {
			continue
		}
		if strings.HasPrefix(iface, "eth") || strings.HasPrefix(iface, "ens") || strings.HasPrefix(iface, "enp") || strings.HasPrefix(iface, "eno") {
			Conf := GetLiveConfig(iface)
			if Conf.State == "down" {
				continue
			}
			if strings.HasPrefix(Conf.IpAddr, "127.0") {
				continue
			}
			if isValidIP(Conf.IpAddr) {
				return iface
			}
		}

		Conf := GetLiveConfig(iface)
		if Conf.State == "down" {
			continue
		}
		if strings.HasPrefix(Conf.IpAddr, "127.0") {
			continue
		}
		if isValidIP(Conf.IpAddr) {
			return iface
		}
	}

	return ""
}
func isValidIP(ip string) bool {
	if ip == "" {
		return false
	}
	if len(ip) < 3 {
		return false
	}
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}

type LiveConfig struct {
	IpAddr     string `json:"IpAddr"`
	MacAddr    string `json:"MacAddr"`
	NetMask    string `json:"NetMask"`
	Gateway    string `json:"Gateway"`
	Wireless   bool   `json:"Wireless"`
	Broadcast  string `json:"Broadcast"`
	State      string `json:"State"`
	Network    string `json:"Network"`
	LastUsable string `json:"LastUsable"`
}

func GetLiveConfig(ifname string) LiveConfig {
	var Out LiveConfig

	Out.IpAddr = InterfaceToIPv4(ifname)
	Out.MacAddr = GetMACAddress(ifname)
	Out.NetMask = HexToNetmask(GetNetmask(ifname))
	Out.Network, Out.Broadcast, _ = calculateNetworkAndBroadcast(Out.IpAddr, Out.NetMask)
	Out.Gateway = Getgateway(ifname)
	Out.Wireless = IsWirelessInterface(ifname)
	Out.State = GetInterfaceState(ifname)
	Out.LastUsable, _ = decrementIP(net.ParseIP(Out.Broadcast))
	return Out
}
func GetInterfaceState(interfaceName string) string {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return ""
	}

	if iface.Flags&net.FlagUp != 0 {
		return "up"
	}
	return "down"
}
func decrementIP(ip net.IP) (string, error) {
	ip = ip.To4() // Ensure it's an IPv4 address
	if ip == nil {
		return "", fmt.Errorf("not a valid IPv4 address")
	}

	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] > 0 {
			ip[i]--
			break
		} else {
			ip[i] = 255
		}
	}

	return ip.String(), nil
}
func Getgateway(interfaceName string) string {

	err, gw := DefaultGateway(interfaceName)
	if err == nil {
		return gw
	}
	ipbin := futils.FindProgram("ip")
	err, out := futils.ExecuteShell(fmt.Sprintf("%v route show table all", ipbin))
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line := strings.TrimSpace(line)
		if !strings.Contains(line, "dev "+interfaceName) {
			continue
		}
		if strings.HasPrefix(line, "default via") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[2]
			}
		}
	}

	return ""
}
func IsWirelessInterface(interfaceName string) bool {
	wirelessPath := fmt.Sprintf("/sys/class/net/%s/wireless", interfaceName)
	if _, err := os.Stat(wirelessPath); err == nil {
		return true // The directory exists, so it's a wireless interface
	} else if os.IsNotExist(err) {
		return false // The directory does not exist, so it's not wireless
	} else {
		return false // An error occurred while checking the directory
	}
}
func DefaultGateway(interfaceName string) (error, string) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("Error getting routes ", err), ""
	}

	for _, route := range routes {
		if route.Dst == nil && route.LinkIndex > 0 {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				continue
			}

			if link.Attrs().Name == interfaceName {
				return nil, route.Gw.String()
			}
		}
	}
	gw, err := getDefaultGateway2(interfaceName)
	if err != nil {
		return err, ""
	}
	return nil, gw
}
func getDefaultGateway2(ifaceName string) (string, error) {

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("could not get interface %s: %v", ifaceName, err)
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("could not get routes for interface %s: %v", ifaceName, err)
	}
	for _, route := range routes {
		if route.Dst == nil {
			return route.Gw.String(), nil
		}
	}

	return "", fmt.Errorf("default gateway not found for interface %s", ifaceName)
}
func calculateNetworkAndBroadcast(ipStr string, maskStr string) (string, string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", "", fmt.Errorf("invalid IP address: %s", ipStr)
	}
	mask := net.IPMask(net.ParseIP(maskStr).To4())
	if mask == nil {
		return "", "", fmt.Errorf("invalid subnet mask: %s", maskStr)
	}
	network := ip.Mask(mask)
	broadcast := make(net.IP, len(ip.To4()))
	for i := 0; i < len(network); i++ {
		broadcast[i] = network[i] | ^mask[i]
	}
	network[3] += 1 // Increment the last byte for the first usable IP

	return network.String(), broadcast.String(), nil
}
func GetNetmask(interfaceName string) string {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			return ipNet.Mask.String()
		}
	}

	return ""
}
func HexToNetmask(hexStr string) string {
	num, err := strconv.ParseUint(hexStr, 16, 32)
	if err != nil {
		return ""
	}
	octet1 := num >> 24 & 0xFF
	octet2 := num >> 16 & 0xFF
	octet3 := num >> 8 & 0xFF
	octet4 := num & 0xFF
	netmask := fmt.Sprintf("%d.%d.%d.%d", octet1, octet2, octet3, octet4)
	return netmask
}
func GetMACAddress(interfaceName string) string {
	// Get a list of all network interfaces
	interfaceName = strings.ToLower(interfaceName)
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	// Iterate over all interfaces
	for _, iface := range interfaces {
		if strings.ToLower(iface.Name) == interfaceName {
			return iface.HardwareAddr.String()
		}
	}

	return ""
}
func IsLocalIPAddress(ipToCheck string) bool {
	if len(ipToCheck) < 3 {
		return false
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, intf := range interfaces {
		addrs, err := intf.Addrs()
		if err != nil {
			log.Error().Msgf("%v Error getting addresses: %v", futils.GetCalleRuntime(), err)
			continue
		}
		for _, addr := range addrs {
			current := addr.String()
			if strings.Contains(current, "/") {
				tb := strings.Split(current, "/")
				current = tb[0]
			}
			log.Debug().Msgf("%v: Checking IP %v (%v)", futils.GetCalleRuntime(), addr.String(), current)
			if current == ipToCheck {
				return true
			}

		}
	}

	return false
}
func IsIPAddress(s string) bool {
	switch s {
	case "-", "!nil", "", "0.0.0.0":
		return false
	case "127.0.0.1", "::1":
		return true
	}
	return isValidIP(s)
}
func getVirtualAliasInfo(aliasName string) string {
	s := ""

	if strings.HasPrefix(aliasName, "Relay:") {
		return s
	}
	if !strings.Contains(aliasName, ":") {
		return s
	}
	parts := strings.Split(aliasName, ":")
	baseIfaceName := parts[0]

	link, err := netlink.LinkByName(baseIfaceName)
	if err != nil {
		log.Error().Msgf("%v %v %v", futils.GetCalleRuntime(), aliasName, err.Error())
		return s
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		log.Error().Msgf("%v %v Could not list addresses for interface %s: %v", futils.GetCalleRuntime(), aliasName, baseIfaceName, err)
		return s
	}
	aliasFound := false
	for _, addr := range addrs {
		if addr.Label == aliasName {
			s = addr.IP.String()
			aliasFound = true
			break
		}
	}
	if !aliasFound {
		log.Error().Msgf("%v Alias %s not found on interface %s", futils.GetCalleRuntime(), aliasName, baseIfaceName)
		return s
	}

	return s

}
func IsInterfaceExists(ifname string) bool {
	if strings.Contains(ifname, ":") {
		IpAddr := getVirtualAliasInfo(ifname)
		if len(IpAddr) > 2 {
			return true
		}
		return false
	}
	if ifname == "" {
		return false
	}
	if len(ifname) < 2 {
		return false
	}
	_, err := net.InterfaceByName(ifname)
	if err != nil {
		return false
	}
	return true
}
func GetVirtualAliasInfo(aliasName string) IfStatus {
	var s IfStatus

	if strings.HasPrefix(aliasName, "Relay:") {
		return s
	}

	if !strings.Contains(aliasName, ":") {
		return s
	}
	parts := strings.Split(aliasName, ":")
	baseIfaceName := parts[0]

	// Get the alias network interface by name
	link, err := netlink.LinkByName(baseIfaceName)
	if err != nil {
		log.Error().Msgf("%v %v %v", futils.GetCalleRuntime(), aliasName, err.Error())
		return s
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		log.Error().Msgf("%v %v Could not list addresses for interface %s: %v", futils.GetCalleRuntime(), aliasName, baseIfaceName, err)
		return s
	}
	aliasFound := false
	for _, addr := range addrs {
		if addr.Label == aliasName {
			s.IpAddr = addr.IP.String()
			aliasFound = true
			break
		}
	}
	if !aliasFound {
		log.Error().Msgf("%v Alias %s not found on interface %s", futils.GetCalleRuntime(), aliasName, baseIfaceName)
		return s
	}
	s.MainIface = baseIfaceName
	s.MacAddr = link.Attrs().HardwareAddr.String()

	s.State = "down"
	if link.Attrs().Flags&net.FlagUp != 0 {
		s.State = "up"
	}

	// Retrieve statistics if available
	stats := link.Attrs().Statistics
	if stats != nil {
		s.TxBytes = stats.TxBytes
		s.RxBytes = stats.RxBytes
		s.Drops = stats.TxDropped + stats.RxDropped
	}
	return s

}
func InterfaceToIPv4(interfaceName string) string {

	if IsIPAddress(interfaceName) && IsLocalIPAddress(interfaceName) {
		return interfaceName
	}

	if interfaceName == "default" {
		return "127.0.0.1"
	}
	if interfaceName == "lo" {
		return "127.0.0.1"
	}
	if interfaceName == "!nil" {
		return "127.0.0.1"
	}
	if len(interfaceName) < 2 {
		return "127.0.0.1"
	}

	if strings.Contains(interfaceName, ":") {
		info := GetVirtualAliasInfo(interfaceName)
		if len(info.IpAddr) > 3 {
			return info.IpAddr
		}
		return "127.0.0.1"
	}

	if !IsInterfaceExists(interfaceName) {

		var TheCall string
		pc, Srcfile, line, ok := runtime.Caller(1)
		if ok {
			file := path.Base(Srcfile)
			fn := runtime.FuncForPC(pc)
			TheCall = fmt.Sprintf("%s[%v:%d]: ", file, fn.Name(), line)
		}

		log.Warn().Msgf("%v => Interface %s not exist, try netlink %v", futils.GetCalleRuntime(), interfaceName, TheCall)
		ifis, err := interfaces(netlink.FAMILY_V4)
		if err != nil {
			log.Warn().Msg(fmt.Sprintf("interfaces(netlink.FAMILY_V4) =>Interface %s not exist err=%s, return 127.0.0.1 line %s", interfaceName, err, futils.GetCalleRuntime()))
			return "127.0.0.1"
		}
		_, ok = ifis[interfaceName]
		if !ok {
			log.Warn().Msgf("%v: ifis[interfaceName] =>Interface %s not exist, return 127.0.0.1", futils.GetCalleRuntime(), interfaceName)
			return "127.0.0.1"
		}
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Warn().Msg(fmt.Sprintf("InterfaceByName() => Interface %s not exist err=%s, try netlink line %s", interfaceName, err, futils.GetCalleRuntime()))
		ifis, err := interfaces(netlink.FAMILY_V4)
		if err != nil {
			log.Warn().Msg(fmt.Sprintf("interfaces(netlink.FAMILY_V4) =>Interface %s not exist err=%s, return 127.0.0.1 line %s", interfaceName, err, futils.GetCalleRuntime()))
			return "127.0.0.1"
		}
		_, ok := ifis[interfaceName]
		if !ok {
			log.Warn().Msg(fmt.Sprintf("ifis[interfaceName] =>Interface %s not exist, return 127.0.0.1 line %s", interfaceName, futils.GetCalleRuntime()))
			return "127.0.0.1"
		}
	}

	addrs, err := iface.Addrs()
	if err != nil {
		log.Info().Msg(fmt.Sprintf("iface.Addrs() => %s try netlink, return 127.0.0.1 line %s", err, futils.GetCalleRuntime()))
		ifis, err := interfaces(netlink.FAMILY_V4)
		if err != nil {
			log.Warn().Msg(fmt.Sprintf("interfaces(netlink.FAMILY_V4) =>Interface %s not exist err=%s, return 127.0.0.1 line %s", interfaceName, err, futils.GetCalleRuntime()))
			return "127.0.0.1"
		}
		ip, ok := ifis[interfaceName]
		if !ok {
			log.Warn().Msg(fmt.Sprintf("ifis[interfaceName] =>Interface %s not exist, return 127.0.0.1 line %s", interfaceName, futils.GetCalleRuntime()))
			return "127.0.0.1"
		} else {
			if net.ParseIP(ip.String()) == nil {
				log.Warn().Msg(fmt.Sprintf("net.ParseIP() =>Invalid IP %s for Interface %s , return 127.0.0.1 line %s", ip, interfaceName, futils.GetCalleRuntime()))
				return "127.0.0.1"
			} else {
				return ip.String()
			}
		}
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			} else {
				return ipNet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
func interfaces(family int) (map[string]net.IP, error) {
	req := nl.NewNetlinkRequest(syscall.RTM_GETADDR, syscall.NLM_F_DUMP)
	msg := nl.NewIfInfomsg(family)
	req.AddData(msg)
	messages, err := req.Execute(syscall.NETLINK_ROUTE, syscall.RTM_NEWADDR)
	if err != nil {
		return nil, err
	}
	ifis := make(map[string]net.IP)
	for _, m := range messages {
		msg := nl.DeserializeIfAddrmsg(m)
		attrs, err := nl.ParseRouteAttr(m[msg.Len():])
		if err != nil {
			return nil, err
		}
		var ip net.IP
		var label string
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.IFA_LOCAL:
				ip = attr.Value
			case syscall.IFA_LABEL:
				label = string(attr.Value[:len(attr.Value)-1])
			}
		}
		if ip != nil && label != "" {
			ifis[label] = ip
		}
	}
	return ifis, nil
}

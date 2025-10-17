package futils

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/idna"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var invalidCharsRegex = regexp.MustCompile(`[<>;/*%\\$@:]`)

type MyHostNameStruct struct {
	Domain      string `json:"Domain"`
	Fqdn        string `json:"Fqdn"`
	NetBiosName string `json:"NetBiosName"`
}

func HostnameInfo() MyHostNameStruct {
	var f MyHostNameStruct
	f.Domain = GetMyDomain()
	f.Fqdn = getFQDN()
	f.NetBiosName = extractNetBIOSName(f.Fqdn)
	return f
}

// getFQDN retrieves the fully qualified hostname
func getFQDN() string {
	hostnameBin := FindProgram("hostname")
	out, err := exec.Command(hostnameBin, "-f").Output()
	if err != nil {
		return ""
	}
	fqdn := strings.TrimSpace(string(out))
	return fqdn
}
func getHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	return hostname, nil
}
func GetMyDomain() string {

	hostname, err := os.Hostname()
	if err != nil {
		log.Debug().Msg(fmt.Sprintf("Get my hostname error %v", err.Error()))
		return "localdomain"
	}

	addrs, err := net.LookupIP(hostname)
	if err != nil || len(addrs) == 0 {
		log.Debug().Msg(fmt.Sprintf("LookupIP(%v) failed", hostname))
		return "localdomain"
	}

	for _, addr := range addrs {
		names, err := net.LookupAddr(addr.String())
		if err != nil || len(names) == 0 {
			log.Debug().Msg(fmt.Sprintf("names:%v failed", names))
			continue
		}
		fqdn := RemoveTrailingDot(names[0])
		log.Debug().Msg(fmt.Sprintf("fqdn:%v/%v", fqdn, hostname))

		if fqdn == hostname {
			NetBiosName := extractNetBIOSName(fqdn)
			domainname := strings.TrimPrefix(fqdn, NetBiosName+".")
			return domainname
		}

		if fqdn != hostname && strings.HasPrefix(fqdn, hostname) {
			domainname := strings.TrimPrefix(fqdn, hostname+".")
			return domainname
		}
	}
	return "localdomain"
}
func extractNetBIOSName(fqdn string) string {
	parts := strings.Split(fqdn, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}
func IsValidDomainRegex(domain string) bool {

	if invalidCharsRegex.MatchString(domain) {
		return false
	}
	return true
}
func IsValidHostname(hostname string) bool {
	// Trim whitespace from the hostname
	hostname = strings.TrimSpace(hostname)

	// List of invalid characters
	invalidChars := []string{
		"(", ")", "[", "]", ";", ",", "?", "$", "%", "é", "è", "à", "@",
		"/", ":", " ", "\\", "*", "+", "=", "°", "&", "'", "\"", "|", "`", "^", "}", "{",
	}
	for _, char := range invalidChars {
		if strings.Contains(hostname, char) {
			return false
		}
	}

	return true
}

func IsValidDomain(domain string) bool {
	domain = strings.ToLower(domain)
	if !IsValidDomainRegex(domain) {
		return false
	}
	bdPatz := []string{
		"localhost", "local", "broadcasthost", "0.0.0.0", "localhost.localdomain",
	}
	for _, line := range bdPatz {
		if line == domain {
			return false
		}
	}

	punycode, err := idna.ToASCII(domain)
	if err != nil {
		return false
	}
	_, err = idna.ToUnicode(punycode)
	if err != nil {
		return false
	}
	return true
}

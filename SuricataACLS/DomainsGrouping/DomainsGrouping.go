package DomainsGrouping

import (
	"fmt"
	"futils"
	"strings"
)

const DataSetDir = "/etc/suricata/dataset/domains"

func Build(ruleid int, Main []string) string {
	var Postive []string
	var Negative []string
	NegativeFile := ""
	for _, domain := range Main {
		if strings.HasPrefix(domain, "!") {
			domain = strings.TrimSpace(domain[1:])
			Negative = append(Negative, futils.Base64Encode(domain))
			continue
		}
		Postive = append(Postive, futils.Base64Encode(domain))
	}

	if len(Postive) == 0 {
		return ""
	}

	futils.CreateDir(DataSetDir)
	PositiveFile := fmt.Sprintf("%v/%d.positive.lst", DataSetDir, ruleid)

	_ = futils.FilePutContents(PositiveFile, strings.Join(Postive, "\n"))
	if len(Negative) > 0 {
		NegativeFile = fmt.Sprintf("%v/%d.negative.lst", DataSetDir, ruleid)
		_ = futils.FilePutContents(NegativeFile, strings.Join(Negative, "\n"))
	}
	return fmt.Sprintf("%s|%s", PositiveFile, NegativeFile)
}
func AcceptedDomains() map[string]string {
	zDomains := make(map[string]string)
	zDomains["dns"] = "dns.query"
	zDomains["tls"] = "tls.sni"
	zDomains["http"] = "http.host"
	zDomains["smtp"] = "smtp.helo"
	//zDomains["smtp"] = "smtp.mail"
	//zDomains["smtp"] = "smtp.rcpt"
	zDomains["mdns"] = "mdns.answers.rrname"
	zDomains["websocket"] = "http.host"
	zDomains["http2"] = "http.host"
	zDomains["quic"] = "quic.sni"
	zDomains["sip"] = "sip.uri"
	zDomains["doh"] = "http.host"
	zDomains["doh2"] = "http2.header"
	zDomains["smb"] = "smb.ntlmssp_domain"
	zDomains["krb5"] = "krb5_cname"
	return zDomains
}
func GetAcls(proto string, pattern string) string {
	ADomains := AcceptedDomains()
	var f []string
	f = append(f, ADomains[proto]+";")
	f = append(f, "domain;")

	tbFiles := strings.Split(pattern, "|")
	if len(tbFiles[0]) > 3 {
		f = append(f, fmt.Sprintf("dataset:isset,include_domains,type string,load %v", tbFiles[0]))
	}
	if len(tbFiles[1]) > 3 {
		f = append(f, fmt.Sprintf("!dataset:isset,exclude_domains,type string,load %v ", tbFiles[1]))
	}
	return strings.TrimSpace(strings.Join(f, " "))
}
func BuiliTypes(itypes []string) string {

	var negFirst []string
	var posFirst []string
	var finalRule []string

	for _, ztype := range itypes {
		if strings.HasPrefix(ztype, "!") {
			negFirst = append(negFirst, fmt.Sprintf("itype:%v;", ztype))
			continue
		}
		posFirst = append(posFirst, fmt.Sprintf("itype:%v;", ztype))
	}
	if len(negFirst) > 0 {
		for _, ztype := range negFirst {
			finalRule = append(finalRule, ztype)
		}
	}
	if len(posFirst) > 0 {
		for _, ztype := range posFirst {
			finalRule = append(finalRule, ztype)
		}
	}
	return strings.Join(finalRule, " ")
}

func BuildGeoIP(Countries []string, GroupType string) string {
	// find negation first, if there is entries in negation then all will be negated
	Negation := false

	ttype := make(map[string]string)
	ttype["geoipsrc"] = "src"
	ttype["geoipdest"] = "dst"
	Dir := ttype[GroupType]
	negChar := ""
	AllCountries := make(map[string]bool)
	for _, country := range Countries {
		if strings.HasPrefix(country, "!") {
			country = strings.TrimSpace(country[1:])
			AllCountries[country] = true
			Negation = true
			continue
		}
		AllCountries[country] = true
	}
	var ff []string
	for ctry, _ := range AllCountries {
		ff = append(ff, ctry)
	}
	if Negation {
		negChar = "!"
	}
	finalRule := fmt.Sprintf("%s geoip %s %s", negChar, Dir, strings.Join(ff, ","))
	finalRule = strings.TrimSpace(finalRule)
	finalRule = strings.ReplaceAll(finalRule, ",,", ",")
	return finalRule

}

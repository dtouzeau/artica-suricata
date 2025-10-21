package IPSetClass

import (
	"errors"
	"fmt"
	"futils"
	"github.com/lrh3321/ipset-go"
	"github.com/rs/zerolog/log"
	"net"
	"strings"
)

func CreateIPSet(IpSetName string, items []string) error {

	if !IpSetExists(IpSetName) {
		err := ipset.Create(
			IpSetName,
			ipset.TypeHashNet,
			ipset.CreateOptions{
				Replace: true,
				Timeout: 0,
				Size:    5000000,
			},
		)
		if err != nil {
			log.Error().Msgf("%v Error Creating IPSet(%v) %s", futils.GetCalleRuntime(), IpSetName, err.Error())
			return err
		}

	} else {
		err := ipset.Flush(IpSetName)
		if err != nil {
			log.Error().Msgf("%v Error Flushing IPSet %s %v", futils.GetCalleRuntime(), IpSetName, err.Error())
			return err
		}
	}
	for _, cidr := range items {
		if !strings.Contains(cidr, "/") {
			cidr = cidr + "/32"
		}

		cidrip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Error().Msgf("%v Invalid CIDR: %v", futils.GetCalleRuntime(), err)
		}
		cidrSize, _ := ipnet.Mask.Size()
		entry := &ipset.Entry{
			IP:   cidrip,
			CIDR: uint8(cidrSize),
		}

		// Add Entry
		if err := ipset.Add(IpSetName, entry); err != nil {
			log.Error().Msgf("%v Failed to add entry (%v): %v", futils.GetCalleRuntime(), cidr, err)
		}

	}
	return nil
}

func IpSetAdd(ipsetname string, Ipaddr string) error {
	if isIPv6(Ipaddr) {
		return nil
	}
	if len(ipsetname) < 3 {
		return errors.New("IPSet name corrupted or not defined")
	}
	zip := net.ParseIP(Ipaddr).To4()
	err := ipset.Add(ipsetname, &ipset.Entry{IP: zip})
	if err != nil {

		if strings.Contains(err.Error(), "errno 4352") {
			return fmt.Errorf("IPSet cannot add additional elements ( hash is full)")
		}
		return err
	}
	return nil

}
func isIPv6(IPstr string) bool {
	ip := net.ParseIP(IPstr)
	if ip == nil {
		return false
	}
	if ip.To4() == nil {
		return true
	}
	return false
}

func RemoveIPSet(IpSetName string) error {
	err := ipset.Destroy(IpSetName)
	if err != nil {
		return err
	}
	return nil
}
func IpSetExists(IpSetName string) bool {

	Sets, _ := ipset.ListAll()
	for _, zset := range Sets {
		if strings.ToLower(strings.TrimSpace(zset.SetName)) == strings.ToLower(strings.TrimSpace(IpSetName)) {
			return true
		}

	}
	return false

}

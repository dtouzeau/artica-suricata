package afirewall

import (
	"errors"
	"fmt"
	"futils"
	"net"
	"strings"

	"github.com/lrh3321/ipset-go"
)

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
		return fmt.Errorf("%v %v->%v %v", futils.GetCalleRuntime(), ipsetname, Ipaddr, err)
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

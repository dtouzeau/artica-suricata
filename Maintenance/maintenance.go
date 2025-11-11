package Maintenance

import (
	"CacheMem"
	"context"
	"fmt"
	"futils"
	"regexp"
	"strings"
	"suricata"
	"suricata/SuricataTools"
	"surisock"
	"time"

	"github.com/rs/zerolog/log"
)

var RegexVersion = regexp.MustCompile(`^([0-9]+)\.([0-9]+)`)

func CheckSuricataSocket() bool {
	zctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	Pid := SuricataTools.GetPID()
	if !futils.ProcessExists(Pid) {
		log.Error().Msgf("%v Suricata not running -> Start it", futils.GetCalleRuntime())
		_ = suricata.Start()
		return false
	}
	log.Debug().Msgf("%v Suricata is running PID:%d", futils.GetCalleRuntime(), Pid)

	_, err := surisock.Version(zctx)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			log.Error().Msgf("%v %v -> RELOAD", futils.GetCalleRuntime(), err.Error())
			suricata.Reload()
			return false
		}

		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return false
	}

	return true

}
func GetVersion() string {

	MainBinary := futils.FindProgram("suricata")

	cmdline := fmt.Sprintf("%v -V", MainBinary)
	log.Debug().Msgf("%v %v", futils.GetCalleRuntime(), cmdline)
	err, out := futils.ExecuteShell(fmt.Sprintf("%v -V", MainBinary))

	if err != nil {
		tb := strings.Split(out, "\n")
		for _, line := range tb {
			if strings.Contains(line, "loading shared libraries: libpcap") {
				if !futils.FileExists("/etc/ld.so.conf.d/local.lib.conf") {
					_ = futils.FilePutContents("/etc/ld.so.conf.d/local.lib.conf", "/usr/local/lib\n")
				}
				_ = futils.RunLdconfig("")
			}

			log.Error().Msgf("%v [%v]", futils.GetCalleRuntime(), line)
		}

		log.Error().Msgf("%v %v [%v]", futils.GetCalleRuntime(), err.Error(), out)
	}

	tb := strings.Split(out, "\n")
	for _, v := range tb {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		ver := futils.RegexGroup1(RegexVersion, v)
		if len(ver) > 1 {
			CacheMem.SetStringFunc(ver)
			return ver
		}
		log.Debug().Msgf("%v %v no matches", futils.GetCalleRuntime(), v)

	}
	return "0.0.0"
}

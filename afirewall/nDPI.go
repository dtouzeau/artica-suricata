package afirewall

import (
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"regexp"
	"sockets"
	"strings"
)

var RexexModInfo = regexp.MustCompile(`Error.*?missing`)

func checkNDPI() {
	EnablenDPI := sockets.GET_INFO_INT("EnablenDPI")
	if EnablenDPI == 0 {
		return
	}
	xt_ndpi := fmt.Sprintf("/lib/modules/%v/extra/xt_ndpi.ko", futils.KernelVersion())
	log.Debug().Msgf("%v Kernel version %v [%v]", futils.GetCalleRuntime(), futils.KernelVersion(), xt_ndpi)
	if !futils.FileExists(xt_ndpi) {
		return
	}
	modinfo := futils.FindProgram("modinfo")
	err, out := futils.ExecuteShell(fmt.Sprintf("%v xt_ndpi", modinfo))
	if err != nil {
		log.Error().Msgf("%v %v %v", futils.GetCalleRuntime(), modinfo, out)
	}
	tb := strings.Split(out, "\n")
	for _, line := range tb {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "description:") {
			return
		}

		if futils.RegexFind(RexexModInfo, line) {
			err := futils.RunDepmod()
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			}
		}

	}
}

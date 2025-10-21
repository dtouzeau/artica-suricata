package aBridges

import (
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"os/exec"
	"regexp"
	"strings"
)

func RemoveAll() {
	brctl := futils.FindProgram("brctl")
	ipBin := futils.FindProgram("ip")
	cmd := exec.Command(brctl, "show")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Msgf("%v Error executing command: /sbin/brctl show [%v]", futils.GetCalleRuntime(), output)
		return
	}
	lines := strings.Split(string(output), "\n")
	re := regexp.MustCompile(`^br([0-9]+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if matches := re.FindStringSubmatch(line); matches != nil {
			bridge := fmt.Sprintf("br%s", matches[1])
			log.Warn().Msgf("%v Remove bridge %s", futils.GetCalleRuntime(), bridge)

			err := exec.Command(ipBin, "link", "set", bridge, "down").Run()

			if err != nil {
				log.Error().Msgf("%v Error executing command: ip link set %v down [%v]", futils.GetCalleRuntime(), bridge, output)
				return
			}

			// Delete the bridge
			err = exec.Command(brctl, "delbr", bridge).Run()
			if err != nil {
				log.Error().Msgf("%v Error executing command: brctl del %v [%v]", futils.GetCalleRuntime(), bridge, output)
				return
			}
		}
	}

}

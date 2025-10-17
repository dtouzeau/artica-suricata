package notifs

import (
	"futils"
	"github.com/coreos/go-systemd/v22/journal"
	"github.com/rs/zerolog/log"
	"strings"
)

func TosystemDStopping(text string, serviceName string, function string) {

	err := journal.Send(text,
		journal.PriWarning,
		map[string]string{"APP_NAME": serviceName, "SERVICE": function, "EVENT_TYPE": "Finish", "STATUS": "STOPPING"})
	if err != nil {
		log.Error().Msgf("%v Failed to send log to journald: %v", futils.GetCalleRuntime(), err)
	}

}

func TosystemDStartUP(text string, serviceName string, function string) {
	if !journal.Enabled() {
		log.Debug().Msgf("%v Systemd journald is not available", futils.GetCalleRuntime())
		return
	}

	if strings.Contains("ERROR", text) {
		err := journal.Send(text,
			journal.PriErr, // Priority level
			map[string]string{
				"APP_NAME":   serviceName,
				"VERSION":    "",
				"SERVICE":    function,
				"EVENT_TYPE": "Startup",
			})
		if err != nil {
			log.Error().Msgf("%v Failed to send log to journald: %v", futils.GetCalleRuntime(), err)
		}
		return
	}
	err := journal.Send(text,
		journal.PriInfo, // Priority level
		map[string]string{
			"APP_NAME":   serviceName,
			"VERSION":    "",
			"SERVICE":    function,
			"EVENT_TYPE": "Startup",
		})
	if err != nil {
		log.Error().Msgf("%v Failed to send log to journald: %v", futils.GetCalleRuntime(), err)
	}

}

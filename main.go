package main

import (
	"flag"
	"fmt"
	"futils"
	"github.com/robfig/cron/v3"
	"github.com/rs/zerolog/log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"
)

const PanicFile = "/etc/artica-postfix/artica-suricata.panic"
const PidFile = "/run/artica-suricata.pid"

var MainCron *cron.Cron
var GoInDebug = flag.Bool("debug", false, "Run Debug mode")
var Getversion = flag.Bool("version", false, "Get version")

func main() {

	var rLimit syscall.Rlimit
	defer func() {
		if r := recover(); r != nil {
			_ = os.WriteFile(PanicFile, debug.Stack(), 0755)
			println(fmt.Sprintf("Panic: %v,\n%s", r, debug.Stack()))
			os.Exit(1)
		}
	}()

	flag.Parse()
	if *Getversion {
		fmt.Println("Version:", version)
		os.Exit(0)
	}
	_, err := time.LoadLocation(futils.GetTimeZone())
	if err != nil {
		log.Error().Msgf("[START]: Load timezone failed: %v", err)
	}
	initZerolog()

	OldPid := futils.GetPIDFromFile(PidFile)
	if futils.ProcessExists(OldPid) {
		fmt.Println("An already process exists:", OldPid, futils.ProcessCommandLine(OldPid))
		os.Exit(0)
	}

	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Error().Msgf("%v Error Getting Rlimit %s", futils.GetCalleRuntime(), err)
	}
	//fmt.Println(rLimit)
	rLimit.Max = 200000
	rLimit.Cur = 200000
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v Error Setting Rlimit %s", futils.GetCalleRuntime(), err))
	}
	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v Error Getting Rlimit %s", futils.GetCalleRuntime(), err))
	}

	MainCron = cron.New()
	_, _ = MainCron.AddFunc("*/5 * * * *", Each5Minutes)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGTERM)
	usr1Chan := make(chan os.Signal, 1)
	usr2Chan := make(chan os.Signal, 1)
	hupChan := make(chan os.Signal, 1)
	KillChan := make(chan os.Signal, 1)
	signal.Notify(usr1Chan, syscall.SIGUSR1)
	signal.Notify(usr2Chan, syscall.SIGUSR2)
	signal.Notify(hupChan, syscall.SIGHUP)
	signal.Notify(KillChan, syscall.SIGTERM)

	for {

		select {

		case <-time.After(time.Second * 10):

		case <-KillChan:
			log.Warn().Msgf("[STOP]: %v Received KILL signal Terminate process", futils.GetCalleRuntime())
			log.Warn().Msgf("%v Dump Database...", futils.GetCalleRuntime())

			MainCron.Stop()
			log.Warn().Msgf("%v Dump memory...", futils.GetCalleRuntime())
			log.Warn().Msgf("%v Cleaning...", futils.GetCalleRuntime())
			log.Warn().Msgf("%v Saving cache memory...", futils.GetCalleRuntime())
			os.Exit(0)

		case <-usr1Chan:
			log.Info().Msg(fmt.Sprintf("Received USR1 signal."))

		case <-usr2Chan:
			log.Info().Msg(fmt.Sprintf("Received USR2 signal."))

		case <-hupChan:
			log.Info().Msgf("%v Received HUP signal, reloading configuration...", futils.GetCalleRuntime())
			initZerolog()
			MainCron.Stop()
			MainCron.Start()

		}

	}
}

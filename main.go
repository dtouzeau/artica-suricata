package main

import (
	"LogForward"
	"RESTApi"
	"SuriConf"
	"SuriStructs"
	"SuriTables"
	"flag"
	"fmt"
	"futils"
	"os"
	"os/signal"
	"runtime/debug"
	"sockets"
	"suricata"
	"surirules"
	"syscall"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/rs/zerolog/log"
)

const PanicFile = "/etc/artica-postfix/artica-suricata.panic"
const PidFile = "/run/artica-suricata.pid"

var MainCron *cron.Cron
var GoInDebug = flag.Bool("debug", false, "Run Debug mode")
var Getversion = flag.Bool("version", false, "Get version")
var cmdstopsuricata = flag.Bool("stop-ids", false, "Stop the IDS service")
var cmdstartsuricata = flag.Bool("start-ids", false, "Start the IDS service")
var cmdrestartsuricata = flag.Bool("restart-ids", false, "Restart the IDS service")
var cmdreconfiguresuricata = flag.Bool("reconfigure-ids", false, "Reconfigure the IDS service")
var cmdinstallsuricata = flag.Bool("install-ids", false, "Install the IDS service")
var cmduninstallsuricata = flag.Bool("uninstall-ids", false, "Uninstall the IDS service")
var cmdstatussuricata = flag.Bool("status-ids", false, "Status of the IDS service")
var cmdFixDuplicatesssuricata = flag.Bool("duplicates-ids", false, "Fix duplicate rules in IDS")
var cmdPFRing = flag.Bool("pf-ring", false, "Verify PF RING Configration for IDS")
var CMDSuricataLUpdate = flag.Bool("updates", false, "Updates Suricata - scheduled")
var CMDSuricataUpdates = flag.Bool("suricata-updates", false, "Updates Suricata")
var CMDSuricataSock = flag.String("suricata-sock", "", "Send command to suricata socket")
var CMDParseRules = flag.Bool("suricata-rules", false, "Parse rules from directory and inject them into database")
var CMDOtx = flag.Bool("otx", false, "Get rules from OTX")
var CMDCleanQueue = flag.Bool("clean-queue", false, "Destroy PostgreSQL queue failed")
var CMDClassify = flag.Bool("classify", false, "Build json classification file")
var CMDRules = flag.Bool("rules", false, "Get rules infos")
var CMDPostgreSQL = flag.Bool("postgres", false, "PostgreSQL maintenance")
var CMDAclsExplains = flag.Bool("acls-explains", false, "Fill explain text for acls")
var CMDChecksocket = flag.Bool("check-socket", false, "Check the listening socket")
var CMDSynCats = flag.Bool("sync-categories", false, "Synchronize enabled and available categories")

func main() {

	var rLimit syscall.Rlimit
	defer func() {
		if r := recover(); r != nil {
			_ = os.WriteFile(PanicFile, debug.Stack(), 0755)
			println(fmt.Sprintf("Panic: %v,\n%s", r, debug.Stack()))
			os.Exit(1)
		}
	}()
	sockets.UseMemCacheClient = futils.StrToInt64(futils.FileGetContents("/etc/artica-postfix/settings/Daemons/UseMemCacheClient"))
	flag.Parse()
	if *Getversion {
		fmt.Println("Version:", version)
		_ = suricata.GetVersion()
		os.Exit(0)
	}

	_, err := time.LoadLocation(futils.GetTimeZone())
	if err != nil {
		log.Error().Msgf("[START]: Load timezone failed: %v", err)
	}
	initZerolog()
	ParseCmdLines()

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
	go func() {
		_ = suricata.GetVersion()
		suricata.LoadClassifications(false)
	}()
	log.Info().Msgf("%v Starting version [%v]", futils.GetCalleRuntime(), version)
	df := SuriStructs.LoadConfig()
	df.Version = version
	SuriStructs.SaveConfig(df)

	MainCron = cron.New()
	go LogForward.Start()
	go RESTApi.Start()
	go suricata.CheckStartup()
	go SuriTables.Check()
	go surirules.CheckRulesCounter()
	go SuriConf.PatchTables()
	_, _ = MainCron.AddFunc("* * * * *", EachMinutes)
	_, _ = MainCron.AddFunc("*/2 * * * *", Each2Minutes)
	_, _ = MainCron.AddFunc("*/5 * * * *", Each5Minutes)
	_, _ = MainCron.AddFunc("*/15 * * * *", Each15Minutes)
	_, _ = MainCron.AddFunc("*/10 * * * *", Each10Minutes)
	_, _ = MainCron.AddFunc("*/30 * * * *", Each30Minutes)
	_, err = MainCron.AddFunc("0 */12 * * *", Each12Hours)
	SquidRotateOnlySchedule := sockets.GET_INFO_INT("SquidRotateOnlySchedule")
	if SquidRotateOnlySchedule == 1 {
		LogRotateH := sockets.GET_INFO_STR("LogRotateH")
		LogRotateM := sockets.GET_INFO_STR("LogRotateM")
		zpattern := fmt.Sprintf("%d %d * * *", futils.StrToInt(LogRotateM), futils.StrToInt(LogRotateH))
		_, err = MainCron.AddFunc(zpattern, EachRotation)
		if err != nil {
			log.Err(err).Msg(fmt.Sprintf("Unable to create cron tasks for EachRotation (%v) %v", zpattern, err.Error()))
		}
	}
	MainCron.Start()

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
			futils.Chmod("/run/suricata-service.sock", 0777)

		case <-KillChan:
			log.Warn().Msgf("[STOP]: %v Received KILL signal Terminate process", futils.GetCalleRuntime())
			log.Warn().Msgf("%v Dump Database...", futils.GetCalleRuntime())
			RESTApi.Stop()
			MainCron.Stop()
			log.Warn().Msgf("%v Dump memory...", futils.GetCalleRuntime())
			log.Warn().Msgf("%v Cleaning...", futils.GetCalleRuntime())
			log.Warn().Msgf("%v Saving cache memory...", futils.GetCalleRuntime())
			os.Exit(0)

		case <-usr1Chan:
			log.Info().Msg(fmt.Sprintf("Received USR1 signal."))
			df := SuriStructs.LoadConfig()
			df.Version = version
			SuriStructs.SaveConfig(df)
			SuriConf.PatchTables()
			go surirules.CheckRulesCounter()

		case <-usr2Chan:
			log.Info().Msg(fmt.Sprintf("Received USR2 signal."))

		case <-hupChan:
			log.Info().Msgf("%v Received HUP signal, reloading configuration...", futils.GetCalleRuntime())
			initZerolog()
			MainCron.Stop()
			MainCron.Start()
			SuriTables.Check()
			go surirules.CheckRulesCounter()
			_ = suricata.GetVersion()

		}

	}
}

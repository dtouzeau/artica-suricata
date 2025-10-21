package logsink

import (
	"database/sql"
	"fmt"
	"futils"
	"ipclass"
	"sockets"
	"strings"

	"github.com/rs/zerolog/log"
)

type SSlConfSyslog struct {
	Expose_contentkey   []string
	Expose_contentert   []string
	Expose_contentca    []string
	Events              []string
	RECALL_SSL          map[string]map[string]bool
	RsyslogCertificates map[string]string
}

func Journald() {

	if !futils.FileExists("/etc/systemd/journald.conf") {
		return
	}
	SystemLogRateLimitInterval := sockets.GET_INFO_INT("SystemLogRateLimitInterval")
	SystemLogRateLimitBurst := sockets.GET_INFO_INT("SystemLogRateLimitBurst")

	if SystemLogRateLimitInterval == 0 {
		SystemLogRateLimitInterval = 5
	}
	if SystemLogRateLimitBurst == 0 {
		SystemLogRateLimitBurst = 50000
	}
	md51 := futils.MD5File("/etc/systemd/journald.conf")
	var f []string
	f = append(f, "[Journal]")
	f = append(f, "#Storage=auto")
	f = append(f, "#Compress=yes")
	f = append(f, "#Seal=yes")
	f = append(f, "#SplitMode=uid")
	f = append(f, "#SyncIntervalSec=5m")
	f = append(f, fmt.Sprintf("RateLimitIntervalSec=%ds", SystemLogRateLimitInterval))
	f = append(f, fmt.Sprintf("RateLimitBurst=%d", SystemLogRateLimitBurst))
	f = append(f, "#SystemMaxUse=")
	f = append(f, "#SystemKeepFree=")
	f = append(f, "#SystemMaxFileSize=")
	f = append(f, "#SystemMaxFiles=100")
	f = append(f, "#RuntimeMaxUse=")
	f = append(f, "#RuntimeKeepFree=")
	f = append(f, "#RuntimeMaxFileSize=")
	f = append(f, "#RuntimeMaxFiles=100")
	f = append(f, "#MaxRetentionSec=")
	f = append(f, "#MaxFileSec=1month")
	f = append(f, "#ForwardToSyslog=yes")
	f = append(f, "#ForwardToKMsg=no")
	f = append(f, "#ForwardToConsole=no")
	f = append(f, "#ForwardToWall=yes")
	f = append(f, "#TTYPath=/dev/console")
	f = append(f, "#MaxLevelStore=debug")
	f = append(f, "#MaxLevelSyslog=debug")
	f = append(f, "#MaxLevelKMsg=notice")
	f = append(f, "#MaxLevelConsole=info")
	f = append(f, "#MaxLevelWall=emerg")
	f = append(f, "#LineMax=48K")
	f = append(f, "#ReadKMsg=yes")
	f = append(f, "#Audit=no")
	f = append(f, "#\n\n")
	_ = futils.FilePutContents("/etc/systemd/journald.conf", strings.Join(f, "\n"))
	md52 := futils.MD5File("/etc/systemd/journald.conf")
	if md51 == md52 {
		return
	}
	systemctl := futils.FindProgram("systemctl")
	if !futils.FileExists(systemctl) {
		return
	}
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v restart systemd-journald", systemctl))

}

func BuildRsyslogConf() bool {

	rsyslogd_version := GetVersion()
	imudp := "#"
	imtcp := "#"
	impstats := 0
	Journald()

	SystemLogRateLimitInterval := sockets.GET_INFO_INT("SystemLogRateLimitInterval")
	SystemLogRateLimitBurst := sockets.GET_INFO_INT("SystemLogRateLimitBurst")
	ActAsASyslogServer := sockets.GET_INFO_INT("ActAsASyslogServer")

	if SystemLogRateLimitInterval == 0 {
		SystemLogRateLimitInterval = 5
	}
	if SystemLogRateLimitBurst == 0 {
		SystemLogRateLimitBurst = 50000
	}
	LegallogServer := sockets.GET_INFO_INT("LegallogServer")
	RsyslogInterface := sockets.GET_INFO_STR("RsyslogInterface")

	RsyslogPort := sockets.GET_INFO_INT("RsyslogPort")
	RsyslogProtoTCP := sockets.GET_INFO_INT("RsyslogProtoTCP")
	RsyslogTCPPort := sockets.GET_INFO_INT("RsyslogTCPPort")
	RsyslogDisableProtoUDP := sockets.GET_INFO_INT("RsyslogDisableProtoUDP")
	RsyslogTCPUseSSL := sockets.GET_INFO_INT("RsyslogTCPUseSSL")
	RsyslogTCPCertificateName := sockets.GET_INFO_STR("RsyslogTCPCertificateName")
	EnableDockerService := sockets.GET_INFO_INT("EnableDockerService")
	Enablehacluster := sockets.GET_INFO_INT("Enablehacluster")
	EnableSyslogLogSink := sockets.GET_INFO_INT("EnableSyslogLogSink")
	if EnableSyslogLogSink == 1 {
		ActAsASyslogServer = 1
	}
	var f []string
	if Enablehacluster == 1 {
		imudp = ""
	}
	if EnableDockerService == 1 {
		imudp = ""
	}

	if RsyslogTCPPort == 0 {
		RsyslogTCPPort = 5514
	}
	if RsyslogPort == 0 {
		RsyslogPort = 514
	}

	if ActAsASyslogServer == 1 {
		if RsyslogDisableProtoUDP == 0 {
			imudp = ""
			if RsyslogProtoTCP == 1 {
				imtcp = ""
			}
		}
	}
	if LegallogServer == 1 {
		imtcp = ""
		imudp = ""
	}
	if futils.FileExists("/usr/lib/x86_64-linux-gnu/rsyslog/impstats.so") {
		f = append(f, "# impstats.so [OK]")
		impstats = 1
	} else {
		f = append(f, "# impstats.so missing !!!")
		impstats = 0
	}
	if !futils.FileExists("/usr/lib/x86_64-linux-gnu/rsyslog/lmnsd_ossl.so") {
		f = append(f, "# lmnsd_ossl.so missing !!!")
		RsyslogTCPUseSSL = 0
	} else {
		f = append(f, "# lmnsd_ossl.so [OK]")
	}
	f = append(f, fmt.Sprintf("#  /etc/rsyslog.conf Configuration file for rsyslog v%v", rsyslogd_version))
	f = append(f, "#")
	f = append(f, "#        Written by Artica")
	f = append(f, "#        For more information see")
	f = append(f, "#        /usr/share/doc/rsyslog-doc/html/rsyslog_conf.html")
	f = append(f, "")
	f = append(f, "")
	f = append(f, "#################")
	f = append(f, "#### MODULES ####")
	f = append(f, "#################")
	f = append(f, "")

	Exposed := SSLExposed()
	if len(Exposed.Expose_contentca) > 0 {
		_ = futils.FilePutContents("/etc/rsyslog.d/ca.pem", strings.Join(Exposed.Expose_contentca, "\n"))
		_ = futils.FilePutContents("/etc/rsyslog.d/server_key.pem", strings.Join(Exposed.Expose_contentkey, "\n"))
		_ = futils.FilePutContents("/etc/rsyslog.d/server_cert.pem", strings.Join(Exposed.Expose_contentert, "\n"))

		RsyslogTCPUseSSL = 1
	}

	if RsyslogTCPUseSSL == 1 {
		f = append(f, "#\t * * * Provides TLS support * * *")
		f = append(f, "$DefaultNetstreamDriver ossl")
		f = append(f, "$DefaultNetstreamDriverCAFile /etc/rsyslog.d/ca.pem")
		f = append(f, "$DefaultNetstreamDriverCertFile /etc/rsyslog.d/server_cert.pem")
		f = append(f, "$DefaultNetstreamDriverKeyFile /etc/rsyslog.d/server_key.pem")
		f = append(f, "$ActionSendStreamDriverPermittedPeer *")
		f = append(f, "")
	}
	f = append(f, fmt.Sprintf("module(load=\"imuxsock\" SysSock.RateLimit.Interval=\"%d\" SysSock.RateLimit.Burst=\"%d\")", SystemLogRateLimitInterval, SystemLogRateLimitBurst))
	//f = append(f, "$ModLoad imuxsock # provides support for local system logging")
	f = append(f, "$ModLoad imklog   # provides kernel logging support (previously done by rklogd)")
	f = append(f, "$ModLoad imfile   # Provide a kind of tail of log files...")
	//f = append(f, fmt.Sprintf("$imjournalRatelimitBurst %d", SystemLogRateLimitInterval))
	f = append(f, "#\t$ModLoad immark  # provides --MARK-- message capability")
	f = append(f, fmt.Sprintf("#\timpstats: %d", impstats))

	if impstats == 1 {
		f = append(f, "module(")
		f = append(f, "\tload=\"impstats\"")
		f = append(f, "\tinterval=\"10\"")
		f = append(f, "\tresetCounters=\"off\"")
		f = append(f, "\tlog.file=\"/var/log/syslog.stats\"")
		f = append(f, "\tlog.syslog=\"off\"")
		f = append(f, ")")
	}
	f = append(f, "$MaxMessageSize 32k")
	f = append(f, "")
	f = append(f, "#\t-----------------------------------------------------------------------")
	f = append(f, "#\tProvides UDP syslog reception")
	f = append(f, fmt.Sprintf("%v$ModLoad imudp", imudp))
	if len(RsyslogInterface) > 2 {
		f = append(f, fmt.Sprintf("%v%v %v", imudp, "$UDPServerAddress", ipclass.InterfaceToIPv4(RsyslogInterface)))
	}
	f = append(f, fmt.Sprintf("%v$UDPServerRun %d", imudp, RsyslogPort))

	f = append(f, "")
	f = append(f, "#\tProvides TCP syslog reception")
	f = append(f, fmt.Sprintf("%v$ModLoad imtcp", imtcp))
	if len(RsyslogInterface) > 2 {
		f = append(f, fmt.Sprintf("%v%v %v", imtcp, "$InputTCPServerAddress", ipclass.InterfaceToIPv4(RsyslogInterface)))
	}
	f = append(f, fmt.Sprintf("%v$InputTCPServerRun %d", imtcp, RsyslogTCPPort))
	f = append(f, "#\t-----------------------------------------------------------------------")
	if RsyslogTCPUseSSL == 1 {
		f = append(f, "$InputTCPServerStreamDriverMode 1")
		f = append(f, "$InputTCPServerStreamDriverAuthMode anon")
	}

	//f = append(f, "$IncludeConfig /etc/LegalLogs.conf")
	f = append(f, "")
	futils.CreateDir("/run/hacluster/dev")
	futils.CreateDir("/run/PulseReverse/dev")
	f = append(f, "$AddUnixListenSocket /dev/log")
	f = append(f, "$AddUnixListenSocket /run/hacluster/dev/log")
	f = append(f, "$AddUnixListenSocket /run/PulseReverse/dev/log")
	f = append(f, "$WorkDirectory /var/spool/rsyslog # where to place spool files")
	f = append(f, "$ActionQueueFileName uniqName # unique name prefix for spool files")
	f = append(f, "$ActionQueueMaxDiskSpace 1g   # 1gb space limit (use as much as possible)")
	f = append(f, "$ActionQueueSaveOnShutdown on # save messages to disk on shutdown")
	f = append(f, "$ActionQueueType LinkedList   # run asynchronously")
	f = append(f, "$ActionResumeRetryCount -1    # infinite retries if host is down")
	f = append(f, "$ActionQueueSize 10000         # 10,000 messages")
	f = append(f, "$ActionQueueHighWaterMark 8000 # 80% of size")
	f = append(f, "$ActionQueueLowWaterMark 2000  # 20% of size")

	f = append(f, "$MainMsgQueueType LinkedList")
	f = append(f, "$MainMsgQueueDequeueBatchSize 100")
	f = append(f, "$MainMsgQueueCheckpointInterval 10")
	f = append(f, "$MainMsgQueueFileName mainmsg_queue")
	f = append(f, "$MainMsgQueueMaxDiskSpace 1g")
	f = append(f, "$MainMsgQueueSaveOnShutdown on")
	f = append(f, "$MainMsgQueueSize 10000         # 10,000 messages")
	f = append(f, "$MainMsgQueueHighWaterMark 8000 # 80% of size")
	f = append(f, "$MainMsgQueueLowWaterMark 2000  # 20% of size")
	f = append(f, "$MainMsgQueueDiscardMark 9000  # 90% of size")
	f = append(f, "")
	f = append(f, fmt.Sprintf("#\tTCP enabled      = %d", RsyslogProtoTCP))
	f = append(f, fmt.Sprintf("#\tSSL enabled      = %d", RsyslogTCPUseSSL))
	f = append(f, fmt.Sprintf("#\tCertificate name = %v", RsyslogTCPCertificateName))
	futils.DeleteFile("/etc/rsyslog.d/send-all.conf")
	f = append(f, "")
	f = append(f, "###########################")
	f = append(f, "#### GLOBAL DIRECTIVES ####")
	f = append(f, "###########################")
	f = append(f, "")
	f = append(f, "#")
	f = append(f, "# Use traditional timestamp format.")
	f = append(f, "# To enable high precision timestamps, comment out the following line.")
	f = append(f, "#")
	f = append(f, "$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat")
	f = append(f, "")
	f = append(f, "#")
	f = append(f, "# Set the default permissions for all log files.")
	f = append(f, "#")
	f = append(f, "$FileOwner root")
	f = append(f, "$FileGroup adm")
	f = append(f, "$FileCreateMode 0640")
	f = append(f, "$DirCreateMode 0755")
	f = append(f, "$Umask 0022")
	f = append(f, "$MaxOpenFiles 2048")
	f = append(f, "module(load=\"omuxsock\")")
	f = append(f, "#")
	f = append(f, LogSynkConfig())
	f = append(f, "#\tGlobally, send all events if \"all\" as been set in rules..")
	add_all := BuildRemoteSyslogs("all", "global")
	if len(add_all) > 3 {
		f = append(f, add_all)
	} else {
		f = append(f, "#\tNothing in rules...")
	}
	f = append(f, "#")
	f = append(f, "#\tInclude all config files in /etc/rsyslog.d/")
	f = append(f, "$IncludeConfig /etc/rsyslog.d/*.conf")
	f = append(f, "")
	f = append(f, "")
	f = append(f, "###############")
	f = append(f, "#### RULES ####")
	f = append(f, "###############")
	f = append(f, "")
	f = append(f, "#")
	f = append(f, "# First some standard log files.  Log by facility.")
	f = append(f, "#")
	//f=append(f,"auth,authpriv.*       /var/log/auth.log")
	f = append(f, "*.*;auth,authpriv.none     -/var/log/syslog")
	f = append(f, "#cron.*           -/var/log/cron.log")
	f = append(f, "daemon.*          -/var/log/daemon.log")
	f = append(f, "kern.=debug          -/var/log/iptables.log")
	f = append(f, "lpr.*             -/var/log/lpr.log")
	//f=append(f,"mail.*          -/var/log/mail.log")
	f = append(f, "local3.* /var/log/haproxy.log")
	f = append(f, "user.*            -/var/log/user.log")
	f = append(f, "mail.info         -/var/log/mail.info")
	f = append(f, "mail.warn         -/var/log/mail.warn")
	f = append(f, "mail.err       /var/log/mail.err")
	f = append(f, "news.crit         /var/log/news/news.crit")
	f = append(f, "news.err       /var/log/news/news.err")
	f = append(f, "news.notice       -/var/log/news/news.notice")
	f = append(f, "")
	f = append(f, "#")
	f = append(f, "# Some \"catch-all\" log files.")
	f = append(f, "#")
	f = append(f, "*.=debug;\\")
	f = append(f, "   auth,authpriv.none;\\")
	f = append(f, "   news.none;mail.none  -/var/log/debug")
	f = append(f, "*.=info;*.=notice;*.=warn;\\")
	f = append(f, "   auth,authpriv.none;\\")
	f = append(f, "   cron,daemon.none;\\")
	f = append(f, "   mail,news.none    -/var/log/messages")
	f = append(f, "")
	f = append(f, "")
	futils.CreateDir("/etc/rsyslog.d")
	md51 := futils.MD5File("/etc/rsyslog.conf")
	log.Debug().Msgf("%v /etc/rsyslog.conf [OK]", futils.GetCalleRuntime())
	_ = futils.FilePutContents("/etc/rsyslog.conf", strings.Join(f, "\n"))
	md52 := futils.MD5File("/etc/rsyslog.conf")
	RsyslogDWebFiltering()
	RsyslogDGeoIP()
	RsyslogDKernel()
	REBOOT := false

	if md51 != md52 {
		REBOOT = true
	}
	if RsyslogDFirewall() {
		REBOOT = true
	}
	if RsyslogDStrongswan() {
		REBOOT = true
	}
	if RsyslogDOthers() {
		REBOOT = true
	}
	return REBOOT
}
func RsyslogDKernel() {
	var f []string
	destdfile := "/etc/rsyslog.d/kernel.conf"

	f = append(f, "if  ($programname =='kernel') then {")
	remote_kernel := BuildRemoteSyslogs("kernel", "kernel")

	MainF := BuildLocalFilelog(LocalFileConf{File: "/var/log/kern.log", AsyncWriting: true})
	f = append(f, fmt.Sprintf("\t%v", MainF))

	if len(remote_kernel) > 3 {
		f = append(f, remote_kernel)
	}
	f = append(f, "\tstop")
	f = append(f, "}")
	f = append(f, "")
	_ = futils.FilePutContents(destdfile, strings.Join(f, "\n"))
}
func RsyslogDOthers() bool {
	gbfile := "/etc/rsyslog.d/class-process-inc.conf"
	var f []string
	f = append(f, "if  ($programname =='class.process.inc') then {")
	f = append(f, "\t-/var/log/class.process.log")
	f = append(f, "\t& stop")
	f = append(f, "}")

	f = append(f, "if  ($programname =='CRON') then {")
	f = append(f, "\t-/var/log/cron.log")
	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "if  ($programname =='cron') then {")
	f = append(f, "\t-/var/log/cron.log")
	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "")
	f = append(f, "if  ($programname =='iscsid') then {")
	f = append(f, "\t-/var/log/iscsid.log")
	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "")
	f = append(f, "if  ($programname =='ntpd') then {")
	f = append(f, "\t-/var/log/ntpd.log")
	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "")
	f = append(f, "if  ($programname =='haproxy') then {")
	f = append(f, "\t-/var/log/haproxy.log")
	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "")
	f = append(f, "if  ($programname =='ad-agent-lbl') then {")
	f = append(f, "\t-/var/log/adagent.log")
	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "")
	f = append(f, "if  ($programname =='wpa_supplicant') then {")
	f = append(f, "\t-/var/log/wpa_supplicant.log")
	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "if  ($programname =='artica-routes') then {")
	f = append(f, "\t-/var/log/routing.log")
	f = append(f, "\t& stop")
	f = append(f, "}")

	f = append(f, "")
	f = append(f, "if  ($msg contains '%ASA-') then  {")
	f = append(f, "\t-/var/log/cisco-asa.log")
	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "")
	f = append(f, "if  ($msg contains 'Legal Logs') then  {")
	f = append(f, "\t-/var/log/legal-rotate.log")
	f = append(f, "\t& stop")
	f = append(f, "}")
	md51 := futils.MD5File(gbfile)
	_ = futils.FilePutContents(gbfile, strings.Join(f, "\n"))

	md52 := futils.MD5File(gbfile)
	if md51 == md52 {
		return false
	}
	return true

}
func RsyslogDWebFiltering() {
	var f []string
	f = append(f, "if  ($programname =='webfiltering') then {")

	MainF := BuildLocalFilelog(LocalFileConf{File: "/var/log/webfiltering.log", AsyncWriting: true})
	f = append(f, fmt.Sprintf("\t%v", MainF))

	webfiltering := BuildRemoteSyslogs("webfiltering", "webfiltering")
	if len(webfiltering) > 3 {
		f = append(f, webfiltering)
	}
	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "")
	_ = futils.FilePutContents("/etc/rsyslog.d/webfiltering.conf", strings.Join(f, "\n"))

}
func RsyslogDStrongswan() bool {
	returned := false
	oldf := "/etc/rsyslog.d/strongswan-vici-stats.conf"
	newf := "/etc/rsyslog.d/00_strongswan.conf"

	if futils.FileExists(oldf) {
		futils.DeleteFile(oldf)
		returned = true
	}
	md51 := futils.MD5File(newf)
	var f []string
	StrongSwanLogSyslogDoNotStorelogsLocally := sockets.GET_INFO_INT("StrongSwanLogSyslogDoNotStorelogsLocally")
	remote := BuildRemoteSyslogs("strongswan", "strongswan")

	if StrongSwanLogSyslogDoNotStorelogsLocally == 1 {
		if len(remote) == 0 {
			return returned
		}
	}
	f = append(f, "if  ($programname =='strongswan-vici') then {")
	if StrongSwanLogSyslogDoNotStorelogsLocally == 0 {
		MainF := BuildLocalFilelog(LocalFileConf{File: "/var/log/strongswan-vici.log", AsyncWriting: true})
		f = append(f, fmt.Sprintf("\t%v", MainF))
	}

	if len(remote) > 3 {
		f = append(f, "\t"+remote)
	}

	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "")
	_ = futils.FilePutContents(newf, strings.Join(f, "\n"))

	md52 := futils.MD5File(newf)
	if md51 == md52 {
		return false
	}
	return true

}
func RsyslogDGeoIP() {
	var f []string
	f = append(f, "if  ($programname =='proxy_geoip') then {")
	MainF := BuildLocalFilelog(LocalFileConf{File: "/var/log/proxy-geoip.log", AsyncWriting: true})
	f = append(f, fmt.Sprintf("\t%v", MainF))
	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "")
	_ = futils.FilePutContents("/etc/rsyslog.d/proxy_geoip.conf", strings.Join(f, "\n"))

}
func RsyslogDFirewall() bool {
	returned := false
	oldf := "/etc/rsyslog.d/firewall.conf"
	newf := "/etc/rsyslog.d/00_firewall.conf"
	if futils.FileExists(oldf) {
		futils.DeleteFile(oldf)
		returned = true
	}
	md51 := futils.MD5File(newf)
	var f []string
	FirewallSyslogDoNotStorelogsLocally := sockets.GET_INFO_INT("FirewallSyslogDoNotStorelogsLocally")
	f = append(f, "")
	remote := BuildRemoteSyslogs("firewall", "firewall")

	if len(remote) == 0 {
		if FirewallSyslogDoNotStorelogsLocally == 1 {
			if len(md51) == 0 {
				return true
			} else {
				return returned
			}
		}
	}

	f = append(f, "if  ($msg contains 'FIREHOL') then {")
	if FirewallSyslogDoNotStorelogsLocally == 0 {
		MainF := BuildLocalFilelog(LocalFileConf{File: "/var/log/firewall.log", AsyncWriting: true})
		f = append(f, fmt.Sprintf("\t%v", MainF))
	}
	f = append(f, remote)

	f = append(f, "\t& stop")
	f = append(f, "}")
	f = append(f, "")
	_ = futils.FilePutContents(newf, strings.Join(f, "\n"))

	md52 := futils.MD5File(newf)
	if md51 == md52 {
		return false
	}
	return true

}
func LogSynkConfig() string {

	LogSinkWorkDir := sockets.GET_INFO_STR("LogSinkWorkDir")
	if len(LogSinkWorkDir) < 3 {
		LogSinkWorkDir = "/home/syslog/logs_sink"
	}
	ActAsASyslogServer := sockets.GET_INFO_INT("ActAsASyslogServer")
	EnableSyslogLogSink := sockets.GET_INFO_INT("EnableSyslogLogSink")
	LogSynRTEnabled := sockets.GET_INFO_INT("LogSynRTEnabled")
	LogSynRTMaxSize := sockets.GET_INFO_INT("LogSynRTMaxSize")
	LogSynWazuh := sockets.GET_INFO_INT("LogSynWazuh")
	var f []string
	f = append(f, fmt.Sprintf("#\t%v", futils.GetCalleRuntime()))
	f = append(f, fmt.Sprintf("#\tLogs Sink feature: EnableSyslogLogSink=%d/ActAsASyslogServer=%d/LogSynRTEnabled=%d", EnableSyslogLogSink, ActAsASyslogServer, LogSynRTEnabled))
	DestinationDir := LogSinkWorkDir
	if ActAsASyslogServer == 0 {
		futils.DeleteFile("/etc/cron.d/logsink-remove-rtime")
		return strings.Join(f, "\n")
	}
	if EnableSyslogLogSink == 0 {
		futils.DeleteFile("/etc/cron.d/logsink-remove-rtime")
		_ = futils.RmRF(LogSinkWorkDir)
		return strings.Join(f, "\n")
	}
	SyslogLogSinkZipLevel := sockets.GET_INFO_INT("SyslogLogSinkZipLevel")
	if SyslogLogSinkZipLevel == 0 {
		SyslogLogSinkZipLevel = 2
	}
	futils.CreateDir(DestinationDir)

	LogSynRTMaxSize = LogSynRTMaxSize * 1024
	LogSynRTMaxSize = LogSynRTMaxSize * 1024

	APP_WAZHU_INSTALLED := sockets.GET_INFO_INT("APP_WAZHU_INSTALLED")
	EnableWazhuCLient := sockets.GET_INFO_INT("EnableWazhuCLient")

	if APP_WAZHU_INSTALLED == 0 {
		EnableWazhuCLient = 0
	}
	if EnableWazhuCLient == 0 {
		LogSynWazuh = 0
	}
	if LogSynWazuh == 1 {
		LogSynRTEnabled = 1
	}
	var StasCom []string
	StasCom = append(StasCom, "\t\t\tif ($msg contains ':::') then {")
	EnableStatsCommunicator := sockets.GET_INFO_INT("EnableStatsCommunicator")
	if EnableStatsCommunicator == 1 {
		StasCom = append(StasCom, "#\t\t\tQUEUE SETTINGS FOR THE SOCKET ACTION")
		StasCom = append(StasCom, "\t\t\t\t$ActionQueueType           LinkedList")
		StasCom = append(StasCom, "\t\t\t\t$ActionQueueSize           10000")
		StasCom = append(StasCom, "\t\t\t\t$ActionQueueHighWaterMark  8000")
		StasCom = append(StasCom, "\t\t\t\t$ActionQueueLowWaterMark   2000")
		StasCom = append(StasCom, "\t\t\t\t$OMUxSockSocket /run/logsink/stats.sock")
		StasCom = append(StasCom, "\t\t\t\t:omuxsock:;SquidStats")
		StasCom = append(StasCom, "#\t\t\tEND OF QUEUE SETTINGS FOR THE SOCKET")
	}
	StasCom = append(StasCom, fmt.Sprintf("\t\t\t\t%v", BuildLocalFilelog(LocalFileConf{File: "/var/log/squid/stats.log", AsyncWriting: true})))
	StasCom = append(StasCom, "\t\t\t& stop")
	StasCom = append(StasCom, "\t}")
	StasComRules := strings.Join(StasCom, "\n")

	f = append(f, fmt.Sprintf("#\t %v APP_WAZHU_INSTALLED=%d,EnableWazhuCLient=%d LogSynWazuh=%d", futils.GetCalleRuntime(), APP_WAZHU_INSTALLED, EnableWazhuCLient, LogSynWazuh))
	futils.CreateDir("/var/log/squid")
	f = append(f, "template (name=\"LogsSink\" type=\"string\" string=\""+DestinationDir+`/%HOSTNAME%/%timegenerated:1:10:date-rfc3339%_%FROMHOST-IP%.gz")`)
	f = append(f, `template(name="SquidStats" type="string" string="%timestamp% %hostname% squid: %msg%\n")`)
	f = append(f, "template(name=\"dbg\" type=\"string\" string=\"prog='%programname%' tag='%syslogtag%' msg='%msg%'\\n\")")
	f = append(f, "if ($fromhost-ip != \"127.0.0.1\" and $fromhost-ip != \"::1\") then {")
	f = append(f, "")
	f = append(f, "")

	//f = append(f, "action(type=\"omfile\" file=\"/var/log/rsyslog-dbg.txt\" template=\"dbg\")")
	f = append(f, "")
	f = append(f, "\tif ($programname contains \"(squid-\" ) then {")
	f = append(f, StasComRules)
	f = append(f, fmt.Sprintf("\t\t%v", BuildLocalFilelog(LocalFileConf{File: "/var/log/squid/access.log", AsyncWriting: true})))
	f = append(f, "\tstop")
	f = append(f, "\t}")

	f = append(f, "\tif ($msg contains '\" devid=\"FGT') then {")
	futils.CreateDir("/var/log/fortinet")
	f = append(f, fmt.Sprintf("\t\t%v", BuildLocalFilelog(LocalFileConf{File: "/var/log/fortinet/access.log", AsyncWriting: true})))
	f = append(f, BuildToArticaRest("fortigate"))
	f = append(f, "\t\t& stop")
	f = append(f, "\t}")
	f = append(f, "\tif ($programname =='squid') then {")
	f = append(f, StasComRules)

	cachelog := BuildLocalFilelog(LocalFileConf{File: "/var/log/squid/cache.log", AsyncWriting: true})
	BadWords := []string{
		"Processing Configuration File", "WARNING:", "HTCP Disabled", "ERROR:", "helperOpenServers:",
		"Logfile:", "Finished loading", "Squid plugin", "Store logging", "DNS IPv4", "Adaptation support",
		"Adding nameserver", "Finished loading", "Accepting HTTP Socket", "Accepting SSL", "Accepting SNMP",
		"CheckGlobalInfos", "NETDB state", "Sending SNMP messages", "squid.conf line", ": acl", "Set Current Directory",
		"Reconfiguring Squid", "Closing HTTP", "Closing SNMP", "ipcCreate: fork", "Reloading Proxy service", "current master transaction",
		"abandoning conn", "aclIpParseIpData", "storeLateRelease", "storeDirWriteCleanLogs", "write failure:",
		"kick abandoning", "RESTAPI:",
	}
	var Comp []string
	for _, BadWord := range BadWords {
		Comp = append(Comp, fmt.Sprintf("($msg contains '%v')", BadWord))
	}

	f = append(f, fmt.Sprintf("\t\t\tif %v then {", strings.Join(Comp, " or ")))
	f = append(f, fmt.Sprintf("\t\t\t%v", cachelog))
	f = append(f, "\t\t\t\t& stop")
	f = append(f, "\t\t\t}")

	f = append(f, fmt.Sprintf("\t%v", BuildLocalFilelog(LocalFileConf{File: "/var/log/squid/access.log", AsyncWriting: true})))
	f = append(f, "\t\t& stop")
	f = append(f, "\t\t}")
	f = append(f, "")

	if LogSynRTEnabled == 1 {
		_, _ = futils.ExecutePHP("exec.wazhu.client.php --logsink")
		f = append(f, BuildLocalFilelog(LocalFileConf{File: "/var/log/logsink-rtime.log", AsyncWriting: true}))
	}

	f = append(f, fmt.Sprintf("\taction(type=\"omfile\" ZipLevel=\"%d\" dynaFile=\"LogsSink\" dirCreateMode=\"0755\" FileCreateMode=\"0666\" ioBufferSize=\"128k\" veryRobustZip=\"on\" flushOnTXEnd=\"off\" asyncWriting=\"on\")", SyslogLogSinkZipLevel))
	f = append(f, "\t& stop")
	f = append(f, "}")
	return strings.Join(f, "\n")
}
func CleanRtt() {
	futils.DeleteFile("/etc/cron.d/logsink-remove-rtime")
	file := "/var/log/logsink-rtime.log"
	LogSynRTEnabled := sockets.GET_INFO_INT("LogSynRTEnabled")
	if LogSynRTEnabled == 0 {
		futils.DeleteFile(file)
		return
	}

	size := futils.FileSizeMB("/var/log/logsink-rtime.log")
	LogSynRTMaxSize := sockets.GET_INFO_INT("LogSynRTMaxSize")

	echo := futils.FindProgram("echo")
	if size < LogSynRTMaxSize {
		return
	}
	_, _ = futils.ExecuteShell(fmt.Sprintf("%v \"\" >%v", echo, file))
}
func SSLExposed() SSlConfSyslog {
	var Conf SSlConfSyslog
	RsyslogCertificatesEnc := futils.Base64Decode(sockets.GET_INFO_STR("RsyslogCertificates"))
	Conf.RsyslogCertificates = futils.UnserializeMap1(RsyslogCertificatesEnc)

	if len(Conf.RsyslogCertificates["PRIVKEY"]) < 50 {
		return Conf
	}
	if len(Conf.RsyslogCertificates["CERT"]) < 50 {
		return Conf
	}
	if len(Conf.RsyslogCertificates["CA"]) < 50 {
		return Conf
	}
	Conf.Expose_contentca = append(Conf.Expose_contentca, Conf.RsyslogCertificates["CA"])
	Conf.Expose_contentkey = append(Conf.Expose_contentkey, Conf.RsyslogCertificates["PRIVKEY"])
	Conf.Expose_contentert = append(Conf.Expose_contentkey, Conf.RsyslogCertificates["CERT"])
	Conf.RECALL_SSL["certificate"] = make(map[string]bool)
	Conf.RECALL_SSL["ca_key"] = make(map[string]bool)
	Conf.RECALL_SSL["public_key"] = make(map[string]bool)

	if futils.FileExists("/usr/lib/x86_64-linux-gnu/rsyslog/lmnsd_ossl.so") {
		log.Error().Msg(fmt.Sprintf("SSLExposed(): /usr/lib/x86_64-linux-gnu/rsyslog/lmnsd_ossl.so no such file"))
	}

	err, db := ConnectDB()
	if err != nil {
		log.Error().Msg(fmt.Sprintf("BuildRemoteSyslogs() %v", err.Error()))
		return Conf
	}
	defer db.Close()

	rows, err := db.Query(`SELECT ID,public_key,certificate,ca_key FROM rules WHERE ssl=1 and enabled=1`)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("BuildRemoteSyslogs() %v", err.Error()))
		return Conf
	}
	defer rows.Close()

	for rows.Next() {
		var ID int
		var public_key, certificate, ca_key sql.NullString
		err = rows.Scan(&ID, &public_key, &certificate, &ca_key)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("BuildRemoteSyslogs() rows.Scan %v", err.Error()))
			return Conf
		}
		if len(public_key.String) < 50 {
			continue
		}
		if len(ca_key.String) < 50 {
			continue
		}
		if len(certificate.String) < 50 {
			continue
		}
		zcertificate := certificate.String
		zCaKey := ca_key.String
		md5 := futils.Md5String(public_key.String)
		if !Conf.RECALL_SSL["public_key"][md5] {
			Conf.Expose_contentkey = append(Conf.Expose_contentkey, futils.Base64Decode(public_key.String))
			Conf.RECALL_SSL["public_key"][md5] = true
		}
		md5 = futils.Md5String(zcertificate)
		if !Conf.RECALL_SSL["certificate"][md5] {
			Conf.Expose_contentert = append(Conf.Expose_contentert, futils.Base64Decode(zcertificate))
			Conf.RECALL_SSL["certificate"][md5] = true
		}
		md5 = futils.Md5String(zCaKey)
		if !Conf.RECALL_SSL["ca_key"][md5] {
			Conf.Expose_contentca = append(Conf.Expose_contentca, futils.Base64Decode(zCaKey))
			Conf.RECALL_SSL["ca_key"][md5] = true
		}

		Conf.Events = append(Conf.Events, fmt.Sprintf("#\tAdding certificate for rule %d", ID))
	}
	return Conf
}

package logsink

import (
	"fmt"
	"futils"
	"strings"
)

func BuilCommon() {
	commonPgBouncer()
	commonLetsEncrypt()
	buildSyslog()
}

func commonPgBouncer() {
	lfile := "/var/log/pgbouncer.log"
	ConfFile := "/etc/rsyslog.d/00_pgbouncer.conf"
	oldmd := futils.MD5File(ConfFile)
	sName := "pgbouncer"
	add_rules := BuildRemoteSyslogs(sName, sName)
	mainrule := BuildLocalFileSimple(lfile)

	var h []string
	h = append(h, fmt.Sprintf("if  ( $programname =='%v') then {", sName))
	h = append(h, mainrule)
	h = append(h, add_rules)
	h = append(h, "\t& stop")
	h = append(h, "\t}")
	h = append(h, "")
	_ = futils.FilePutContents(ConfFile, strings.Join(h, "\n"))
	newmd := futils.MD5File(ConfFile)
	if oldmd == newmd {
		return
	}
	Restart()
}
func commonLetsEncrypt() {
	lfile := "/var/log/letsencrypt.log"
	ConfFile := "/etc/rsyslog.d/00_letsencrypt.conf"
	oldmd := futils.MD5File(ConfFile)
	sName := "letsencrypt"
	add_rules := BuildRemoteSyslogs(sName, sName)
	mainrule := BuildLocalFileSimple(lfile)

	var h []string
	h = append(h, fmt.Sprintf("if  ( $programname =='%v') then {", sName))
	h = append(h, mainrule)
	h = append(h, add_rules)
	h = append(h, "\t& stop")
	h = append(h, "\t}")
	h = append(h, "")
	_ = futils.FilePutContents(ConfFile, strings.Join(h, "\n"))
	newmd := futils.MD5File(ConfFile)
	if oldmd == newmd {
		return
	}
	Restart()
}
func buildSyslog() {
	lfile := "/var/log/rsyslogd.log"
	oldmd := futils.MD5File(SyslogConf)
	add_rules := BuildRemoteSyslogs("syslog", "rsyslogd")
	mainrule := BuildLocalFileSimple(lfile)

	var h []string
	h = append(h, "if  ( $programname =='liblogging-stdlog' or $programname =='rsyslogd') then {")
	h = append(h, mainrule)
	h = append(h, add_rules)
	h = append(h, "\t& stop")
	h = append(h, "\t}")
	h = append(h, "")
	_ = futils.FilePutContents(SyslogConf, strings.Join(h, "\n"))
	newmd := futils.MD5File(SyslogConf)
	if oldmd == newmd {
		return
	}
	Restart()
}

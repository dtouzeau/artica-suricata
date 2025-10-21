package aFirewallTools

import (
	"IptablesTools"
	"SqliteConns"
	"bytes"
	"database/sql"
	"fmt"
	"futils"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

var reMatchesNumber = regexp.MustCompile(`RULE\.(\d+)`)
var ipTablesSave []string

func CleanRulesByString(StrDetect []string) {

	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)

	if ok {
		file := futils.Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s[%v:%d]: ", file, fn.Name(), line)
	}
	log.Info().Msgf("%v clean rules using [%v] by %v", futils.GetCalleRuntime(), strings.Join(StrDetect, ","), TheCall)

	Lines := CurrentRules()
	Changes := false
	var NewLines []string
	log.Debug().Msgf("%v scanning %d lines", futils.GetCalleRuntime(), len(Lines))
	for _, line := range Lines {
		Found := false
		for _, Str := range StrDetect {
			if strings.Contains(line, Str) {
				Found = true
				break
			}
		}
		if Found {
			Changes = true
			continue
		}
		NewLines = append(NewLines, line)
	}
	if !Changes {
		return
	}
	log.Debug().Msgf("%v Restoring \"%d\"", futils.GetCalleRuntime(), len(NewLines))
	_ = IptablesTools.Restore(strings.Join(NewLines, "\n"))
	return
}
func GetCurrentIPTablesRules() (string, error) {
	var stdout bytes.Buffer
	IptablesSaveCMD := futils.FindProgram("iptables-save")
	cmd := exec.Command(IptablesSaveCMD)
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", err
	}
	Out := stdout.String()
	ipTablesSave = strings.Split(Out, "\n")
	return Out, nil
}
func GetIptablesAllRules() ([]string, error) {
	iptablesBin := futils.FindProgram("iptables")
	commands := [][]string{
		{"-L", "-n"},                 // Filter table (INPUT, FORWARD, OUTPUT)
		{"-t", "nat", "-L", "-n"},    // NAT table
		{"-t", "mangle", "-L", "-n"}, // Mangle table
	}
	var results []string
	for _, args := range commands {
		cmd := exec.Command(iptablesBin, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to run iptables %v: %v", args, err)
		}
		tb := strings.Split(string(output), "\n")
		for _, line := range tb {
			results = append(results, strings.TrimSpace(line))
		}
	}

	return results, nil
}
func CurrentRules() []string {
	tb, _ := GetCurrentIPTablesRules()
	return strings.Split(tb, "\n")
}
func IPTablesRestore(Content string) error {

	if len(ipTablesSave) > 3 {
		SrcContent := strings.Join(ipTablesSave, "\n")
		Md51 := futils.Md5String(SrcContent)
		Md52 := futils.Md5String(Content)
		if Md51 == Md52 {
			log.Debug().Msgf("%v ipTablesSave is the same of saved content...", futils.GetCalleRuntime())
			return nil
		}
	}

	iptablesRestore := futils.FindProgram("iptables-restore")
	tempfile := "/etc/artica-postfix/iptables.save"
	err := futils.FilePutContents(tempfile, Content)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return err
	}

	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)

	if ok {
		file := futils.Basename(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s[%v:%d]: ", file, fn.Name(), line)
	}

	log.Warn().Msgf("%v Restoring iptables configuration (From %v)", futils.GetCalleRuntime(), TheCall)
	cmdline := fmt.Sprintf("%v < %v", iptablesRestore, tempfile)
	err, out := futils.ExecuteShell(cmdline)
	futils.DeleteFile(tempfile)

	if err != nil {
		return fmt.Errorf("%v Error while executing iptables-restore %v %v", futils.GetCalleRuntime(), err.Error(), out)
	}

	var stdout bytes.Buffer
	cmd := exec.Command("/usr/sbin/iptables-save")
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf(fmt.Sprintf("%v /usr/sbin/iptables-save %v", futils.GetCalleRuntime(), err.Error()))
	}
	Out := stdout.String()
	ipTablesSave = strings.Split(Out, "\n")
	return nil
}
func extractRuleNumber(input string) int {
	match := reMatchesNumber.FindStringSubmatch(input)
	if match == nil || len(match) < 2 {
		return 0
	}
	return futils.StrToInt(match[1])
}
func ConfigIDs() map[int]bool {

	res := make(map[int]bool)
	db, err := SqliteConns.FirewallConnectRO()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return res
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(db)
	rows, err := db.Query(`SELECT ID  FROM iptables_main WHERE enabled=1`)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		_ = db.Close()
		return res
	}

	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		var ID int
		err := rows.Scan(&ID)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
			continue
		}
		res[ID] = true
	}
	return res
}
func CurrentIDs() map[int]bool {
	lines, err := GetIptablesAllRules()
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
	}
	log.Debug().Msgf("%v get %d lines", futils.GetCalleRuntime(), len(lines))
	ids := make(map[int]bool)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "references)") || strings.Contains(line, "policy ACCEPT") || strings.Contains(line, "prot opt source") {
			continue
		}
		Rnumber := extractRuleNumber(line)
		if Rnumber == 0 {
			log.Debug().Msgf("%v No rule detected in [%v]", futils.GetCalleRuntime(), line)
			continue
		}
		ids[Rnumber] = true

	}
	return ids
}
func MissingIDS() []int {
	IDsInSystem := CurrentIDs()
	IDsInDB := ConfigIDs()
	var res []int
	for Rnumber, _ := range IDsInDB {
		log.Debug().Msgf("%v Checking ID:%v = %v", futils.GetCalleRuntime(), Rnumber, IDsInSystem[Rnumber])
		if IDsInSystem[Rnumber] == false {
			res = append(res, Rnumber)
		}
	}
	return res

}
func CreateChain(GroupName string, Comment string) (error, string) {
	iptables := futils.FindProgram("iptables")
	cmd := exec.Command(iptables, "-t", "filter", "-N", GroupName, "-m", "comment", "--comment", Comment)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if strings.Contains(stderr.String(), "Chain already exists") {
			return nil, ""
		}

		log.Error().Msgf("%v [%v %v] %v (%v)", futils.GetCalleRuntime(), iptables, strings.Join(cmd.Args, " "), err.Error(), stderr.String())
		return err, stderr.String() + fmt.Sprintf("\n%v %v", iptables, strings.Join(cmd.Args, " "))
	}

	return nil, out.String()
}
func IpTablesSave() string {
	iptables_save := futils.FindProgram("iptables-save")
	cmd := exec.Command(iptables_save)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Error().Msgf("%v [%v] %v (%v)", futils.GetCalleRuntime(), iptables_save, err.Error(), stderr.String())
		return ""
	}

	return out.String()
}

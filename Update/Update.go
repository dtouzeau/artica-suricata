package Update

import (
	"DataShieldIPv4Blocklist"
	"SuriStructs"
	"Update/IPSets"
	"Update/Otx"
	"Update/UpdateLog"
	"apostgres"
	"bufio"
	"compressor"
	"database/sql"
	"fmt"
	"futils"
	"httpclient"
	"notifs"
	"os"
	"path/filepath"
	"regexp"
	"sockets"
	"strings"
	"suricata/SuricataTools"
	"surirules"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

var zmutex sync.Mutex

const iprepDir = "/etc/suricata/iprep"
const ProgressF = "suricata-update.progress"
const Pidtime = "/etc/artica-postfix/pids/exec.suricata.updates.php.update.time"

func TimeToUpdate() int64 {

	if !futils.FileExists(Pidtime) || !futils.FileExists("/etc/artica-postfix/settings/Daemons/CurrentEmergingRulesMD5") {
		return 10000000
	}
	return int64(futils.FileTimeMin(Pidtime))
}

func Run() {
	zmutex.Lock()
	defer zmutex.Unlock()
	futils.CreateDir("/etc/artica-postfix/pids")
	pidtime := "/etc/artica-postfix/pids/exec.suricata.updates.php.update.time"
	EnableSuricata := sockets.GET_INFO_INT("EnableSuricata")
	if EnableSuricata == 0 {
		return
	}

	SuriStructs.NDPICheckVer()
	SuricataUpdateInterval := sockets.GET_INFO_INT("SuricataUpdateInterval")
	if SuricataUpdateInterval == 0 {
		SuricataUpdateInterval = 1440
	}
	if SuricataUpdateInterval > 518400 {
		return
	}

	TimeMin := TimeToUpdate()
	if TimeMin < SuricataUpdateInterval {
		log.Debug().Msgf("%v %v < %v ABORTING", futils.GetCalleRuntime(), TimeMin, SuricataUpdateInterval)
		return
	}

	defer futils.TouchFile(pidtime)
	_ = Update()
	_ = OpenInfoSecFoundation()

}

func Update() error {

	notifs.BuildProgress(20, "{update_now} emerging.rules.tar.gz.md5", ProgressF)

	CurrentEmergingRulesMD5 := sockets.GET_INFO_STR("CurrentEmergingRulesMD5")
	tmpdir := futils.TEMPDIR()
	targetpath := fmt.Sprintf("%v/emerging.rules.tar.gz.md5", tmpdir)
	SuricataVersion := sockets.GET_INFO_STR("SURICATA_VERSION")

	if SuricataVersion == "0.0.0" {
		notifs.BuildProgress(110, "{failed} unable to stat suricata version", ProgressF)
		return fmt.Errorf("suricata version 0.0.0 is unsupported")
	}
	log.Debug().Msgf("%v CurrentEmergingRulesMD5=%v TMPDIR:%v", futils.GetCalleRuntime(), CurrentEmergingRulesMD5, tmpdir)
	uri := fmt.Sprintf("https://rules.emergingthreatspro.com/open/suricata-%v/emerging.rules.tar.gz.md5", SuricataVersion)
	if !httpclient.DownloadFile(uri, targetpath) {
		notifs.BuildProgress(110, "{failed} {downloading} emerging.rules.tar.gz.md5", ProgressF)
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: emerging.rules.tar.gz.md5"), futils.GetCalleRuntime())
		return fmt.Errorf("downloading failed")
	}
	data := strings.Split(futils.FileGetContents(targetpath), "\n")
	if len(data) > 3 {
		notifs.BuildProgress(110, "{failed} {downloading} Corrupted emerging.rules.tar.gz.md5", ProgressF)
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: emerging.rules.tar.gz.md5"), futils.GetCalleRuntime())
		return fmt.Errorf("downloading failed")
	}
	if len(data) == 0 {
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: emerging.rules.tar.gz.md5"), futils.GetCalleRuntime())
		notifs.BuildProgress(110, "{failed} {downloading} NULL emerging.rules.tar.gz.md5", ProgressF)
		return fmt.Errorf("downloading failed")
	}
	NewEmergingRulesMD5 := strings.TrimSpace(data[0])

	uri = fmt.Sprintf("https://rules.emergingthreatspro.com/open/suricata-%v/version.txt", SuricataVersion)
	targetpath = fmt.Sprintf("%v/version.txt", tmpdir)
	if !httpclient.DownloadFile(uri, targetpath) {
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: version.txt"), futils.GetCalleRuntime())
		notifs.BuildProgress(110, "{failed} {downloading} version.txt", ProgressF)
		return fmt.Errorf("downloading failed")
	}
	NextVersion := futils.FileGetContents(targetpath)
	futils.DeleteFile(targetpath)

	notifs.BuildProgress(30, "{update_now} emerging.rules.tar.gz", ProgressF)
	uri = fmt.Sprintf("https://rules.emergingthreatspro.com/open/suricata-%v/emerging.rules.tar.gz", SuricataVersion)
	targetpath = fmt.Sprintf("%v/emerging.rules.tar.gz", tmpdir)
	if !httpclient.DownloadFile(uri, targetpath) {
		notifs.BuildProgress(110, "{failed} emerging.rules.tar.gz", ProgressF)
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: emerging.rules.tar.gz"), futils.GetCalleRuntime())
		return fmt.Errorf("downloading failed")
	}
	FileMD5 := futils.MD5File(targetpath)
	if FileMD5 != NewEmergingRulesMD5 {
		notifs.BuildProgress(110, "{failed} emerging.rules.tar.gz {corrupted}", ProgressF)
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: corrupted emerging.rules.tar.gz"), futils.GetCalleRuntime())
		notifs.SquidAdminMysql(0, "[IDS]: Corrupted emerging.rules.tar.gz file", fmt.Sprintf("%v is not %v", FileMD5, NewEmergingRulesMD5), futils.GetCalleRuntime(), 73)
		return fmt.Errorf("corrupted emerging.rules.tar.gz")
	}

	notifs.BuildProgress(35, "{extracting} emerging.rules.tar.gz", ProgressF)
	err := compressor.UntarTgz(targetpath, "/etc/suricata")
	if err != nil {
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: extracting emerging.rules.tar.gz"), futils.GetCalleRuntime())
		notifs.BuildProgress(110, "{failed} unable to untar "+err.Error(), ProgressF)
		futils.DeleteFile(targetpath)
		return err
	}
	futils.DeleteFile(targetpath)
	UpdateLog.UpdateEvent(fmt.Sprintf("SUCCESS: Emerging Rules %v", NextVersion), futils.GetCalleRuntime())
	sockets.SET_INFO_STR("CurrentEmergingRulesMD5", NewEmergingRulesMD5)
	sockets.SET_INFO_STR("CurrentEmergingRulesVersion", NextVersion)

	final := false
	_ = AbuseCh(false)
	if NewEmergingRulesMD5 == CurrentEmergingRulesMD5 {
		notifs.BuildProgress(40, "{downloading} IP Reputation 1/9", ProgressF)
		if ipreputationAlienvault() {
			final = true
		}
		notifs.BuildProgress(45, "{downloading} IP Reputation 2/9", ProgressF)
		if ipreputationEmergingThreatsPro() {
			final = true
		}
		notifs.BuildProgress(50, "{downloading} IP Reputation 3/9", ProgressF)
		if ipreputationFirehol1() {
			final = true
		}
		notifs.BuildProgress(55, "{downloading} IP Reputation 4/9", ProgressF)
		if DataShieldIPv4Blocklist.Run(false) {
			final = true
		}
		notifs.BuildProgress(60, "{downloading} IP Reputation 5/9", ProgressF)
		if ipreputationBlocklistDeStrongips() {
			final = true
		}
		notifs.BuildProgress(65, "{downloading} IP Reputation 6/9", ProgressF)
		if ipreputationCibadguys() {
			final = true
		}
		notifs.BuildProgress(66, "{downloading} IP AlienVault data feeds 7/9", ProgressF)
		if Otx.Run() {
			final = true
		}

		notifs.BuildProgress(67, "{downloading} threat fox Abuse CH 8/9", ProgressF)
		if threatfoxAbuseCH() {
			final = true
		}
		notifs.BuildProgress(67, "{downloading} Stamus Network rules 9/9", ProgressF)
		if stamusNetworks() {
			final = true
		}

		notifs.BuildProgress(70, "{downloading} IP Reputation {done}", ProgressF)
		if final {
			Global := SuriStructs.LoadConfig()
			Global.LastUpdate = time.Now().Unix()
			SuriStructs.SaveConfig(Global)

			notifs.BuildProgress(75, "{reloading}", ProgressF)
			_ = buildFinal()
			notifs.BuildProgress(100, "{done}", ProgressF)
		} else {
			notifs.BuildProgress(100, "{success} {no_new_updates}", ProgressF)
		}
		return nil
	}

	notifs.BuildProgress(90, "{reloading}", ProgressF)
	_ = buildFinal()
	notifs.SquidAdminMysql(2, fmt.Sprintf("[IDS]: Success updating IDS patterns %v", NextVersion), "", futils.GetCalleRuntime(), 129)
	notifs.BuildProgress(100, "{done}", ProgressF)
	return nil

}
func checkAndDownloadRules(url, localFile, infoKey string) (bool, error) {
	tmpFile := filepath.Join(futils.TEMPDIR(), "tmp_rules")

	if !httpclient.DownloadFile(url, localFile) {
		return false, fmt.Errorf("%v downloading failed", url)
	}
	newMD5 := futils.MD5File(tmpFile)
	oldMD5 := sockets.GET_INFO_STR(infoKey)
	if newMD5 != oldMD5 {
		futils.DeleteFile(localFile)
		sockets.SET_INFO_STR(infoKey, newMD5)
		return true, nil
	}

	// No changes
	_ = os.Remove(tmpFile)
	return false, nil
}
func AbuseCh(only bool) error {
	var finalResults bool

	// JA3 Fingerprints
	if result, err := checkAndDownloadRules("https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules",
		"/etc/suricata/rules/ja3_fingerprints.rules", "ja3_fingerprints.rules"); err != nil {
		return err
	} else if result {
		UpdateLog.UpdateEvent(fmt.Sprintf("SUCCESS: Abuse.CH: ja3_fingerprints.rules"), futils.GetCalleRuntime())
		finalResults = true
	}

	// SSL IP Blacklist
	if result, err := checkAndDownloadRules("https://sslbl.abuse.ch/blacklist/sslipblacklist.rules",
		"/etc/suricata/rules/sslipblacklist.rules", "sslipblacklist.rules"); err != nil {
		if finalResults {
			UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: Abuse.CH: sslipblacklist.rules %v", err.Error()), futils.GetCalleRuntime())
			_ = buildFinal()
		}
		return err
	} else if result {
		UpdateLog.UpdateEvent(fmt.Sprintf("SUCCESS: Abuse.CH: sslipblacklist.rules"), futils.GetCalleRuntime())
		if finalResults {
			UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: Abuse.CH: sslipblacklist.rules %v", err.Error()), futils.GetCalleRuntime())
			_ = buildFinal()
		}
		finalResults = true
	}

	// SSL Blacklist
	if result, err := checkAndDownloadRules("https://sslbl.abuse.ch/blacklist/sslblacklist.rules",
		"/etc/suricata/rules/sslblacklist.rules", "sslblacklist.rules"); err != nil {
		if finalResults {
			UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: Abuse.CH: sslblacklist.rules %v", err.Error()), futils.GetCalleRuntime())
			_ = buildFinal()
		}
		return err
	} else if result {
		UpdateLog.UpdateEvent(fmt.Sprintf("SUCCESS: Abuse.CH: sslblacklist.rules"), futils.GetCalleRuntime())
		finalResults = true
	}

	// Emerging Threats Drop Rules
	if result, err := checkAndDownloadRules("http://rules.emergingthreats.net/blockrules/emerging-drop.suricata.rules",
		"/etc/suricata/rules/emerging-drop.suricata.rules", "emerging-drop.suricata.rules"); err != nil {
		if finalResults {
			UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: emerging-drop.suricata.rules %v", err.Error()), futils.GetCalleRuntime())
			_ = buildFinal()
		}
		return err
	} else if result {
		UpdateLog.UpdateEvent(fmt.Sprintf("SUCCESS: emerging-drop.suricata.rules"), futils.GetCalleRuntime())
		finalResults = true
	}

	// Optionally trigger buildfinal if rules were updated
	if only && finalResults {
		_ = buildFinal()
	}

	return nil
}
func buildFinal() error {

	tmpDir := futils.TEMPDIR()
	_ = surirules.ImportSuricataRulesToSQLite()

	err, disabledSignatures := SuricataTools.GetDisabledSignatures()
	if err != nil {
		return err
	}

	// Create the shell script
	shellScriptPath := filepath.Join(tmpDir, "sidrule-remove.sh")
	shellScriptFile, err := os.Create(shellScriptPath)
	if err != nil {
		return fmt.Errorf("failed to create shell script: %v", err)
	}
	defer func(shellScriptFile *os.File) {
		_ = shellScriptFile.Close()
	}(shellScriptFile)

	writer := bufio.NewWriter(shellScriptFile)
	_, _ = writer.WriteString("#!/bin/sh\n")

	for _, sig := range disabledSignatures {
		fmt.Printf("Disable signature %s\n", sig)
		_, _ = writer.WriteString(fmt.Sprintf("/usr/share/artica-postfix/bin/sidrule -d %s || true\n", sig))
	}
	_, _ = writer.WriteString(fmt.Sprintf("rm -f %s\n", shellScriptPath))
	_, _ = writer.WriteString("/etc/init.d/suricata reload\n\n")
	_ = writer.Flush()

	futils.Chmod(shellScriptPath, 0755)

	go func() {
		_, _ = futils.ExecuteShell(shellScriptPath)
		futils.DeleteFile(shellScriptPath)

	}()
	return nil
}
func ipreputationCibadguys() bool {
	url := "http://cinsscore.com/list/ci-badguys.txt"
	tempDir := os.TempDir()
	targetPath := filepath.Join(tempDir, "ci-badguys.txt")

	// Download the file

	if !httpclient.DownloadFile(url, targetPath) {
		log.Error().Msgf("%v Unable to download reputation file", futils.GetCalleRuntime())
		return false
	}

	oldMD5 := sockets.GET_INFO_STR("cibadguys.reputation")
	currentMD5 := futils.MD5File(targetPath)

	if oldMD5 == currentMD5 {
		_ = os.Remove(targetPath)
		return true
	}

	file, err := os.Open(targetPath)
	if err != nil {
		fmt.Println("Unable to open reputation file:", err)
		return false
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	outputPath := filepath.Join(iprepDir, "cibadguys.list")
	outputFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Println("Unable to create output file:", err)
		return false
	}
	defer func(outputFile *os.File) {
		_ = outputFile.Close()
	}(outputFile)

	scanner := bufio.NewScanner(file)
	reIP := regexp.MustCompile(`^([0-9\.]+)`)

	for scanner.Scan() {
		line := scanner.Text()
		if reIP.MatchString(line) {
			parts := reIP.FindStringSubmatch(line)
			_, _ = outputFile.WriteString(fmt.Sprintf("%s,6,127\n", parts[1]))
		}
	}

	_ = os.Remove(targetPath)
	sockets.SET_INFO_STR("cibadguys.reputation", currentMD5)

	return true
}
func ipreputationBlocklistDeStrongips() bool {
	uri := "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de_strongips.ipset"
	tempDir := os.TempDir()
	targetPath := filepath.Join(tempDir, "blocklist_de_strongips_ipset.txt")

	if !httpclient.DownloadFile(uri, targetPath) {
		log.Error().Msgf("%v Unable to download reputation file", futils.GetCalleRuntime())
		return false
	}

	oldMD5 := sockets.GET_INFO_STR("blocklist_de_strongips.reputation")
	currentMD5 := futils.MD5File(targetPath)

	if oldMD5 == currentMD5 {
		_ = os.Remove(targetPath)
		return true
	}

	// Open the downloaded file
	file, err := os.Open(targetPath)
	if err != nil {
		fmt.Println("Unable to open reputation file:", err)
		return false
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	outputPath := filepath.Join(iprepDir, "blocklist_de_strongips.list")
	outputFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Println("Unable to create output file:", err)
		return false
	}
	defer func(outputFile *os.File) {
		_ = outputFile.Close()
	}(outputFile)

	scanner := bufio.NewScanner(file)
	reIP := regexp.MustCompile(`^([0-9\.]+)$`)             // Regex to match IP addresses
	reCidr := regexp.MustCompile(`^([0-9\.]+)\/([0-9]+)$`) // Regex to match CIDR format

	for scanner.Scan() {
		line := scanner.Text()
		if reIP.MatchString(line) {
			parts := reIP.FindStringSubmatch(line)
			_, _ = outputFile.WriteString(fmt.Sprintf("%s,5,100\n", parts[1]))
			continue
		}
		if reCidr.MatchString(line) {
			parts := reCidr.FindStringSubmatch(line)
			_, _ = outputFile.WriteString(fmt.Sprintf("%s/%s,5,127\n", parts[1], parts[2]))
			continue
		}
	}
	_ = os.Remove(targetPath)
	sockets.SET_INFO_STR("blocklist_de_strongips.reputation", currentMD5)
	return true
}
func ipreputationAlienvault() bool {
	alienvaultURL := "https://reputation.alienvault.com/reputation.snort"
	tempDir := futils.TEMPDIR()
	targetPath := filepath.Join(tempDir, "alienvault_reputation.snort")

	// Download the file
	if !httpclient.DownloadFile(alienvaultURL, targetPath) {
		log.Error().Msgf("%v Unable to download reputation file:%v ", futils.GetCalleRuntime(), alienvaultURL)
		return false
	}

	oldMD5 := sockets.GET_INFO_STR("alienvault.reputation")
	currentMD5 := futils.MD5File(targetPath)
	if oldMD5 == currentMD5 {
		return true
	}

	file, err := os.Open(targetPath)
	if err != nil {
		fmt.Println("Unable to open reputation file:", err)
		return false
	}
	defer file.Close()

	futils.CreateDir(iprepDir)
	outputPath := filepath.Join(iprepDir, "alienvault.list")
	outputFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Println("Unable to create output file:", err)
		return false
	}
	defer outputFile.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "0") { // Match IPv4 addresses starting with "0" to "9"
			parts := strings.Fields(line)
			if len(parts) > 0 {
				_, _ = outputFile.WriteString(fmt.Sprintf("%s,1,127\n", parts[0]))
			}
		}
	}
	_ = os.Remove(targetPath)
	sockets.SET_INFO_STR("alienvault.reputation", currentMD5)

	return true
}
func ipreputationEmergingThreatsPro() bool {
	// Define URLs and paths
	emergingThreatsProURL := "https://rules.emergingthreatspro.com/fwrules/emerging-Block-IPs.txt"
	tempDir := futils.TEMPDIR()
	targetPath := filepath.Join(tempDir, "emergingthreatspro_block_ips.txt")

	// Download the file
	if !httpclient.DownloadFile(emergingThreatsProURL, targetPath) {
		log.Error().Msgf("%v Unable to download reputation file:%v ", futils.GetCalleRuntime(), emergingThreatsProURL)
		return false
	}

	oldMD5 := sockets.GET_INFO_STR("emergingthreatspro.reputation")
	currentMD5 := futils.MD5File(targetPath)
	if oldMD5 == currentMD5 {
		_ = os.Remove(targetPath)
		return false
	}

	db, err := apostgres.SQLConnect()
	if err != nil {
		log.Error().Msgf("%v Error connecting to database:%v ", futils.GetCalleRuntime(), err)
		return false
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	_, err = db.Exec(`DELETE FROM suricata_firewall WHERE xauto=1 and signature=0`)
	if err != nil {
		log.Error().Msgf("%v Error deleting firewall record:%v ", futils.GetCalleRuntime(), err)
		return false
	}

	file, err := os.Open(targetPath)
	if err != nil {
		fmt.Println("Unable to open reputation file:", err)
		return false
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	futils.CreateDir("/etc/suricata/iprep")
	outputPath := "/etc/suricata/ipre/emergingthreatspro.list"
	outputFile, err := os.Create(outputPath)

	if err != nil {
		fmt.Println("Unable to create output file:", err)
		return false
	}
	defer func(outputFile *os.File) {
		err := outputFile.Close()
		if err != nil {

		}
	}(outputFile)

	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`^([0-9\.]+)`) // Regex to match IP addresses
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if re.MatchString(line) {
			parts := re.FindStringSubmatch(line)
			_, _ = outputFile.WriteString(fmt.Sprintf("%s,2,100\n", parts[1]))
		}
	}
	_ = os.Remove(targetPath)
	sockets.SET_INFO_STR("emergingthreatspro.list", currentMD5)
	return true
}
func ipreputationFirehol1() bool {
	uri := "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset"
	tempDir := futils.TEMPDIR()
	targetPath := filepath.Join(tempDir, "firehol_level1.netset")

	// Download the file
	if !httpclient.DownloadFile(uri, targetPath) {
		log.Error().Msgf("%v Unable to download reputation file", futils.GetCalleRuntime())
		return false
	}
	oldMD5 := sockets.GET_INFO_STR("firehol_level1.reputation")
	currentMD5 := futils.MD5File(targetPath)

	if oldMD5 == currentMD5 {
		_ = os.Remove(targetPath)
		return true
	}

	err, Counter := IPSets.Build(IPSets.IPBuild{CategoryID: 4, SourcePath: targetPath, OutFileName: "firehol_level1.list"})
	if err != nil {
		log.Error().Msgf("%v Unable to build IPSet:%v", futils.GetCalleRuntime(), err)
		return false
	}
	log.Info().Msgf("%v IPSet built: %d records", futils.GetCalleRuntime(), Counter)
	sockets.SET_INFO_STR("firehol_level1.reputation", currentMD5)

	return true
}
func threatfoxAbuseCH() bool {
	uri := "https://threatfox.abuse.ch/downloads/threatfox_suricata.rules"
	tempDir := futils.TEMPDIR()
	targetPath := filepath.Join(tempDir, "threatfox_suricata.rules")

	if !httpclient.DownloadFile(uri, targetPath) {
		log.Error().Msgf("%v Unable to download reputation file", futils.GetCalleRuntime())
		return false
	}
	oldMD5 := sockets.GET_INFO_STR("threatfox_suricata.rules")
	currentMD5 := futils.MD5File(targetPath)

	if oldMD5 == currentMD5 {
		_ = os.Remove(targetPath)
		return false
	}
	sockets.SET_INFO_STR("threatfox_suricata.rules", currentMD5)
	futils.CopyFile(targetPath, "/etc/suricata/rules/threatfox_suricata.rules")
	return true

}
func stamusNetworks() bool {
	uri := "https://ti.stamus-networks.io/open/stamus-lateral-rules-checksum.txt"
	tempDir := futils.TEMPDIR()
	targetPath := filepath.Join(tempDir, "stamus-lateral-rules-checksum.txt")

	if !httpclient.DownloadFile(uri, targetPath) {
		log.Error().Msgf("%v Unable to download reputation file", futils.GetCalleRuntime())
		return false
	}
	oldMD5 := sockets.GET_INFO_STR("stamus-lateral-rules")
	currentMD5 := futils.FileGetContents(targetPath)
	if oldMD5 == currentMD5 {
		_ = os.Remove(targetPath)
		return false
	}
	targetPath = filepath.Join(tempDir, "stamus-lateral-rules.tar.gz")
	uri = "https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz"
	if !httpclient.DownloadFile(uri, targetPath) {
		log.Error().Msgf("%v Unable to download reputation file", futils.GetCalleRuntime())
		return false
	}
	err := compressor.UntarTgz(targetPath, "/etc/suricata")
	if err != nil {
		log.Error().Msgf("%v Unable to untar file", futils.GetCalleRuntime())
		return false
	}
	sockets.SET_INFO_STR("stamus-lateral-rules", currentMD5)
	return true
}

//

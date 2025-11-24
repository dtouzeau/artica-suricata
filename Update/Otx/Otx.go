package Otx

import (
	"SuriStructs"
	"Update/UpdateLog"
	"bufio"
	"fmt"
	"futils"
	"httpclient"
	"math/rand"
	"notifs"
	"os"
	"path/filepath"
	"strings"
	"surirules"
	"time"
	"unicode"

	"github.com/AlienVault-Labs/OTX-Go-SDK/src/otxapi"
	"github.com/rs/zerolog/log"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

const (
	TempDownloadDir = "/var/db/artica-suricata"
	ipRuleTemplate  = `alert ip $HOME_NET any -> any any (msg:"OTX internal host talking to host known in pulse"; flow:to_server; iprep:dst,Pulse,>,30; sid:41414141; rev:1;)
`
	ipCategoryTemplate = "41,Pulse,OTX community identified IP address\n"
	ipRepTemplate      = "%s,41,127\n"
	fileRuleTemplate   = `alert http any any -> $HOME_NET any (msg:"OTX - FILE MD5 from pulse %s"; filemd5:%s; reference: url, otx.alienvault.com/pulse/%s; sid:41%04d; rev:1;)
`
	ProgressF = "suricata-update.progress"
)

var otxfile = fmt.Sprintf("%s/otx.list", TempDownloadDir)
var otxrule = fmt.Sprintf("%s/otx_file_rules.rules", TempDownloadDir)

func parseFlags() SuriStructs.OtxOptions {
	var opt SuriStructs.OtxOptions

	Config := SuriStructs.LoadConfig()
	opt = Config.Otx
	opt.SkipIPRep = false
	opt.SkipFileMD5 = false
	opt.DestDir = "/var/db/artica-suricata"
	if opt.MaxPages == 0 {
		opt.MaxPages = 20
	}
	return opt
}

func mustCreate(path string) *os.File {
	f, err := os.Create(path)
	if err != nil {
		log.Error().Msgf("%v create %s: %v", futils.GetCalleRuntime(), path, err)
	}
	return f
}

// cleanASCII performs NFKD normalization and strips non-ASCII runes.
func cleanASCII(s string) string {
	// decompose accents, then drop non-ASCII
	t := transform.Chain(norm.NFKD, transform.RemoveFunc(func(r rune) bool {
		// keep printable ASCII (including space); drop everything else
		return r > unicode.MaxASCII || r < 0x20
	}))
	out, _, _ := transform.String(t, s)
	// Allow spaces and typical punctuation; collapse any newlines/tabs
	out = strings.ReplaceAll(out, "\n", " ")
	out = strings.ReplaceAll(out, "\t", " ")
	return strings.TrimSpace(out)
}

func Run() bool {

	opt := parseFlags()
	if opt.Enabled == 0 {
		return false
	}
	rand.Seed(time.Now().UnixNano())
	futils.CreateDir(opt.DestDir)
	pps := httpclient.LoadProxySettings()
	Hclient, err := httpclient.InitClient(pps)
	if err != nil {
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR:updated %d files signatures", err.Error()), futils.GetCalleRuntime())
		log.Error().Msgf("%v init client: %v", futils.GetCalleRuntime(), err)
		return false
	}
	if len(opt.ApiKey) < 5 {
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: API key too short"), futils.GetCalleRuntime())
		log.Error().Msgf("%v API key too short", futils.GetCalleRuntime())
		return false
	}
	// SDK expects the API key via header. The SDK reads it from env var "X_OTX_API_KEY".
	// Set it here so users can just pass --key like the Python script.
	if err := os.Setenv("X_OTX_API_KEY", opt.ApiKey); err != nil {
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: X_OTX_API_KEY ev failed %v", opt.ApiKey), futils.GetCalleRuntime())
		log.Error().Msgf("%v set env: %v", futils.GetCalleRuntime(), err)
		return false
	}

	log.Debug().Msgf("%v OTX API key: %s --> otxapi.NewClient", futils.GetCalleRuntime(), opt.ApiKey)
	client := otxapi.NewClient(Hclient)

	// Output files (opened lazily when needed)
	var fileRules *os.File
	var repList *os.File

	md51otxFile := futils.MD5File(otxfile)
	MD51otxRule := futils.MD5File(otxrule)

	md5RuleCount := 0
	ipCount := 0

	// Iterate subscribed pulses with pagination
	page := 1
	limit := 50

	for {

		notifs.BuildProgress(66, fmt.Sprintf("{downloading} IP AlienVault data feeds %d/%d", page, opt.MaxPages), ProgressF)
		if opt.MaxPages > 0 && page > opt.MaxPages {
			break
		}
		log.Debug().Msgf("%v Page %d Max=%d", futils.GetCalleRuntime(), page, limit)
		feed, resp, err := client.ThreatIntel.List(&otxapi.ListOptions{Page: page, PerPage: limit})
		if err != nil {
			var zBody string
			if resp.Content != nil {
				for s, b := range resp.Content {
					zBody = fmt.Sprintf("%v %v %v", zBody, s, b)
				}
			}
			log.Error().Msgf("%v OTX list page=%d: %v [%v]", futils.GetCalleRuntime(), page, err, zBody)
		}
		if feed.Count == 0 {
			break
		}

		for _, pulse := range feed.Pulses {
			// Collect indicators
			var md5s []string
			var ips []string

			for _, ind := range pulse.Indicators {
				typ := strings.ToLower(*ind.Type)
				switch typ {
				case "filehash-md5", "filehash_md5", "filehash", "md5":
					// Some feeds use different labels; be lenient
					md5 := strings.TrimSpace(*ind.Indicator)
					if md5 != "" {
						md5s = append(md5s, md5)
					}
				case "ipv4", "ipv6":
					ip := strings.TrimSpace(*ind.Indicator)
					if ip != "" {
						ips = append(ips, ip)
					}
				}
			}

			// Generate file MD5 rule + per-pulse md5 list
			if !opt.SkipFileMD5 && len(md5s) > 0 {
				if fileRules == nil {
					fileRules = mustCreate(filepath.Join(opt.DestDir, "otx_file_rules.rules"))
					defer fileRules.Close()
				}
				id := S(pulse.ID)
				zDate := S(pulse.CreatedAt)
				md5File := fmt.Sprintf("OTX_%s.txt", id)
				md5Path := filepath.Join(opt.DestDir, md5File)
				if err := writeLines(md5Path, md5s); err != nil {
					log.Error().Msgf("%v write %s: %v", futils.GetCalleRuntime(), md5Path, err)
				}
				name := cleanASCII(S(pulse.Name)) + " - " + C(zDate)
				log.Debug().Msgf("%v %v %v %v", futils.GetCalleRuntime(), name, md5File, id)
				rule := fmt.Sprintf(fileRuleTemplate, name, md5File, id, rand.Intn(9000)+1000)
				if _, err := fileRules.WriteString(rule); err != nil {
					log.Error().Msgf("%v append rule: %v", futils.GetCalleRuntime(), err)
				}
				md5RuleCount++
			}

			// Accumulate IP reputation entries
			if !opt.SkipIPRep && len(ips) > 0 {
				if repList == nil {
					repList = mustCreate(filepath.Join(opt.DestDir, "otx.list"))
					defer repList.Close()
				}
				bw := bufio.NewWriter(repList)
				for _, ip := range ips {
					if _, err := bw.WriteString(fmt.Sprintf(ipRepTemplate, ip)); err != nil {
						log.Error().Msgf("%v write rep entry: %v", futils.GetCalleRuntime(), err)
						return false
					}
				}
				if err := bw.Flush(); err != nil {
					log.Error().Msgf("%v flush rep list: %v", futils.GetCalleRuntime(), err)
					return false
				}
				ipCount += len(ips)
			}
		}
		page++
	}

	// Write core iprep support files
	if !opt.SkipIPRep {
		if err := os.WriteFile(filepath.Join(opt.DestDir, "categories.txt"), []byte(ipCategoryTemplate), 0o644); err != nil {
			UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: write categories.txt %v", err), futils.GetCalleRuntime())
			log.Error().Msgf("%v write categories.txt: %v", futils.GetCalleRuntime(), err)
		}
		if err := os.WriteFile(filepath.Join(opt.DestDir, "otx_iprep.rules"), []byte(ipRuleTemplate), 0o644); err != nil {
			UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: write otx_iprep.rules %v", err), futils.GetCalleRuntime())
			log.Error().Msgf("%v write otx_iprep.rules: %v", futils.GetCalleRuntime(), err)
		}

		UpdateLog.UpdateEvent(fmt.Sprintf("INFO: Wrote related iprep rules to %s", filepath.Join(opt.DestDir, "otx_iprep.rules")), futils.GetCalleRuntime())
		log.Info().Msgf("%v Wrote related iprep rules to %s", futils.GetCalleRuntime(), filepath.Join(opt.DestDir, "otx_iprep.rules"))
		if repList != nil {
			UpdateLog.UpdateEvent(fmt.Sprintf("INFO: Wrote %d IPv4 & IPv6 to %s", ipCount, repList.Name()), futils.GetCalleRuntime())
			log.Info().Msgf("%v Wrote %d IPv4 & IPv6 to %s", futils.GetCalleRuntime(), ipCount, repList.Name())
		} else {
			log.Info().Msgf("No IPs found; otx.list not created.")
		}
	}

	if !opt.SkipFileMD5 {
		if fileRules != nil {
			UpdateLog.UpdateEvent(fmt.Sprintf("INFO: Wrote %d rules to %s", md5RuleCount, fileRules.Name()), futils.GetCalleRuntime())
			log.Info().Msgf("%v Wrote %d md5 hash files to %s", futils.GetCalleRuntime(), md5RuleCount, opt.DestDir)
			log.Info().Msgf("%v Wrote %d rules to %s", futils.GetCalleRuntime(), md5RuleCount, fileRules.Name())
		} else {
			log.Info().Msgf("%v No MD5 indicators found; otx_file_rules.rules not created.")
		}

	}
	md52otxFile := futils.MD5File(otxfile)
	MD52otxRule := futils.MD5File(otxrule)
	if md52otxFile != md51otxFile || MD52otxRule != MD51otxRule {
		opt.LastUpdate = time.Now().Unix()
		Cfg := SuriStructs.LoadConfig()
		Cfg.Otx = opt
		SuriStructs.SaveConfig(Cfg)
		InstallOtx()
		return true
	}
	return false

}
func CleanWorkDir() {
	files := futils.DirectoryScan("/etc/suricata/rules")
	for _, f := range files {
		if strings.HasPrefix(f, "OTX_") && strings.HasSuffix(f, ".txt") {
			futils.DeleteFile(fmt.Sprintf("/etc/suricata/rules/%s", f))
		}
	}
	futils.TouchFile("/etc/suricata/iprep/otx.list")
	futils.TouchFile("/etc/suricata/rules/otx_file_rules.rules")
}

func InstallOtx() {
	CleanWorkDir()
	files := futils.DirectoryScan(TempDownloadDir)
	for _, f := range files {
		if strings.HasPrefix(f, "OTX_") && strings.HasSuffix(f, ".txt") {
			_ = futils.CopyFile(fmt.Sprintf("%s/%s", TempDownloadDir, f), fmt.Sprintf("/etc/suricata/rules/%s", f))
			futils.DeleteFile(fmt.Sprintf("%s/%s", TempDownloadDir, f))
		}
	}
	_ = futils.CopyFile(otxfile, fmt.Sprintf("/etc/suricata/iprep/otx.list"))
	_ = futils.CopyFile(otxrule, fmt.Sprintf("/etc/suricata/rules/otx_file_rules.rules"))
	UpdateLog.UpdateEvent(fmt.Sprintf("INFO: installing otx_file_rules.rules otx.list"), futils.GetCalleRuntime())
	err := surirules.ImportSuricataRulesToSQLite()
	if err != nil {
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: %v", err.Error()), futils.GetCalleRuntime())
	}
}

func writeLines(path string, lines []string) error {
	f := mustCreate(path)
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		if _, err := w.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}
func S(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
func C(input string) string {
	// Layout matching your input format
	const inputLayout = "2006-01-02T15:04:05.000000"
	const outputLayout = "2006/01/02"

	t, err := time.Parse(inputLayout, input)
	if err != nil {
		return ""
	}
	return t.Format(outputLayout)
}

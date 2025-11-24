package Update

import (
	"Reconfigure"
	"Update/UpdateLog"
	"compressor"
	"fmt"
	"futils"
	"httpclient"
	"notifs"
	"os"
	"sockets"
	"strings"
	"surirules"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type Parameter struct {
	Prompt string `yaml:"prompt"`
}

type Source struct {
	Summary      string               `yaml:"summary"`
	Description  string               `yaml:"description"`
	Vendor       string               `yaml:"vendor"`
	License      string               `yaml:"license"`
	LicenseURL   string               `yaml:"license-url,omitempty"`
	URL          string               `yaml:"url"`
	SubscribeURL string               `yaml:"subscribe-url,omitempty"`
	Parameters   map[string]Parameter `yaml:"parameters,omitempty"`
	MinVersion   string               `yaml:"min-version,omitempty"`
	Obsolete     string               `yaml:"obsolete,omitempty"`
	Deprecated   string               `yaml:"deprecated,omitempty"`
	Checksum     bool                 `yaml:"checksum,omitempty"`
	Replaces     []string             `yaml:"replaces,omitempty"`
}
type Suricata struct {
	Recommended string `yaml:"recommended"`
	V70         string `yaml:"7.0"`
}
type Versions struct {
	Suricata Suricata `yaml:"suricata"`
}

type Config struct {
	Version  int               `yaml:"version"`
	Sources  map[string]Source `yaml:"sources"`
	Versions Versions          `yaml:"versions"`
}

func OpenInfoSecFoundation() error {
	SuricataVersion := sockets.GET_INFO_STR("SURICATA_VERSION")
	Url := "https://www.openinfosecfoundation.org/rules/index.yaml"
	targetpath := futils.TempFileName()
	if !httpclient.DownloadFile(Url, targetpath) {
		return fmt.Errorf("downloading Index from openinfosecfoundation failed")
	}
	yamlFile, err := os.ReadFile(targetpath)
	if err != nil {
		log.Error().Msgf("%v Error reading YAML file: %v", futils.GetCalleRuntime(), err.Error())
	}

	// Unmarshal the YAML content into the Config struct
	var config Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Error().Msgf("%v Error unmarshalling YAML: %v", futils.GetCalleRuntime(), err)
	}
	log.Debug().Msgf("%v Current version:%v", futils.GetCalleRuntime(), SuricataVersion)

	RecommendedVersion := config.Versions.Suricata.Recommended
	if RecommendedVersion != SuricataVersion {
		log.Warn().Msgf("%v Recommended version:%v !=%v", futils.GetCalleRuntime(), RecommendedVersion, SuricataVersion)
		notifs.SquidAdminMysql(1, fmt.Sprintf("Update downloads recommended v%v but current version is %v ( please upgrade )", RecommendedVersion, SuricataVersion), "", futils.GetCalleRuntime(), 69)
		UpdateLog.UpdateEvent(fmt.Sprintf("Update downloads recommended v%v but current version is %v ( please upgrade )", RecommendedVersion, SuricataVersion), futils.GetCalleRuntime())
		return fmt.Errorf("incompatible version")
	}
	UPDATED := false
	UpdatedCount := 0
	pp := httpclient.LoadProxySettings()
	TempDir := futils.TEMPDIR() + "/Suricata"
	futils.CreateDir(TempDir)
	for key, source := range config.Sources {
		Md5String := ""
		if source.License == "Commercial" {
			continue
		}
		source.URL = strings.ReplaceAll(source.URL, `%(__version__)s`, SuricataVersion)
		BaseNameFile := futils.BaseName(source.URL)

		err, heads := httpclient.GetHeaders(source.URL, pp)
		if err != nil {
			UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: fetching headers from %v: %v", key, err), futils.GetCalleRuntime())
			log.Error().Msgf("%v Error fetching headers from %v: %v", futils.GetCalleRuntime(), key, err)
			continue
		}
		if len(heads["ETAG"]) > 0 {
			Md5String = futils.Md5String(heads["ETAG"])
			log.Debug().Msgf("%v %v Header ETAG:%v/%v", futils.GetCalleRuntime(), BaseNameFile, heads["ETAG"], Md5String)
		} else {
			log.Warn().Msgf("%v %v Header ETAG:%v", futils.GetCalleRuntime(), BaseNameFile, "Missing")
		}

		SourceKey := futils.Md5String(BaseNameFile)
		CurMD5 := sockets.GET_INFO_STR(SourceKey)
		if len(Md5String) > 0 {
			if CurMD5 == Md5String {
				log.Debug().Msgf("%v %v SKIP", futils.GetCalleRuntime(), key)
				continue
			}
		}
		TargetFile := fmt.Sprintf("%v/%v", TempDir, BaseNameFile)
		FinalFile := fmt.Sprintf("%v/%v", "/etc/suricata/rules", BaseNameFile)

		if !httpclient.DownloadFile(source.URL, TargetFile) {
			UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: downloading %v", BaseNameFile), futils.GetCalleRuntime())
			log.Error().Msgf("%v Error downloading %v", futils.GetCalleRuntime(), BaseNameFile)
			continue
		}

		if strings.HasSuffix(BaseNameFile, ".rules") {
			if len(Md5String) == 0 {
				Md5String = futils.MD5File(TargetFile)
			}

			if Md5String == CurMD5 {
				continue
			}
			if futils.FileExists(FinalFile) {
				md5Old := futils.MD5File(FinalFile)
				md5New := futils.MD5File(TargetFile)
				if md5Old == md5New {
					continue
				}
			}
			UpdatedCount++
			UPDATED = true
			_ = futils.CopyFile(TargetFile, FinalFile)
			sockets.SET_INFO_STR(SourceKey, Md5String)
			UpdateLog.UpdateEvent(fmt.Sprintf("SUCCESS:  update IDS rules %v", BaseNameFile), futils.GetCalleRuntime())
			log.Info().Msgf("%v Success update IDS rules %v", futils.GetCalleRuntime(), BaseNameFile)
			continue
		}
		if strings.HasSuffix(BaseNameFile, ".tar.gz") {

			if len(Md5String) == 0 {
				Md5String = futils.MD5File(TargetFile)
			}

			if Md5String == CurMD5 {
				continue
			}

			err := compressor.UntarTgz(TargetFile, TempDir)
			if err != nil {
				futils.DeleteFile(TargetFile)
				UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: Untaring tar.gz: %v", BaseNameFile), futils.GetCalleRuntime())
				log.Error().Msgf("%v Error untaring tar.gz: %v", futils.GetCalleRuntime(), err)
				continue
			}
			futils.DeleteFile(TargetFile)
			sockets.SET_INFO_STR(SourceKey, Md5String)
		}

	}

	Files := futils.DirectoryScan(TempDir)
	for _, file := range Files {
		if strings.HasSuffix(file, ".txt") {
			continue
		}
		if strings.HasSuffix(file, ".tar.gz") {
			continue
		}

		if file == "LICENSE" {
			continue
		}

		SourceFile := fmt.Sprintf("%v/%v", TempDir, file)
		DestFile := fmt.Sprintf("/etc/suricata/rules/%v", file)
		md51 := futils.MD5File(SourceFile)
		msd52 := futils.MD5File(DestFile)
		if md51 == msd52 {
			continue
		}
		UpdatedCount++
		_ = futils.CopyFile(SourceFile, DestFile)
		UpdateLog.UpdateEvent(fmt.Sprintf("SUCCESS: Update IDS rules %v", file), futils.GetCalleRuntime())
		UPDATED = true
	}

	if UPDATED {
		UpdateLog.UpdateEvent(fmt.Sprintf("SUCCESS:updated %d files signatures", UpdatedCount), futils.GetCalleRuntime())
		notifs.SquidAdminMysql(1, fmt.Sprintf("{success} updated %d files signatures", UpdatedCount), "", futils.GetCalleRuntime(), 178)
		_ = surirules.ImportSuricataRulesToSQLite()
		surirules.Classifications()
		Reconfigure.BuildRules()
	}
	return nil
}

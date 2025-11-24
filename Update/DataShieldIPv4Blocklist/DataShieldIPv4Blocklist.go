package DataShieldIPv4Blocklist

import (
	"SuriStructs"
	"Update/IPSets"
	"Update/UpdateLog"
	"encoding/json"
	"fmt"
	"futils"
	"httpclient"
	"suricata/SuricataTools"

	"github.com/rs/zerolog/log"
)

const HTTPSource = "https://api.github.com/repos/duggytuxy/Data-Shield_IPv4_Blocklist/contents/prod_data-shield_ipv4_blocklist.txt"

type RepoFile struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	SHA         string `json:"sha"`
	Size        int64  `json:"size"`
	URL         string `json:"url"`
	HTMLURL     string `json:"html_url"`
	GitURL      string `json:"git_url"`
	DownloadURL string `json:"download_url"`
	Type        string `json:"type"`
	Content     string `json:"content"`
	Encoding    string `json:"encoding"`
	Links       struct {
		Self string `json:"self"`
		Git  string `json:"git"`
		HTML string `json:"html"`
	} `json:"_links"`
}

func Run(Reload bool) bool {

	Conf := SuriStructs.LoadConfig()
	if Conf.DataShieldIPv4Blocklist == 0 {
		futils.TouchFile(fmt.Sprintf("%v/dsipv4.list", IPSets.IprepDir))
		return false
	}
	LocalSHA := Conf.DataShieldIPv4BlocklistSHA
	err, data := httpclient.GetData(httpclient.GetAPIConf{Url: HTTPSource, Timeout: 10})
	if err != nil {
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: %v", err.Error()), futils.GetCalleRuntime())
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return false
	}
	var Github RepoFile
	err = json.Unmarshal([]byte(data), &Github)
	if err != nil {
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: %v", err.Error()), futils.GetCalleRuntime())
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return false
	}
	RemoteSHA := Github.SHA
	if LocalSHA == RemoteSHA {
		return false
	}

	err, entries := DownloadIT(Github.DownloadURL)
	if err != nil {
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: %v", err.Error()), futils.GetCalleRuntime())
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return false
	}
	UpdateLog.UpdateEvent(fmt.Sprintf("SUCCESS: Update Data-Shield IPv4 Blocklist Success with %d records", entries), futils.GetCalleRuntime())
	log.Info().Msgf("%v Update Data-Shield IPv4 Blocklist Success with %d records", futils.GetCalleRuntime(), entries)
	Conf.DataShieldIPv4BlocklistSHA = RemoteSHA
	Conf.DataShieldIPv4BlocklistRec = entries
	SuriStructs.SaveConfig(Conf)
	if !Reload {
		return true
	}
	SuricataTools.Reload()
	return true

}
func DownloadIT(url string) (error, int) {

	TmpFile := futils.TempFileName()
	defer futils.DeleteFile(TmpFile)

	err := httpclient.DownloadBigFileWithError(url, TmpFile, "")
	if err != nil {
		UpdateLog.UpdateEvent(fmt.Sprintf("ERROR: %v", err.Error()), futils.GetCalleRuntime())
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err)
		return err, 0
	}
	return IPSets.Build(IPSets.IPBuild{CategoryID: 7, SourcePath: TmpFile, OutFileName: "dsipv4.list"})
}

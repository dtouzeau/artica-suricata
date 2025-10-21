package MonitServices

import (
	"encoding/json"
	"encoding/xml"
	"futils"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/html/charset"
	"httpclient"
	"strings"
)

type Monit struct {
	XMLName  xml.Name  `xml:"monit"`
	Server   Server    `xml:"server"`
	Platform Platform  `xml:"platform"`
	Services []Service `xml:"service"`
}
type MonitJson struct {
	Services      map[string]Service `xml:"service"`
	ServicesLists []string           `xml:"available"`
}

type Server struct {
	ID          string `xml:"id"`
	Incarnation string `xml:"incarnation"`
	Version     string `xml:"version"`
	Uptime      int    `xml:"uptime"`
	Poll        int    `xml:"poll"`
	StartDelay  int    `xml:"startdelay"`
	HostName    string `xml:"localhostname"`
	ControlFile string `xml:"controlfile"`
	HTTPD       HTTPD  `xml:"httpd"`
}

type HTTPD struct {
	Address string `xml:"address"`
	Port    int    `xml:"port"`
	SSL     int    `xml:"ssl"`
}

type Platform struct {
	Name    string `xml:"name"`
	Release string `xml:"release"`
	Version string `xml:"version"`
	Machine string `xml:"machine"`
	CPU     int    `xml:"cpu"`
	Memory  int    `xml:"memory"`
	Swap    int    `xml:"swap"`
}

type Service struct {
	Type            int             `xml:"type,attr"`
	Name            string          `xml:"name"`
	CollectedSec    int             `xml:"collected_sec"`
	CollectedUSec   int             `xml:"collected_usec"`
	Status          int             `xml:"status"`
	StatusHint      int             `xml:"status_hint"`
	Monitor         int             `xml:"monitor"`
	MonitorMode     int             `xml:"monitormode"`
	OnReboot        int             `xml:"onreboot"`
	PendingAction   int             `xml:"pendingaction"`
	PID             int             `xml:"pid"`
	PPID            int             `xml:"ppid"`
	UID             int             `xml:"uid"`
	EUID            int             `xml:"euid"`
	GID             int             `xml:"gid"`
	Uptime          int             `xml:"uptime"`
	Threads         int             `xml:"threads"`
	Children        int             `xml:"children"`
	Memory          Memory          `xml:"memory"`
	CPU             CPU             `xml:"cpu"`
	FileDescriptors FileDescriptors `xml:"filedescriptors"`
	Read            IOOperations    `xml:"read"`
	Write           IOOperations    `xml:"write"`
	Port            Port            `xml:"port"`
}

type Memory struct {
	Percent       float64 `xml:"percent"`
	PercentTotal  float64 `xml:"percenttotal"`
	Kilobyte      int     `xml:"kilobyte"`
	KilobyteTotal int     `xml:"kilobytetotal"`
}

type CPU struct {
	Percent      float64 `xml:"percent"`
	PercentTotal float64 `xml:"percenttotal"`
}

type FileDescriptors struct {
	Open      int     `xml:"open"`
	OpenTotal int     `xml:"opentotal"`
	Limit     FdLimit `xml:"limit"`
}

type FdLimit struct {
	Soft int `xml:"soft"`
	Hard int `xml:"hard"`
}

type IOOperations struct {
	BytesGeneric IOBytesGeneric `xml:"bytesgeneric"`
	Bytes        IOBytes        `xml:"bytes"`
	Operations   Operations     `xml:"operations"`
}

type IOBytesGeneric struct {
	Count int `xml:"count"`
	Total int `xml:"total"`
}

type IOBytes struct {
	Count int `xml:"count"`
	Total int `xml:"total"`
}

type Operations struct {
	Count int `xml:"count"`
	Total int `xml:"total"`
}

type Port struct {
	Hostname     string  `xml:"hostname"`
	PortNumber   int     `xml:"portnumber"`
	Request      string  `xml:"request"`
	Protocol     string  `xml:"protocol"`
	Type         string  `xml:"type"`
	ResponseTime float64 `xml:"responsetime"`
}

func JsonStatus() MonitJson {

	var conf httpclient.GetAPIConf
	var monit Monit
	var Final MonitJson
	conf.Url = "http://127.0.0.1:2874/_status?format=xml"
	conf.Timeout = 2

	ok, xmlData := httpclient.GetAPI(conf)
	if ok != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), ok.Error())
		return Final
	}
	reader := strings.NewReader(xmlData)
	decoder := xml.NewDecoder(reader)
	decoder.CharsetReader = charset.NewReaderLabel

	err := decoder.Decode(&monit)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return Final
	}
	Final.Services = make(map[string]Service)

	for _, service := range monit.Services {
		if len(service.Name) < 2 {
			continue
		}
		Final.Services[service.Name] = service
		Final.ServicesLists = append(Final.ServicesLists, service.Name)
	}

	return Final
}

func ServicesStatus() string {
	var conf httpclient.GetAPIConf

	conf.Url = "http://127.0.0.1:2874/_status?format=xml"
	conf.Timeout = 2

	ok, xmlData := httpclient.GetAPI(conf)
	if ok != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), ok.Error())
		return ""
	}
	reader := strings.NewReader(xmlData)
	decoder := xml.NewDecoder(reader)
	decoder.CharsetReader = charset.NewReaderLabel

	var monit Monit
	err := decoder.Decode(&monit)
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return ""
	}

	// Convert the struct to JSON
	jsonData, err := json.MarshalIndent(monit, "", "  ")
	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		return ""
	}

	// Print the JSON output
	return string(jsonData)
}

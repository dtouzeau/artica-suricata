package SuriStructs

import (
	"encoding/json"
	"futils"
)

type OtxOptions struct {
	Enabled     int    `json:"Enabled"`
	SkipIPRep   bool   `json:"SkipIPRep"`
	SkipFileMD5 bool   `json:"SkipFileMD5"`
	ApiKey      string `json:"ApiKey"`
	DestDir     string `json:"DestDir"`
	MaxPages    int    `json:"MaxPages"`
	LastUpdate  int64  `json:"LastUpdate"`
}

type SuriDaemon struct {
	Version    string         `json:"Version"`
	LastUpdate int64          `json:"LastUpdate"`
	RulesCount int            `json:"RulesCount"`
	Categories map[string]int `json:"Categories"`
	Otx        OtxOptions     `json:"Otx"`
}

func LoadConfig() SuriDaemon {

	var f SuriDaemon
	data, _ := futils.FileGetContentsBytes("/etc/suricata/suriDaemon.json")
	_ = json.Unmarshal(data, &f)
	if f.Categories == nil {
		f.Categories = make(map[string]int)
	}
	if f.Otx.MaxPages == 0 {
		f.Otx.MaxPages = 20
	}

	return f
}
func SaveConfig(f SuriDaemon) {
	d, _ := json.Marshal(f)
	futils.CreateDir("/etc/suricata")
	_ = futils.FilePutContentsBytes("/etc/suricata/suriDaemon.json", d)
}

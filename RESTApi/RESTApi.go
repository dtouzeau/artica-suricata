package RESTApi

import (
	"CheckMem"
	"DataShieldIPv4Blocklist"
	"ImportExport"
	"LogForward"
	"PFRing"
	"PFRingIfaces"
	"Reconfigure"
	"SuriConf"
	"SuriStructs"
	"SuricataACLS"
	"Update"
	"context"
	"encoding/json"
	"fmt"
	"futils"
	"httpclient"
	"ipclass"
	"os"
	"sockets"
	"suricata"
	"suricata/SuricataTools"
	"surisock"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

func RestSuricataInstall(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	sockets.ResetTempCache()
	go suricata.Install()
	OutTrue(ctx)
}
func ReloadMe(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	futils.KillProcessHUP(os.Getpid())
	OutTrue(ctx)
}

func RestSuricataUninstall(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	sockets.ResetTempCache()
	go suricata.Uninstall()
	OutTrue(ctx)
}
func RestSuricataRestart(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	go suricata.Restart()
	OutTrue(ctx)
}
func ReconfigureAndRestart(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	go Reconfigure.ReconfigureAndRestart()
	OutTrue(ctx)
}

func ReconfigureAndWait(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	Reconfigure.Run()
	OutTrue(ctx)
}
func ReconfigureSmoothAndWait(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	_ = SuriConf.Build(false)
	OutTrue(ctx)
}

func restSuricataReconfigure(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	go Reconfigure.Run()
	OutTrue(ctx)
}
func BuildRules(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	go Reconfigure.BuildRules()
	OutTrue(ctx)
}
func BuildAdminRules(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	go Reconfigure.BuildAdminRules()
	OutTrue(ctx)
}

func ImportACL(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	file := futils.UrlDecode(fmt.Sprintf("%v", ctx.UserValue("file")))
	tfile := fmt.Sprintf("/usr/share/artica-postfix/ressources/conf/upload/%v", file)
	if !futils.FileExists(tfile) {
		OutFalse(ctx, "Invalid path "+tfile)
		return
	}
	ImportExport.Import(tfile)
	OutTrue(ctx)
}

func ExportACL(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	id := futils.StrToInt64(fmt.Sprintf("%v", ctx.UserValue("id")))
	if id == 0 {
		OutFalse(ctx, "INVALID_ID")
		return
	}
	var data struct {
		Status bool   `json:"Status"`
		Error  string `json:"Error"`
		Export string `json:"export"`
	}
	rule, err := ImportExport.Export(id)
	if err != nil {
		OutFalse(ctx, err.Error())
		return
	}
	data.Status = true
	data.Export = rule
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))

}

func GetAdminRulesIndexes(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	var data struct {
		Status bool         `json:"Status"`
		Rules  map[int]bool `json:"rules"`
	}
	data.Status = true
	data.Rules = SuricataACLS.LoadAdminRulePNumbers()
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))
}

func RestReportMemory(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	var data struct {
		Status  bool                        `json:"Status"`
		MemInfo CheckMem.MemoryRequirements `json:"MemInfo"`
	}
	data.Status = true
	data.MemInfo = CheckMem.Run()
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))
}

func restSuricataReload(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	go suricata.Reload()
	OutTrue(ctx)
}
func restSuricataUpdate(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	go func() {
		Update.Run()
	}()
	OutTrue(ctx)
}
func GlobalStats(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	var data struct {
		Status bool   `json:"Status"`
		Stats  string `json:"Stats"`
	}
	data.Status = true
	_, data.Stats = SuricataTools.DumpStats()

	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))
}

func GlobalStatus(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	var data struct {
		Status        bool                   `json:"Status"`
		Error         string                 `json:"Error"`
		Alerts        int64                  `json:"Alerts"`
		UpdateTimeOut int64                  `json:"UpdateTimeOut"`
		Events        int64                  `json:"Events"`
		EventsRefused int64                  `json:"EventsRefused"`
		Info          SuriStructs.SuriDaemon `json:"Info"`
		NDPI          bool                   `json:"NDPI"`
		Running       bool                   `json:"Running"`
		Uptime        int64                  `json:"Uptime"`
		Version       string                 `json:"Version"`
		PersoRules    bool                   `json:"PersoRules"`
	}
	data.Alerts = LogForward.AlertsCount
	data.Status = true
	data.Version = sockets.GET_INFO_STR(suricata.TokenVersion)

	PID := SuricataTools.GetPID()
	if futils.ProcessExists(PID) {
		a, _ := futils.ProcessAgeInSeconds(PID)
		data.Running = true
		data.Uptime = a
	} else {
		data.Running = false
	}
	data.PersoRules = SuriConf.IsPersoRules()
	data.Info = SuriStructs.LoadConfig()
	data.NDPI = data.Info.NDPIOK
	data.Events = LogForward.ReceivedEvents
	data.EventsRefused = LogForward.DroppedEvents
	data.UpdateTimeOut = Update.TimeToUpdate()
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))
}
func restSuricataStats(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}

	if !futils.UnixSocketExists("/run/suricata/suricata.sock") {
		OutFalse(ctx, "SOCKET_NOT_FOUND")
		return
	}

	var data struct {
		Status bool             `json:"Status"`
		Error  string           `json:"Error"`
		Info   surisock.Message `json:"Info"`
	}
	data.Status = true
	data.Info = surisock.GetStats()
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))
}
func restSuricataStatus(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}

	var data struct {
		Status  bool   `json:"Status"`
		Error   string `json:"Error"`
		Info    string `json:"Info"`
		Version string `json:"Version"`
	}

	data.Status = true
	data.Info = suricata.Status(false)
	data.Version = suricata.GetVersion()

	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))
}
func restSuricataPfRingPluging(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}

	pfringP := PFRing.PFringSoPath()

	if futils.FileExists(pfringP) {
		OutTrue(ctx)
		return
	}
	OutFalse(ctx, "{PFRING_PLUGIN_NOT_FOUND}")
}

func restSuricataPfRing(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}

	var data struct {
		Status bool   `json:"Status"`
		Error  string `json:"Error"`
		Info   string `json:"Info"`
	}

	modinfo := futils.FindProgram("modinfo")
	err, out := futils.ExecuteShell(fmt.Sprintf("%v pf_ring", modinfo))
	if err != nil {
		data.Status = false
		data.Error = out
		jsonBytes, _ := json.MarshalIndent(data, "", "  ")
		ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
		ctx.SetStatusCode(200)
		_, _ = fmt.Fprintf(ctx, string(jsonBytes))
		return
	}
	data.Status = true
	data.Info = out
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))

}
func restSuricataDisableSid(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	sid := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("sid")))

	go func() {
		err, out := futils.ExecuteShell(fmt.Sprintf("/usr/share/artica-postfix/bin/sidrule -d %v", sid))
		if err != nil {
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), out)
			}
		}
	}()
	OutTrue(ctx)
}
func IfaceList(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}

	if !futils.UnixSocketExists("/run/suricata/suricata.sock") {

		List := PFRingIfaces.Load()
		if len(List) == 0 {
			OutFalse(ctx, "NO_INTERFACE_SET")
		}

		OutFalse(ctx, "SOCKET_NOT_FOUND")
		return
	}

	zctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	Reply, err := surisock.IfaceList(zctx)

	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		if Reply != nil {
			OutFalse(ctx, string(Reply.Message))
			return
		}
		OutFalse(ctx, err.Error())
		return
	}
	var data struct {
		Status bool   `json:"Status"`
		Error  string `json:"Error"`
		Info   string `json:"Info"`
	}
	data.Status = true
	data.Info = string(Reply.Message)
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))
}
func OtxSave(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	ApiKey := fmt.Sprintf("%v", ctx.UserValue("ApiKey"))
	MaxPages := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("MaxPages")))
	OtxEnabled := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("OtxEnabled")))
	Gconf := SuriStructs.LoadConfig()
	Gconf.Otx.ApiKey = ApiKey
	Gconf.Otx.MaxPages = MaxPages
	Gconf.Otx.Enabled = OtxEnabled
	SuriStructs.SaveConfig(Gconf)
	OutTrue(ctx)
}
func SetQueueParams(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	queuepath := futils.UrlDecode(fmt.Sprintf("%v", ctx.UserValue("queuepath")))
	enabled := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("enabled")))
	Gconf := SuriStructs.LoadConfig()
	Gconf.UseQueueFailed = enabled
	Gconf.QueueFailed = queuepath
	SuriStructs.SaveConfig(Gconf)
	OutTrue(ctx)
}
func SetNDPIParams(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	enabled := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("enabled")))
	Gconf := SuriStructs.LoadConfig()
	Gconf.NDPIEnabled = enabled
	log.Warn().Msgf("%v Edit NDPI integration to %v", futils.GetCalleRuntime(), enabled)
	SuriStructs.SaveConfig(Gconf)
	go Reconfigure.ReconfigureAndRestart()
	OutTrue(ctx)
}
func SetWazuhEnable(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	enabled := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("enabled")))
	Gconf := SuriStructs.LoadConfig()
	Gconf.Wazuh.Enabled = enabled
	log.Warn().Msgf("%v Edit Wazuh integration to %v", futils.GetCalleRuntime(), enabled)
	SuriStructs.SaveConfig(Gconf)
	go func() {
		err := httpclient.RestAPIUnix("/wazuh/restart")
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
	}()
	go LogForward.ReloadConfig()
	OutTrue(ctx)
}
func SetFileBeatEnable(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	enabled := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("enabled")))
	Gconf := SuriStructs.LoadConfig()
	Gconf.Filebeat.Enabled = enabled
	if len(Gconf.Filebeat.UnixSocket) < 3 {
		Gconf.Filebeat.UnixSocket = "/run/filebeat.sock"
	}
	log.Warn().Msgf("%v Edit Filebeat integration to %v", futils.GetCalleRuntime(), enabled)
	SuriStructs.SaveConfig(Gconf)
	go LogForward.ReloadConfig()
	OutTrue(ctx)
}

func SetHomeNetParams(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	net := futils.UrlDecode(fmt.Sprintf("%v", ctx.UserValue("net")))
	negative := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("negative")))
	enabled := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("enabled")))
	Gconf := SuriStructs.LoadConfig()
	if !ipclass.IsValidIPorCDIRorRange(net) {
		log.Error().Msgf("%v %v %v", futils.GetCalleRuntime(), net, "Invalid IP or CIDR or Range")
		return
	}
	log.Warn().Msgf("%v Edit network for HOME_NET %v negative=%d, enabled=%d", futils.GetCalleRuntime(), net, negative, enabled)
	Gconf.HomeNets[net] = SuriStructs.HomeNets{Negative: negative, Enabled: enabled}
	SuriStructs.SaveConfig(Gconf)
	go Reconfigure.Smooth()
	OutTrue(ctx)
}
func DelHomeNetParams(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	net := futils.UrlDecode(fmt.Sprintf("%v", ctx.UserValue("net")))
	log.Warn().Msgf("%v Removed network from HOME_NET %v", futils.GetCalleRuntime(), net)
	Gconf := SuriStructs.LoadConfig()
	delete(Gconf.HomeNets, net)
	SuriStructs.SaveConfig(Gconf)
	go Reconfigure.Smooth()
	OutTrue(ctx)
}

func SetLogTypeParams(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	key := futils.UrlDecode(fmt.Sprintf("%v", ctx.UserValue("key")))
	value := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("value")))
	Gconf := SuriStructs.LoadConfig()
	Gconf.EveLogsType[key] = value
	SuriStructs.SaveConfig(Gconf)
	go func() {
		_ = SuriConf.Build(false)
	}()
	OutTrue(ctx)
}

func SetDataShieldIPv4Blocklist(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	enabled := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("enabled")))
	Gconf := SuriStructs.LoadConfig()
	Gconf.DataShieldIPv4Blocklist = enabled
	SuriStructs.SaveConfig(Gconf)
	if enabled == 1 {
		go DataShieldIPv4Blocklist.Run(true)
	}
	OutTrue(ctx)
}

func AclsExplains(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	go func() {
		SuricataACLS.SetACLsExplain()
		SuricataACLS.BuildACLs()
	}()
	OutTrue(ctx)
}
func RulesStats(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}

	Data := surisock.RuleStats()
	jsonBytes, _ := json.MarshalIndent(Data, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))
}

func IfaceState(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	iface := fmt.Sprintf("%v", ctx.UserValue("iface"))

	var data struct {
		Status bool   `json:"Status"`
		Error  string `json:"Error"`
		Info   string `json:"Info"`
	}

	if iface == "" {
		OutFalse(ctx, "No interface provided")
		return
	}

	if !futils.UnixSocketExists("/run/suricata/suricata.sock") {
		OutFalse(ctx, "SOCKET_NOT_FOUND")
		return
	}

	zctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	Reply, err := surisock.IfaceStat(zctx, iface)

	if err != nil {
		log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		if Reply != nil {
			OutFalse(ctx, string(Reply.Message))
			return
		}
		OutFalse(ctx, err.Error())
		return
	}

	data.Status = true
	data.Info = string(Reply.Message)
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))
}

func restSuricataEnableSid(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	sid := futils.StrToInt(fmt.Sprintf("%v", ctx.UserValue("sid")))

	go func() {
		err, out := futils.ExecuteShell(fmt.Sprintf("/usr/share/artica-postfix/bin/sidrule -e %v", sid))
		if err != nil {
			if err != nil {
				log.Error().Msgf("%v %v", futils.GetCalleRuntime(), out)
			}
		}
	}()
	OutTrue(ctx)
}

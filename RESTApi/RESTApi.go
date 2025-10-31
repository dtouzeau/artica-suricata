package RESTApi

import (
	"LogForward"
	"Reconfigure"
	"SuriStructs"
	"Update"
	"context"
	"encoding/json"
	"fmt"
	"futils"
	"os"
	"sockets"
	"suricata"
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
func GlobalStatus(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	var data struct {
		Status        bool                   `json:"Status"`
		Error         string                 `json:"Error"`
		Alerts        int64                  `json:"Alerts"`
		UpdateTimeOut int64                  `json:"UpdateTimeOut"`
		Info          SuriStructs.SuriDaemon `json:"Info"`
	}
	data.Alerts = LogForward.AlertsCount
	data.Status = true
	data.Info = SuriStructs.LoadConfig()
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

	if !futils.FileExists("/usr/lib/suricata/pfring.so") {
		OutFalse(ctx, "{PFRING_PLUGIN_NOT_FOUND}")
		return
	}
	OutTrue(ctx)
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

func IfaceState(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}
	iface := fmt.Sprintf("%v", ctx.UserValue("iface"))
	if iface == "" {
		OutFalse(ctx, "No interface provided")
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

package RESTApi

import (
	"encoding/json"
	"fmt"
	"futils"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
	"os"
	"sockets"
	"suricata"
	"suricata/SuricataTools"
	"suricata/SuricataUpdates"
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
	go suricata.Reconfigure()
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
		err := SuricataUpdates.Update()
		if err != nil {

		}
	}()
	OutTrue(ctx)
}
func restSuricataStats(ctx *fasthttp.RequestCtx) {
	if !RestRestricts(ctx) {
		return
	}

	var data struct {
		Status bool   `json:"Status"`
		Error  string `json:"Error"`
		Info   string `json:"Info"`
	}
	data.Status = true
	_, data.Info = SuricataTools.DumpStats()
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

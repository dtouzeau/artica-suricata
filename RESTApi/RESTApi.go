package RESTApi

import (
	"context"
	"encoding/json"
	"fmt"
	"futils"
	"os"
	"sockets"
	"suricata"
	"suricata/SuricataUpdates"
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

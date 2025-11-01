package RESTApi

import (
	"bufio"
	"fmt"
	"futils"
	"os"
	"time"

	"github.com/fasthttp/router"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/pprofhandler"
)

var HTTPlocalServer *fasthttp.Server

const Socket = "/run/suricata-service.sock"

func Start() {

	if HTTPlocalServer != nil {
		Stop()
	}

	futils.DeleteFile(Socket)
	futils.CreateDir(futils.DirName(Socket))
	futils.ChownFolder(futils.DirName(Socket), "www-data", "www-data")
	r := buildRouter()
	log.Info().Msgf("%v Version [%v]", futils.GetCalleRuntime(), version)
	go func() {
		HTTPlocalServer = &fasthttp.Server{
			Handler:            r.Handler,
			MaxRequestBodySize: 500 * 1024 * 1024, // Set the maximum request body size to 10 MB
		}
		log.Debug().Msgf("[START]: %v Starting Web API service on the Unix %v interface", futils.GetCalleRuntime(), Socket)
		if err := HTTPlocalServer.ListenAndServeUNIX(Socket, 0777); err != nil {
			log.Error().Msgf("[START]: %v Unable to start the REST API service on %v (%v)", futils.GetCalleRuntime(), err.Error(), Socket)
		}

	}()

	err := futils.ChownFileDetails(Socket, "www-data")
	if err != nil {
		log.Error().Msgf(fmt.Sprintf("[START]: %v error chown  %v (%v)", futils.GetCalleRuntime(), Socket, err.Error()))
	}
}

func Stop() {
	if HTTPlocalServer != nil {
		_ = HTTPlocalServer.Shutdown()
		HTTPlocalServer = nil
	}
}

func logRequest(handler fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		start := time.Now()

		handler(ctx)
		duration := time.Since(start)
		sec := duration.Seconds()
		Warn := ""
		if sec > 1 {
			Warn = fmt.Sprintf(" [WARN !] %s", Warn)
		}
		text := fmt.Sprintf("[%s] suricata-service %s %s - %d (%.6fs) %v\n",
			ctx.RemoteIP(),
			ctx.Method(),
			ctx.RequestURI(),
			ctx.Response.StatusCode(),
			duration.Seconds(), Warn,
		)
		file, err := os.OpenFile("/var/log/articarest.query.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer func(file *os.File) {
			_ = file.Close()
		}(file)
		if err != nil {
			return
		}
		writer := bufio.NewWriterSize(file, 4096)
		defer func(writer *bufio.Writer) {
			_ = writer.Flush()
		}(writer)
		_, _ = writer.WriteString(text)
	}
}

func buildRouter() *router.Router {
	r := router.New()
	r.GET("/reload", logRequest(ReloadMe))
	r.GET("/status", logRequest(GlobalStatus))
	r.GET("/build/rules", logRequest(BuildRules))
	r.GET("/suricata/install", logRequest(RestSuricataInstall))
	r.GET("/suricata/uninstall", logRequest(RestSuricataUninstall))
	r.GET("/suricata/restart", logRequest(RestSuricataRestart))
	r.GET("/suricata/status", logRequest(restSuricataStatus))
	r.GET("/suricata/reconfigure", logRequest(restSuricataReconfigure))
	r.GET("/suricata/reload", logRequest(restSuricataReload))
	r.GET("/suricata/sid/disable/{sid}", logRequest(restSuricataDisableSid))
	r.GET("/suricata/sid/enable/{sid}", logRequest(restSuricataEnableSid))
	r.GET("/iface/state/{iface}", logRequest(IfaceState))
	r.GET("/iface/list", logRequest(IfaceList))
	r.GET("/suricata/update", logRequest(restSuricataUpdate))
	r.GET("/suricata/pfring", logRequest(restSuricataPfRing))
	r.GET("/suricata/stats", logRequest(restSuricataStats))
	r.GET("/suricata/pfring-plugin", logRequest(restSuricataPfRingPluging))
	r.GET("/debug/pprof/{profile:*}", logRequest(pprofhandler.PprofHandler))
	r.GET("/otx/save/{ApiKey}/{MaxPages}/{OtxEnabled}", logRequest(OtxSave))
	r.GET("/config/queue/{queuepath}/{enabled}", logRequest(SetQueueParams))
	r.GET("/rules/stats", logRequest(RulesStats))
	r.GET("/acls/explains", logRequest(AclsExplains))

	return r
}

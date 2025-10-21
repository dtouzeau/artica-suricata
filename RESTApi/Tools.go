package RESTApi

import (
	"encoding/json"
	"fmt"
	"futils"
	"ipclass"
	"net"
	"sockets"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

var version string = "1.0.0"

func OutTrue(ctx *fasthttp.RequestCtx) {
	var Out struct {
		Status  bool   `json:"Status"`
		Info    string `json:"Info"`
		Error   string `json:"Error"`
		Version string `json:"Version"`
	}
	Out.Version = version
	Out.Status = true
	jsonBytes, _ := json.MarshalIndent(Out, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))
}
func OutFalse(ctx *fasthttp.RequestCtx, ErrStr string) {
	var Out struct {
		Status bool   `json:"Status"`
		Info   string `json:"Info"`
		Error  string `json:"Error"`
	}
	Out.Status = false
	Out.Error = ErrStr
	jsonBytes, _ := json.MarshalIndent(Out, "", "  ")
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.SetStatusCode(200)
	_, _ = fmt.Fprintf(ctx, string(jsonBytes))
}
func RestRestricts(ctx *fasthttp.RequestCtx) bool {
	clientIP := GetUserIP(ctx)
	clientIPSrc := clientIP
	ActiveDirectoryRestRestrict := sockets.GET_INFO_STR("ActiveDirectoryRestRestrict")
	via := ctx.Request.Header.Peek("X-ViaConsole")
	if via != nil {
		clientIP = string(via)
	}

	if !ipclass.IsIPAddress(clientIP) {
		clientIP = ipclass.ExtractIPFromIpPort(clientIP)
	}

	var allowedIPs []string

	if RestRestrictsIsLocal(clientIP) {
		return true
	}
	log.Info().Msgf("%v [%v]", futils.GetCalleRuntime(), clientIP)
	if len(ActiveDirectoryRestRestrict) > 5 {
		allowedIPs = strings.Split(ActiveDirectoryRestRestrict, "\n")
	}

	log.Debug().Msg(fmt.Sprintf("[%v]: RestRestricts: Authorized clients = %v items", clientIP, len(allowedIPs)))

	if len(allowedIPs) == 0 {
		if isRestrictsAPIKey(ctx) {
			return true
		}
		allowedIPs = []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8"}
	}

	for _, allowedIP := range allowedIPs {
		_, ipNet, err := net.ParseCIDR(allowedIP)
		log.Debug().Msg(fmt.Sprintf("[%v]: Checking Allowed IP: %v -> %v", clientIP, allowedIP, ipNet))

		if err != nil {
			if strings.TrimSpace(allowedIP) == clientIP {
				return RestRestrictsAPIKey(ctx)
			}
			log.Debug().Msg(fmt.Sprintf("RestRestricts: %v != [%v] [FALSE]", allowedIP, clientIP))

		} else {
			parsedIP := net.ParseIP(clientIP)
			if parsedIP != nil && ipNet.Contains(parsedIP) {
				return RestRestrictsAPIKey(ctx)
			}
			log.Debug().Msg(fmt.Sprintf("RestRestricts: %v != [%v] [FALSE]", allowedIP, clientIP))
		}
	}
	log.Warn().Msgf("%v Address [%v/%v] is not allowed", futils.GetCalleRuntime(), clientIPSrc, clientIP)
	ctx.SetStatusCode(403)

	var data struct {
		Status bool   `json:"Status"`
		Error  string `json:"Error"`
		Info   string `json:"Info"`
	}
	data.Status = false
	data.Error = "Authentication failed"
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	ctx.Error(string(jsonBytes), 403)
	return false
}

func GetUserIP(httpServer *fasthttp.RequestCtx) string {
	var userIP string

	userIP = fmt.Sprintf("%s", httpServer.RemoteAddr())
	if userIP == "@" {
		userIP = "127.0.0.1"
	}
	if userIP == "127.0.0.1" || userIP == "::1" {
		return "127.0.0.1"
	}

	zHeaders := RestParseHeaders(httpServer)
	Potentials := []string{"Remote-Addr", "HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP", "CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"}

	for _, Potential := range Potentials {
		small := strings.ToLower(Potential)
		value := zHeaders[small]
		if len(value) > 0 {
			return value
		}
	}
	return userIP
}
func isRestrictsAPIKey(ctx *fasthttp.RequestCtx) bool {
	ActiveDirectoryRestShellPass := sockets.GET_INFO_STR("ActiveDirectoryRestShellPass")
	if len(ActiveDirectoryRestShellPass) == 0 {
		log.Debug().Msg("RestRestrictsAPIKey: API KEY is null, [FALSE]")
		return false
	}

	encodedToken := GetTokens(ctx)

	if ActiveDirectoryRestShellPass == encodedToken {
		return true
	}
	log.Debug().Msg(fmt.Sprintf("isRestrictsAPIKey: BAD KEY"))
	return false
}

func RestRestrictsAPIKey(ctx *fasthttp.RequestCtx) bool {
	ActiveDirectoryRestShellPass := sockets.GET_INFO_STR("ActiveDirectoryRestShellPass")
	if len(ActiveDirectoryRestShellPass) == 0 {
		log.Debug().Msg("RestRestrictsAPIKey: ActiveDirectoryRestShellPass is null, [TRUE]")
		return true
	}
	encodedToken := GetTokens(ctx)
	if ActiveDirectoryRestShellPass == encodedToken {
		return true
	}
	log.Debug().Msg(fmt.Sprintf("RestRestrictsAPIKey: ActiveDirectoryRestShellPass bad password, [FALSE]"))
	log.Warn().Msg(fmt.Sprintf("X-Auth-Token bad password"))
	ctx.SetStatusCode(403)
	ctx.Error("Forbidden", 403)
	return false

}
func GetTokens(ctx *fasthttp.RequestCtx) string {
	zHeaders := RestParseHeaders(ctx)
	if len(zHeaders["x-auth-token"]) > 2 {
		return zHeaders["x-auth-token"]
	}
	if len(zHeaders["x-api-key"]) > 2 {
		return zHeaders["x-api-key"]
	}
	return ""
}

func RestParseHeaders(ctx *fasthttp.RequestCtx) map[string]string {
	zHeaders := make(map[string]string)
	ctx.Request.Header.VisitAll(func(key, value []byte) {
		zkey := string(key)
		zkey = strings.TrimSpace(strings.ToLower(zkey))
		zHeaders[zkey] = string(value)
		//log.Debug().Msg(fmt.Sprintf("RestParseHeaders: [%v]==[%v]", zkey, zHeaders[zkey]))
	})
	return zHeaders
}
func RestRestrictsIsLocal(clientIP string) bool {
	var LocalIPaddresses []string
	if clientIP == "127.0.0.1" || clientIP == "::1" {
		return true
	}
	if futils.FileExists("/etc/artica-postfix/MICROINSTALLED") {
		if strings.HasPrefix(clientIP, "192.176") {
			return true
		}
	}
	addresses, err := net.InterfaceAddrs()
	if err == nil {
		for _, address := range addresses {
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil { // check for IPv4 address
					LocalIPaddresses = append(LocalIPaddresses, ipnet.IP.String())
				}
			}
		}
	}

	for _, ipaddr := range LocalIPaddresses {
		if clientIP == ipaddr {
			return true
		}
	}
	return false
}

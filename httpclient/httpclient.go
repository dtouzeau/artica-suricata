package httpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"futils"
	"io"
	"ipclass"
	"log/syslog"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sockets"
	"strconv"
	"strings"
	"time"

	"github.com/leeqvip/gophp"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
	"gopkg.in/ini.v1"
)

type HeadersResults struct {
	Headers      map[string]string
	Error        error
	ErrorDetails string
	Result       string
}

var FailedReport []string
var regexPattern = `HOTFIX.*?\].*?([0-9\-]+)`
var re = regexp.MustCompile(regexPattern)

type UploadConfig struct {
	Url       string
	FilePath  string
	FieldName string
	FileName  string
	UseDirect bool
	APIKey    string
	FormData  map[string]string
}
type DownloadConfig struct {
	Url               string
	TargetFile        string
	UseDirect         bool
	OutgoingInterface string
}

type Header struct {
	Key   string
	Value string
}
type GetAPIConf struct {
	LocalAddr     string
	Url           string
	Timeout       int
	APIKey        string
	DoNotUseProxy bool
	ForceUseProxy bool
}
type DownloadPercent struct {
	Total        int64
	Downloaded   int
	Progressfile string
}

type ProxySettings struct {
	Enabled             int
	Proxyaddr           string
	Username            string
	Password            string
	LocalInterface      string
	UserAgent           string
	TargetHost          string
	AddHeader           Header
	TimeOut             int
	DoNotFollowRedirect bool
	UrlPattern          string
	TargetURL           string
	ForDoh              bool
	http2               bool
	UriPath             string
	Headers             []Header
}
type ProgressWriter struct {
	Total     int64
	Completed int64
}

var NoCentPourcent bool
var progressF string
var TempPc int
var DownloadErr string

func UpdateRepoBaseURI() string {
	ArticaRepoSSL := sockets.GET_INFO_INT("ArticaRepoSSL")
	uri := "http://articatech.net"
	if ArticaRepoSSL == 1 {
		uri = "https://www.articatech.com"
	}
	return uri
}

func PProxyReplaceChars(pattern string) string {
	pattern = strings.ReplaceAll(pattern, "@", "%40")
	pattern = strings.ReplaceAll(pattern, ":", "%3A")
	pattern = strings.ReplaceAll(pattern, "!", "%21")
	pattern = strings.ReplaceAll(pattern, "#", "%23")
	pattern = strings.ReplaceAll(pattern, "$", "%24")
	return pattern

}

func parseInterfaceOrIP(Str string) string {
	if len(Str) < 3 {
		return ""
	}
	if !ipclass.IsIPAddress(Str) {
		log.Debug().Msgf("%v LocalInterface=%v is not an IP address", futils.GetCalleRuntime(), Str)
		if !ipclass.IsInterfaceExists(Str) {
			log.Warn().Msgf("%v %v unable to find the local interface", futils.GetCalleRuntime(), Str)
			return ""
		}
		IpAddr := ipclass.InterfaceToIPv4(Str)
		log.Debug().Msgf("%v LocalInterface=%v = %v", futils.GetCalleRuntime(), Str, IpAddr)
		if IpAddr == "127.0.0.1" || IpAddr == "::1" {
			return ""
		}
		return IpAddr
	}

	if !ipclass.IsLocalIPAddress(Str) {
		log.Warn().Msgf("%v %v unable to find the local ip address", futils.GetCalleRuntime(), Str)
		return ""
	}
	return Str
}

func InitClient(proxy ProxySettings) (*http.Client, error) {
	Timeout := proxy.TimeOut

	if !proxy.ForDoh {
		if Timeout < 20 {
			Timeout = 20
		}
	}

	TimeOutDuration := time.Duration(Timeout) * time.Second
	dialer := &net.Dialer{
		Timeout:   TimeOutDuration,
		KeepAlive: TimeOutDuration,
	}

	proxy.LocalInterface = parseInterfaceOrIP(proxy.LocalInterface)

	if len(proxy.LocalInterface) > 3 {
		localAddr := &net.TCPAddr{
			IP: net.ParseIP(proxy.LocalInterface),
		}

		dialer = &net.Dialer{
			Timeout:   TimeOutDuration,
			KeepAlive: TimeOutDuration,
			LocalAddr: localAddr,
		}
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	if proxy.Enabled == 0 {
		transport := &http.Transport{
			DisableKeepAlives: true,
			MaxIdleConns:      0,
			TLSClientConfig:   tlsConfig,
			DialContext:       dialer.DialContext,
		}
		if err := http2.ConfigureTransport(transport); err != nil {
			log.Error().Msgf("%v Failed to configure HTTP/2: %v", futils.GetCalleRuntime(), err)
		}

		client := &http.Client{
			Timeout:   TimeOutDuration,
			Transport: transport,
		}

		if proxy.DoNotFollowRedirect {
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		}
		return client, nil
	}

	if !strings.HasPrefix(proxy.Proxyaddr, "http://") {
		proxy.Proxyaddr = "http://" + proxy.Proxyaddr
	}

	proxyURL, err := url.Parse(proxy.Proxyaddr)
	if err != nil {
		errStr := fmt.Sprintf("InitClient(): Failed to Parse Proxy settings %v", err.Error())
		return nil, errors.New(errStr)
	}
	if len(proxy.Username) > 2 {
		proxyURL.User = url.UserPassword(proxy.Username, proxy.Password)

		transport := &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DialContext:       dialer.DialContext,
			TLSClientConfig:   tlsConfig,
			DisableKeepAlives: true,
			MaxIdleConns:      0,
		}

		client := &http.Client{
			Timeout:   TimeOutDuration,
			Transport: transport,
		}
		if err := http2.ConfigureTransport(transport); err != nil {
			log.Error().Msgf("%v Failed to configure HTTP/2: %v", futils.GetCalleRuntime(), err)
		}

		return client, nil

	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		MaxIdleConns:      0,
		Proxy:             http.ProxyURL(proxyURL),
		DialContext:       dialer.DialContext,
		TLSClientConfig:   tlsConfig,
	}
	_ = http2.ConfigureTransport(transport)
	client := &http.Client{
		Timeout:   TimeOutDuration,
		Transport: transport,
	}
	return client, nil

}
func RestAPIUnixGet(endpoint string) (error, string) {
	socketPath := "/usr/share/artica-postfix/bin/run/articarest.sock"
	transport := &http.Transport{
		DisableKeepAlives: true,
		MaxIdleConns:      0,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	client := &http.Client{
		Transport: transport,
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost%v", endpoint), nil)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error creating request: %v", futils.GetCalleRuntime(), err)), ""
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error sending request: %v", futils.GetCalleRuntime(), err)), ""
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%v Error reading response body: %v", futils.GetCalleRuntime(), err), string(body)
	}

	return nil, string(body)

}
func QueryToMap(formString string) (map[string]interface{}, error) {

	result := make(map[string]interface{})
	values, err := url.ParseQuery(formString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse form string: %v", err)
	}

	for key, vals := range values {
		if len(vals) > 0 {
			val := vals[0]
			result[key] = futils.UrlEncode(val)
		}
	}
	return result, nil
}
func RestAPIUnixPut(endpoint string, variables map[string]interface{}) (error, string) {
	// Unix socket path
	socketPath := "/usr/share/artica-postfix/bin/run/articarest.sock"

	transport := &http.Transport{
		DisableKeepAlives: true,
		MaxIdleConns:      0,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	client := &http.Client{
		Transport: transport,
	}

	formData := url.Values{}
	for key, value := range variables {
		switch v := value.(type) {
		case []string:

			for _, item := range v {
				formData.Add(fmt.Sprintf("%s[]", key), item)
			}
		case string:

			formData.Set(key, v)
		default:
			// Handle other types by converting to string
			formData.Set(key, fmt.Sprintf("%v", v))
		}
	}

	// Encode the form data as a string
	bodyData := formData.Encode()

	req, err := http.NewRequest("PUT", fmt.Sprintf("http://localhost%v", endpoint), bytes.NewBufferString(bodyData))
	if err != nil {
		return fmt.Errorf("%v Error creating request: %v", futils.GetCalleRuntime(), err), ""
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%v Error sending request: %v", futils.GetCalleRuntime(), err), ""
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%v Error reading response body: %v", futils.GetCalleRuntime(), err), string(body)
	}

	return nil, string(body)
}
func RestAPIUnix(endpoint string) error {
	socketPath := "/usr/share/artica-postfix/bin/run/articarest.sock"
	transport := &http.Transport{
		DisableKeepAlives: true,
		MaxIdleConns:      0,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	// Create an HTTP client with the custom transport
	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second, // Set 10-second timeout
	}

	// Create a new HTTP request
	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost%v", endpoint), nil)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error creating request: %v", futils.GetCalleRuntime(), err))
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error sending request: %v", futils.GetCalleRuntime(), err))
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()

	}(resp.Body)

	return nil

}
func NfQueueAPIUnix(endpoint string) error {
	socketPath := "/run/nfqueue.sock"
	transport := &http.Transport{
		DisableKeepAlives: true,
		MaxIdleConns:      0,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	// Create an HTTP client with the custom transport
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second, // Set 10-second timeout
	}

	// Create a new HTTP request
	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost%v", endpoint), nil)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error creating request: %v", futils.GetCalleRuntime(), err))
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error sending request: %v", futils.GetCalleRuntime(), err))
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()

	}(resp.Body)

	return nil

}
func NginxAPIUnix(endpoint string) error {
	socketPath := "/run/reverse-proxy.sock"
	transport := &http.Transport{
		DisableKeepAlives: true,
		MaxIdleConns:      0,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	// Create an HTTP client with the custom transport
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second, // Set 10-second timeout
	}

	// Create a new HTTP request
	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost%v", endpoint), nil)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error creating request: %v", futils.GetCalleRuntime(), err))
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error sending request: %v", futils.GetCalleRuntime(), err))
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()

	}(resp.Body)

	return nil

}
func SuricataAPIUnix(endpoint string) error {
	socketPath := "/run/suricata-service.sock"
	transport := &http.Transport{
		DisableKeepAlives: true,
		MaxIdleConns:      0,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	// Create an HTTP client with the custom transport
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second, // Set 10-second timeout
	}

	// Create a new HTTP request
	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost%v", endpoint), nil)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error creating request: %v", futils.GetCalleRuntime(), err))
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error sending request: %v", futils.GetCalleRuntime(), err))
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()

	}(resp.Body)

	return nil

}

func ReputationInjecterAPIUnix(endpoint string) error {
	socketPath := "/run/reputation-injecter.sock"
	transport := &http.Transport{
		DisableKeepAlives: true,
		MaxIdleConns:      0,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	// Create an HTTP client with the custom transport
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second, // Set 10-second timeout
	}

	// Create a new HTTP request
	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost%v", endpoint), nil)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error creating request: %v", futils.GetCalleRuntime(), err))
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("%v Error sending request: %v", futils.GetCalleRuntime(), err))
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()

	}(resp.Body)

	return nil

}

func GetAllHeader(url string) (error, map[string]string) {
	pp := LoadProxySettings()
	H := Headers(url, pp)
	return H.Error, H.Headers
}
func Headers(fileURL string, proxy ProxySettings) HeadersResults {
	var H HeadersResults
	H.Headers = make(map[string]string)
	client, err := InitClient(proxy)

	req, err := http.NewRequest("HEAD", fileURL, nil)

	var curl []string

	curl = append(curl, "curl --verbose --head --insecure")

	if err != nil {
		H.Error = fmt.Errorf("error creating HEAD request: %v", err)
		return H
	}

	if len(proxy.TargetHost) > 3 {
		req.Host = proxy.TargetHost
		curl = append(curl, fmt.Sprintf("-H \"Host: %v\"", req.Host))
	}
	if len(proxy.UserAgent) == 0 {
		proxy.UserAgent = "Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/120.0"
	}

	if len(proxy.UserAgent) > 3 {
		cmdcurl := strings.ReplaceAll(proxy.UserAgent, `"`, `\"`)
		curl = append(curl, fmt.Sprintf("--user-agent \"%v\"", cmdcurl))
		req.Header.Set("User-Agent", proxy.UserAgent)
	}

	if len(proxy.AddHeader.Key) > 2 {
		req.Header.Set(proxy.AddHeader.Key, proxy.AddHeader.Value)
	}

	curl = append(curl, fileURL)
	CurlCMD := strings.Join(curl, " ")
	resp, err := client.Do(req)
	if err != nil {
		errstr := fmt.Sprintf("URL:[%v]<br>Host:[%v]<br>Error [<strong>%v</strong>]<br>use Curl to verify this error: <textarea style='width:99%%;height:50px'>%v</textarea>", fileURL, proxy.TargetHost, err.Error(), CurlCMD)
		log.Error().Msg(fmt.Sprintf(":[%v] Host:[%v] Error [%v]", fileURL, proxy.TargetHost, err.Error()))
		H.ErrorDetails = errstr
		H.Error = err
		return H

	}

	for key, values := range resp.Header {
		for _, value := range values {
			H.Headers[strings.ToUpper(key)] = value
		}
	}
	_ = resp.Body.Close()
	return H

}
func HeadersReturnCode5x(fileURL string, proxy ProxySettings) (error, map[string]string) {

	client, err := InitClient(proxy)
	var results = make(map[string]string)
	req, err := http.NewRequest("HEAD", fileURL, nil)

	if err != nil {
		return errors.New(fmt.Sprintf("error creating HEAD request: %v", err)), results

	}

	if len(proxy.TargetHost) > 3 {
		req.Host = proxy.TargetHost
	}
	if len(proxy.UserAgent) == 0 {
		proxy.UserAgent = "Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/120.0"
	}

	if len(proxy.UserAgent) > 3 {
		req.Header.Set("User-Agent", proxy.UserAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		errstr := fmt.Sprintf("URL:[%v]<br>Host:[%v]<br>Error [<strong>%v</strong>]", fileURL, proxy.TargetHost, err.Error())
		log.Error().Msg(fmt.Sprintf(":[%v] Host:[%v] Error [%v]", fileURL, proxy.TargetHost, err.Error()))
		return errors.New(errstr), results
	}
	statusCode := resp.StatusCode
	results[strings.ToUpper("HTTP_CODE")] = fmt.Sprintf("%v", statusCode)
	for key, values := range resp.Header {
		for _, value := range values {
			results[strings.ToUpper(key)] = value
			//if gbdebug {
			//	fmt.Printf("%s: %s\n", key, value)
			//}
		}
	}

	_ = resp.Body.Close()
	if statusCode == 500 {
		return fmt.Errorf("error return 500 status code"), results
	}
	if statusCode == 501 {
		return fmt.Errorf("error return 501 status code"), results
	}
	if statusCode == 502 {
		return fmt.Errorf("error return 502 status code"), results
	}

	return nil, results

}
func GetContentAPIParams(Params GetAPIConf) (bool, string) {

	var pps ProxySettings

	fileURL := Params.Url

	if Params.DoNotUseProxy {
		pps.Enabled = 0
	}
	client, err := InitClient(pps)
	if err != nil {
		log.Error().Msgf("%v %v: Initialization failed %v", futils.GetCalleRuntime(), fileURL, err.Error())
		return false, ""
	}
	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v %v: Error creating request: %v", futils.GetCalleRuntime(), fileURL, err.Error()))
		return false, ""
	}
	if len(pps.UserAgent) > 3 {
		req.Header.Set("User-Agent", pps.UserAgent)
	}
	if len(pps.AddHeader.Key) > 2 {
		req.Header.Set(pps.AddHeader.Key, pps.AddHeader.Value)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Error().Msgf("%v %v: Failed to send GET request %v", futils.GetCalleRuntime(), fileURL, err.Error())
		return false, ""
	}
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		log.Error().Msgf("%v %v: Failed to retrieve file information %v", futils.GetCalleRuntime(), fileURL, resp.Status)
		return false, ""
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Msgf("%v %v: Failed to retrieve body information %v", futils.GetCalleRuntime(), fileURL, resp.Status)
		return false, ""
	}
	return true, string(bodyBytes)
}

type ContentApiResults struct {
	Status bool   `json:"Status"`
	Data   string `json:"Data"`
	Error  string `json:"error"`
}

func GetContentAPI(fileURL string) ContentApiResults {

	var pps ProxySettings
	if strings.HasPrefix(fileURL, "direct:") {
		pps.Enabled = 0
		fileURL = strings.ReplaceAll(fileURL, "direct:", "")
	}

	pps.Enabled = 0
	client, err := InitClient(pps)
	if err != nil {
		log.Error().Msgf("%v %v: Initialization failed %v", futils.GetCalleRuntime(), fileURL, err.Error())
		return ContentApiResults{Status: false, Error: fmt.Sprintf("Initialization failed %v", err.Error())}
	}
	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		log.Error().Msgf("%v %v: Error creating request: %v", futils.GetCalleRuntime(), fileURL, err.Error())
		return ContentApiResults{Status: false, Error: fmt.Sprintf("Error creating request: %v", err.Error())}
	}
	if len(pps.UserAgent) > 3 {
		req.Header.Set("User-Agent", pps.UserAgent)
	}
	if len(pps.AddHeader.Key) > 2 {
		req.Header.Set(pps.AddHeader.Key, pps.AddHeader.Value)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Error().Msgf("%v %v Failed to send GET request %v", futils.GetCalleRuntime(), fileURL, err.Error())
		return ContentApiResults{Status: false, Error: fmt.Sprintf("Failed to send GET request: %v", err.Error())}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		log.Error().Msgf(fmt.Sprintf("%v %v Bad Status code %v", futils.GetCalleRuntime(), fileURL, resp.Status))
		return ContentApiResults{Status: false, Error: fmt.Sprintf("Bad Status code %v", resp.Status)}
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Msgf("%v %v Failed to retrieve body information %v", futils.GetCalleRuntime(), fileURL, err.Error())
		return ContentApiResults{Status: false, Error: fmt.Sprintf("Failed to retrieve body information %v", err.Error())}
	}
	return ContentApiResults{Status: true, Data: string(bodyBytes)}
}

type Httpinfos struct {
	ContentType string
	StatusCode  int
	BodySize    int
	RedirectURL string
	UrlPath     string
	Extension   string
}

func LogQueries(url string, function string) {
	if strings.Contains(url, "127.0.0.1:") {
		return
	}

	filename := "/var/log/artica.queries.log"
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)

	sdate := time.Now().Format("2006-01-02 15:04:05")
	pid := os.Getpid()
	_, _ = f.WriteString(fmt.Sprintf("%v [%d] articarest: %v: %v\n", sdate, pid, function, url))
}

func GetContent(settings ProxySettings) (error, string) {

	client, err := InitClient(settings)
	Targeturl := strings.TrimSpace(settings.TargetURL)
	if err != nil {
		return fmt.Errorf("%v:%v Initialization failed %v", futils.GetCalleRuntime(), Targeturl, err.Error()), ""
	}
	log.Debug().Msgf("%v GET [%v]", futils.GetCalleRuntime(), Targeturl)
	req, err := http.NewRequest("GET", Targeturl, nil)
	if err != nil {
		return fmt.Errorf("%v: %v Error creating request: %v", futils.GetCalleRuntime(), Targeturl, err.Error()), ""
	}
	if len(settings.UserAgent) > 3 {
		req.Header.Set("User-Agent", settings.UserAgent)
	}
	if len(settings.AddHeader.Key) > 2 {
		req.Header.Set(settings.AddHeader.Key, settings.AddHeader.Value)
	}
	if len(settings.TargetHost) > 3 {
		req.Host = settings.TargetHost
	}
	if len(settings.Headers) > 0 {
		for _, head := range settings.Headers {
			req.Header.Set(head.Key, head.Value)
		}
	}
	LogQueries(Targeturl, futils.GetCalleRuntime())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%v: %v to send GET request %v", futils.GetCalleRuntime(), Targeturl, err.Error()), ""
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%v: %v Failed to retrieve file information %v", futils.GetCalleRuntime(), Targeturl, resp.Status), ""
	}
	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return fmt.Errorf("%v: %v Error reading response body %v", futils.GetCalleRuntime(), Targeturl, err.Error()), ""
	}
	_ = resp.Body.Close()
	return nil, string(body)

}
func GetData(Conf GetAPIConf) (error, string) {
	pps := LoadProxySettings()
	FailedReport = []string{}
	if len(Conf.LocalAddr) > 1 {
		pps.LocalInterface = Conf.LocalAddr
	}
	if Conf.DoNotUseProxy {
		pps.Enabled = 0
	}

	client, err := InitClient(pps)
	zurl := Conf.Url

	if err != nil {
		return fmt.Errorf("%v:%v Initialization failed %v", futils.GetCalleRuntime(), zurl, err.Error()), ""
	}
	req, err := http.NewRequest("GET", zurl, nil)
	if err != nil {
		return fmt.Errorf("%v: %v Error creating request: %v", futils.GetCalleRuntime(), zurl, err.Error()), ""
	}
	if len(pps.UserAgent) > 3 {
		req.Header.Set("User-Agent", pps.UserAgent)
	}
	if len(pps.AddHeader.Key) > 2 {
		req.Header.Set(pps.AddHeader.Key, pps.AddHeader.Value)
	}
	LogQueries(zurl, futils.GetCalleRuntime())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%v: %v to send GET request %v", futils.GetCalleRuntime(), zurl, err.Error()), ""
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	var ProxyError []string
	FailedReport = append(FailedReport, fmt.Sprintf("URL: %v", zurl))
	FailedReport = append(FailedReport, fmt.Sprintf("Network interface to use: %v", pps.LocalInterface))
	FailedReport = append(FailedReport, "Response Headers")
	FailedReport = append(FailedReport, "----------------------------------------")
	for key, values := range resp.Header {
		for _, value := range values {
			FailedReport = append(FailedReport, fmt.Sprintf("%v: %v", key, value))
			if key == "X-Squid-Error" {
				ProxyError = append(ProxyError, " Proxy Error: "+value)
				break
			}
		}
	}
	if pps.Enabled == 0 {
		FailedReport = append(FailedReport, "Proxy Disabled")
		ProxyError = append(ProxyError, "No Proxy Enabled")
	} else {
		FailedReport = append(FailedReport, "Proxy Enabled")
		FailedReport = append(FailedReport, fmt.Sprintf("Proxy Uri:%v ", pps.Proxyaddr))
		ProxyError = append(ProxyError, fmt.Sprintf("Proxy Enabled: %v", pps.Proxyaddr))
	}
	ProxyText := strings.Join(ProxyError, ", ")
	if resp.StatusCode != http.StatusOK {
		FailedReport = append(FailedReport, fmt.Sprintf("Response Code: %v", resp.StatusCode))
		return fmt.Errorf("%v [%v]: Failed to retrieve file information %v %v", futils.GetCalleRuntime(), zurl, resp.Status, ProxyText), ""
	}
	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return fmt.Errorf("%v: [%v] Error reading response body %v %v", futils.GetCalleRuntime(), zurl, err.Error(), ProxyText), ""
	}
	_ = resp.Body.Close()
	return nil, string(body)

}

func GetContentProd(fileURL string) (error, string) {
	pps := LoadProxySettings()
	pps.TargetURL = fileURL
	err, data := GetContent(pps)
	return err, data
}
func DownloadFile(fileURL string, target string) bool {
	NoCentPourcent = false
	DownloadErr = ""
	pps := LoadProxySettings()
	if strings.HasPrefix(fileURL, "direct:") {
		pps.Enabled = 0
		fileURL = strings.ReplaceAll(fileURL, "direct:", "")
	}

	client, err := InitClient(pps)

	if err != nil {
		DownloadErr = fmt.Sprintf("%v:HTTPDownloadFile() Initialization failed %v", fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return false
	}

	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		DownloadErr = fmt.Sprintf("%v: %v Error creating request: %v", futils.GetCalleRuntime(), fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return false
	}

	if len(pps.UserAgent) > 3 {
		req.Header.Set("User-Agent", pps.UserAgent)
	}
	LogQueries(fileURL, futils.GetCalleRuntime())
	progressF = futils.Basename(fileURL)

	resp, err := client.Do(req)
	if err != nil {
		DownloadErr = fmt.Sprintf("%v: Failed to send GET request %v", fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return false
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		DownloadErr = fmt.Sprintf("%v: Failed to retrieve file information %v", fileURL, resp.Status)
		log.Error().Msg(DownloadErr)
		return false
	}

	totalSize, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)

	outFile, err := os.Create(target)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: Failed to create output file: %v", target, err.Error()))
		return false
	}

	defer func() {
		closeErr := outFile.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	progressWriter := &ProgressWriter{
		Total: totalSize,
	}

	_, err = io.Copy(outFile, io.TeeReader(resp.Body, progressWriter))
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: Failed to copy response body to file: %v", fileURL, err.Error()))
		return false
	}
	return true

}
func UploadFile(url string, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}

	pps := LoadProxySettings()
	if strings.HasPrefix(url, "direct:") {
		pps.Enabled = 0
		url = strings.ReplaceAll(url, "direct:", "")
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	part, err := writer.CreateFormFile("file", file.Name())
	if err != nil {
		return err
	}
	_, err = io.Copy(part, file)

	err = writer.Close()
	if err != nil {
		return err
	}

	request, err := http.NewRequest("POST", url, &requestBody)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())

	client, err := InitClient(pps)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(response.Body)

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-200 status: %d %s", response.StatusCode, response.Status)
	}

	return nil
}
func UploadFileWithFormData(Conf UploadConfig) error {

	pps := LoadProxySettings()

	if len(Conf.APIKey) > 3 {
		pps.AddHeader.Key = "X-API-Key"
		pps.AddHeader.Value = Conf.APIKey
	}

	if Conf.UseDirect {
		pps.Enabled = 0
	}

	file, err := os.Open(Conf.FilePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	part, err := writer.CreateFormFile(Conf.FieldName, Conf.FileName)
	if err != nil {
		return err
	}
	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}

	for key, value := range Conf.FormData {
		err := writer.WriteField(key, value)
		if err != nil {
			return err
		}
	}

	err = writer.Close()
	if err != nil {
		return err
	}
	request, err := http.NewRequest("POST", Conf.Url, &requestBody)
	if err != nil {
		return err
	}
	if len(Conf.APIKey) > 3 {
		request.Header.Set("X-API-Key", Conf.APIKey)
	}

	request.Header.Set("Content-Type", writer.FormDataContentType())
	LogQueries(Conf.Url, futils.GetCalleRuntime())
	client, err := InitClient(pps)
	if err != nil {
		return fmt.Errorf("%v:UploadFileWithFormData() Initialization failed %v", Conf.Url, err.Error())
	}

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(response.Body)

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-200 status: %d %s", response.StatusCode, response.Status)
	}

	return nil
}
func DownloadBigFileWithError(fileURL string, target string, progressFile string) error {
	DownloadErr = ""
	NoCentPourcent = false
	pps := LoadProxySettings()
	if strings.HasPrefix(fileURL, "direct:") {
		pps.Enabled = 0
		fileURL = strings.ReplaceAll(fileURL, "direct:", "")
	}

	pps.TimeOut = 18000
	client, err := InitClient(pps)

	if err != nil {
		DownloadErr = fmt.Sprintf("%v:DownloadBigFileWithError() Initialization failed %v", fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return err
	}

	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		DownloadErr = fmt.Sprintf("%v: DownloadBigFileWithError() Error creating request: %v", fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return err
	}
	LogQueries(fileURL, futils.GetCalleRuntime())
	if len(pps.UserAgent) > 3 {
		req.Header.Set("User-Agent", pps.UserAgent)
	}
	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		DownloadErr = fmt.Sprintf("DownloadBigFileWithError() %v: Failed to send GET request %v", fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		DownloadErr = fmt.Sprintf("DownloadBigFileWithError() %v: Failed to retrieve file information %v", fileURL, resp.Status)
		log.Error().Msg(DownloadErr)
		return fmt.Errorf(resp.Status)
	}

	totalSize, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)

	outFile, err := os.Create(target)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("DownloadBigFileWithError( %v: Failed to create output file: %v", target, err.Error()))
		return err
	}

	defer func(outFile *os.File) {
		err := outFile.Close()
		if err != nil {

		}
	}(outFile)

	counter := &DownloadPercent{Total: totalSize, Progressfile: progressFile}
	_, err = io.Copy(outFile, io.TeeReader(resp.Body, counter))
	if err != nil {
		endTime := time.Now()
		diff := endTime.Sub(startTime).Seconds()
		log.Error().Msg(fmt.Sprintf("DownloadBigFileWithError() %v: after %v seconds, Failed to copy response body to file: %v", fileURL, diff, err.Error()))
		return err
	}
	return nil

}
func (wc *DownloadPercent) Write(p []byte) (int, error) {
	n := len(p)
	wc.Downloaded += n
	percent := futils.Float64ToInt(float64(wc.Downloaded) / float64(wc.Total) * 100)
	if NoCentPourcent {
		if percent > 98 {
			percent = 98
		}
	}
	Mega1 := futils.HumanizeBytes(int64(wc.Downloaded))
	Mega2 := futils.HumanizeBytes(wc.Total)
	if len(wc.Progressfile) == 0 {
		return n, nil
	}
	BuildProgress(percent, fmt.Sprintf("Downloaded %v out of %v bytes", Mega1, Mega2), wc.Progressfile)
	return n, nil
}
func BuildProgress(prc int, text string, fname string) bool {
	if len(fname) == 0 {
		return true
	}
	if NoCentPourcent {
		if prc > 95 {
			prc = 95
		}
	}

	futils.CreateDir("/usr/share/artica-postfix/ressources/logs/web")
	var Files []string
	if strings.Contains(fname, ",") {
		Files = strings.Split(fname, ",")
	} else {
		Files = append(Files, fname)
	}
	for _, BaseName := range Files {
		array := make(map[string]string)
		array["POURC"] = fmt.Sprintf("%d", prc)
		array["TEXT"] = text
		Path := fmt.Sprintf("%v/%v", "/usr/share/artica-postfix/ressources/logs/web", BaseName)
		serialized, _ := gophp.Serialize(array)
		serializedText := fmt.Sprintf("%s", serialized)
		err := futils.FilePutContents(Path, serializedText)
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
		futils.Chmod(Path, 0644)
		futils.ChownFile(Path, "www-data", "www-data")
	}
	return true
}
func DownloadProgress(fileURL string, target string, progressFile string) error {
	NoCentPourcent = true
	DownloadErr = ""
	pps := LoadProxySettings()
	if strings.HasPrefix(fileURL, "direct:") {
		pps.Enabled = 0
		fileURL = strings.ReplaceAll(fileURL, "direct:", "")
	}
	progressF = progressFile
	pps.TimeOut = 18000
	client, err := InitClient(pps)

	if err != nil {
		DownloadErr = fmt.Sprintf("%v %v Initialization failed %v", futils.GetCalleRuntime(), fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return fmt.Errorf("%v", DownloadErr)
	}

	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		DownloadErr = fmt.Sprintf("%v [%v]: Error creating request: %v", futils.GetCalleRuntime(), fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return fmt.Errorf("%v", DownloadErr)
	}

	if len(pps.UserAgent) > 3 {
		req.Header.Set("User-Agent", pps.UserAgent)
	}
	LogQueries(fileURL, futils.GetCalleRuntime())

	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		DownloadErr = fmt.Sprintf("%v [%v]: Failed to send GET request %v", futils.GetCalleRuntime(), fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return fmt.Errorf("%v", DownloadErr)
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		DownloadErr = fmt.Sprintf("%v %v: remote server send code %d %v", futils.GetCalleRuntime(), fileURL, resp.StatusCode, resp.Status)
		log.Error().Msg(DownloadErr)
		return fmt.Errorf("%v", DownloadErr)
	}

	totalSize, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)

	outFile, err := os.Create(target)
	if err != nil {
		log.Error().Msgf("%v %v: Failed to create output file: %v", futils.GetCalleRuntime(), target, err.Error())
		return fmt.Errorf("%v: Failed to create output file: %v", target, err.Error())
	}

	defer func(outFile *os.File) {
		_ = outFile.Close()
	}(outFile)

	progressWriter := &ProgressWriter{
		Total: totalSize,
	}

	_, err = io.Copy(outFile, io.TeeReader(resp.Body, progressWriter))
	if err != nil {
		endTime := time.Now()
		diff := endTime.Sub(startTime).Seconds()
		log.Error().Msgf("%v %v: after %v seconds, Failed to copy response body to file: %v", futils.GetCalleRuntime(), fileURL, diff, err.Error())
		return fmt.Errorf("after %v seconds, Failed to copy response body to file: %v", diff, err.Error())
	}
	return nil

}
func DownloadBigFile(fileURL string, target string) bool {
	DownloadErr = ""
	pps := LoadProxySettings()
	if strings.HasPrefix(fileURL, "direct:") {
		pps.Enabled = 0
		fileURL = strings.ReplaceAll(fileURL, "direct:", "")
	}

	pps.TimeOut = 18000
	client, err := InitClient(pps)

	if err != nil {
		DownloadErr = fmt.Sprintf("%v %v Initialization failed %v", futils.GetCalleRuntime(), fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return false
	}

	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		DownloadErr = fmt.Sprintf("%v [%v]: Error creating request: %v", futils.GetCalleRuntime(), fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return false
	}

	if len(pps.UserAgent) > 3 {
		req.Header.Set("User-Agent", pps.UserAgent)
	}
	LogQueries(fileURL, futils.GetCalleRuntime())
	progressF = futils.Basename(fileURL)
	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		DownloadErr = fmt.Sprintf("%v [%v]: Failed to send GET request %v", futils.GetCalleRuntime(), fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return false
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		DownloadErr = fmt.Sprintf("%v %v: remote server send code %d %v", futils.GetCalleRuntime(), fileURL, resp.StatusCode, resp.Status)
		log.Error().Msg(DownloadErr)
		return false
	}

	totalSize, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)

	outFile, err := os.Create(target)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: Failed to create output file: %v", target, err.Error()))
		return false
	}

	defer func(outFile *os.File) {
		_ = outFile.Close()
	}(outFile)

	progressWriter := &ProgressWriter{
		Total: totalSize,
	}

	_, err = io.Copy(outFile, io.TeeReader(resp.Body, progressWriter))
	if err != nil {
		endTime := time.Now()
		diff := endTime.Sub(startTime).Seconds()
		log.Error().Msgf("%v %v: after %v seconds, Failed to copy response body to file: %v", futils.GetCalleRuntime(), fileURL, diff, err.Error())
		return false
	}
	return true

}
func DownloadFileParms(Params DownloadConfig) error {
	DownloadErr = ""
	pps := LoadProxySettings()
	if Params.UseDirect {
		pps.Enabled = 0

	}
	fileURL := Params.Url
	pps.TimeOut = 18000
	pps.LocalInterface = ""

	target := Params.TargetFile
	log.Debug().Msgf("%v OutgoingInterface=%v", futils.GetCalleRuntime(), Params.OutgoingInterface)
	if len(Params.OutgoingInterface) > 1 {
		pps.LocalInterface = Params.OutgoingInterface
	}
	client, err := InitClient(pps)

	if err != nil {
		DownloadErr = fmt.Sprintf("%v %v Initialization failed %v", futils.GetCalleRuntime(), fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return fmt.Errorf(DownloadErr)
	}

	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		DownloadErr = fmt.Sprintf("%v [%v]: Error creating request: %v", futils.GetCalleRuntime(), fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return fmt.Errorf(DownloadErr)
	}
	LogQueries(fileURL, futils.GetCalleRuntime())
	if len(pps.UserAgent) > 3 {
		req.Header.Set("User-Agent", pps.UserAgent)
	}
	progressF = futils.Basename(fileURL)
	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		DownloadErr = fmt.Sprintf("%v [%v]: Failed to send GET request %v", futils.GetCalleRuntime(), fileURL, err.Error())
		log.Error().Msg(DownloadErr)
		return fmt.Errorf(DownloadErr)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		DownloadErr = fmt.Sprintf("%v %v: Failed to retrieve file information %v", futils.GetCalleRuntime(), fileURL, resp.Status)
		log.Error().Msg(DownloadErr)
		return fmt.Errorf(DownloadErr)
	}

	totalSize, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)

	outFile, err := os.Create(target)
	if err != nil {
		log.Error().Msgf("%v %v: Failed to create output file: %v", futils.GetCalleRuntime(), target, err.Error())
		return fmt.Errorf("%v %v: Failed to create output file: %v", futils.GetCalleRuntime(), target, err.Error())
	}

	defer func(outFile *os.File) {
		err := outFile.Close()
		if err != nil {

		}
	}(outFile)

	progressWriter := &ProgressWriter{
		Total: totalSize,
	}

	_, err = io.Copy(outFile, io.TeeReader(resp.Body, progressWriter))
	if err != nil {
		endTime := time.Now()
		diff := endTime.Sub(startTime).Seconds()
		log.Error().Msgf("%v %v: after %v seconds, Failed to copy response body to file: %v", futils.GetCalleRuntime(), fileURL, diff, err.Error())
		return fmt.Errorf("%v %v: after %v seconds, Failed to copy response body to file: %v", futils.GetCalleRuntime(), fileURL, diff, err.Error())
	}
	return nil

}
func LoadProxySettings() ProxySettings {

	var pp ProxySettings
	ArticaProxySettings := sockets.GET_INFO_STR("ArticaProxySettings")
	NoCheckSquid := sockets.GET_INFO_INT("NoCheckSquid")
	SQUIDEnable := sockets.GET_INFO_INT("SQUIDEnable")
	if SQUIDEnable == 0 {
		NoCheckSquid = 1
	}
	WgetBindIpAddressToCheck := sockets.GET_INFO_STR("WgetBindIpAddress")
	WgetTimeOut := sockets.GET_INFO_INT("WgetTimeOut")

	if WgetTimeOut == 0 {
		WgetTimeOut = 20
	}
	pp.TimeOut = int(WgetTimeOut)

	if len(WgetBindIpAddressToCheck) > 0 {
		if ipclass.IsIPAddress(WgetBindIpAddressToCheck) {
			ipclass.IsLocalIPAddress(WgetBindIpAddressToCheck)
			pp.LocalInterface = WgetBindIpAddressToCheck
		} else {
			if ipclass.IsInterfaceExists(WgetBindIpAddressToCheck) {
				pp.LocalInterface = WgetBindIpAddressToCheck
			}
		}
	}

	pp.UserAgent = sockets.GET_INFO_STR("CurlUserAgent")
	if len(pp.UserAgent) == 0 {
		pp.UserAgent = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:10.0) Gecko/20100101 Firefox/10.0"
	}

	cfg, err := ini.LoadSources(ini.LoadOptions{AllowShadows: true}, []byte(ArticaProxySettings))
	if err != nil {
		log.Warn().Msg(fmt.Sprintf("Unable to get Proxy configuration with error %v", err.Error()))
		return pp
	}
	PROXY := cfg.Section("PROXY")
	ProxyEnabled := 0
	ArticaProxyServerEnabled := PROXY.Key("ArticaProxyServerEnabled").String()
	ArticaProxyServerName := PROXY.Key("ArticaProxyServerName").String()
	ArticaProxyServerPort := strToInt(PROXY.Key("ArticaProxyServerPort").String())
	if ArticaProxyServerPort == 0 {
		ArticaProxyServerPort = 3128
	}
	ArticaProxyServerUsername := PROXY.Key("ArticaProxyServerUsername").String()
	ArticaProxyServerUserPassword := PROXY.Key("ArticaProxyServerUserPassword").String()

	if strings.ToLower(ArticaProxyServerEnabled) == "yes" {
		ArticaProxyServerEnabled = "1"
	}
	if ArticaProxyServerEnabled == "no" {
		ArticaProxyServerEnabled = "1"
	}
	ProxyEnabled = strToInt(ArticaProxyServerEnabled)

	if len(ArticaProxyServerName) == 0 {
		ProxyEnabled = 0
	}

	if ProxyEnabled == 1 {
		pp.Enabled = 1
		pp.Proxyaddr = fmt.Sprintf("%v:%v", ArticaProxyServerName, ArticaProxyServerPort)
		pp.UrlPattern = fmt.Sprintf("http://%v", pp.Proxyaddr)
		if len(ArticaProxyServerUsername) > 1 {
			pp.Username = ArticaProxyServerUsername
			pp.Password = ArticaProxyServerUserPassword
			pp.UrlPattern = fmt.Sprintf("http://%v:%v@%v", pp.Username, pp.Password, pp.Proxyaddr)
		}
		return pp
	}

	SquidMgrListenPort := sockets.GET_INFO_INT("SquidMgrListenPort")
	if SQUIDEnable == 0 {
		NoCheckSquid = 1
	}
	if SquidMgrListenPort == 0 {
		pp.Enabled = 0
		return pp
	}

	if NoCheckSquid == 0 {
		if SQUIDEnable == 1 {
			pp.Enabled = 1
			pp.Proxyaddr = fmt.Sprintf("127.0.0.1:%v", sockets.GET_INFO_INT("SquidMgrListenPort"))
			pp.UrlPattern = fmt.Sprintf("http://%v", pp.Proxyaddr)
			return pp
		}
	}

	if ProxyEnabled == 0 {
		if SQUIDEnable == 1 {
			if NoCheckSquid == 1 {
				pp.Proxyaddr = ""
				pp.Enabled = 0
				return pp
			}
		}
	}
	if ProxyEnabled == 0 {
		if SQUIDEnable == 0 {
			pp.Proxyaddr = ""
			pp.Enabled = 0
			return pp
		}
	}

	pp.Enabled = 1
	pp.Proxyaddr = fmt.Sprintf("%v:%v", ArticaProxyServerName, ArticaProxyServerPort)
	pp.UrlPattern = fmt.Sprintf("http://%v", pp.Proxyaddr)
	if len(ArticaProxyServerUsername) > 1 {
		pp.Username = ArticaProxyServerUsername
		pp.Password = ArticaProxyServerUserPassword
		pp.UrlPattern = fmt.Sprintf("http://%v:%v@%v", pp.Username, pp.Password, pp.Proxyaddr)
	}
	return pp

}
func (pw *ProgressWriter) Write(p []byte) (int, error) {
	if pw.Total == 0 {
		return 0, nil
	}
	n := len(p)
	pw.Completed += int64(n)
	progress := float64(pw.Completed) / float64(pw.Total) * 100.0
	text := fmt.Sprintf("[%v]: Downloaded: %d/%d bytes (%.2f%%)", progressF, pw.Completed, pw.Total, progress)

	intPrc := int(progress)
	if intPrc > TempPc+5 {
		log.Info().Msg(text)
		TempPc = intPrc
	}

	return n, nil
}
func HTTPPostDataAPI(url string, params url.Values) (error, string) {
	pps := LoadProxySettings()
	pps.Enabled = 0
	pps.TimeOut = 10

	client, err := InitClient(pps)

	if err != nil {
		return fmt.Errorf("%v:HTTPPostDataAPI() Initialization failed %v", url, err.Error()), ""
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("%v: HTTPPostDataAPI() Error creating request: %v", url, err.Error()), ""
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if len(pps.UserAgent) > 3 {
		req.Header.Set("User-Agent", pps.UserAgent)
	}
	LogQueries(url, futils.GetCalleRuntime())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%v: HTTPPostDataAPI to send GET request %v", url, err.Error()), ""
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%v %v: Failed to retrieve file information %v", futils.GetCalleRuntime(), url, resp.Status), ""
	}
	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return fmt.Errorf("%v: %v Error reading response body %v", futils.GetCalleRuntime(), url, err.Error()), ""
	}
	_ = resp.Body.Close()
	return nil, string(body)
}
func traceToLicense(function string, StatusCode int, err error, pp ProxySettings) {
	tosyslogGen(fmt.Sprintf("%v ERROR Got status Code %d with error [%s]", function, StatusCode, err), "ARTICA_LICENSE")
	tosyslogGen(fmt.Sprintf("%v ERROR URL: [%v]", function, pp.TargetURL), "ARTICA_LICENSE")
	tosyslogGen(fmt.Sprintf("%v ERROR Time-out: %d seconds", function, pp.TimeOut), "ARTICA_LICENSE")
	tosyslogGen(fmt.Sprintf("%v ERROR Interface: %v", function, pp.LocalInterface), "ARTICA_LICENSE")
	tosyslogGen(fmt.Sprintf("%v ERROR Proxy address: %v active=%d", function, pp.Proxyaddr, pp.Enabled), "ARTICA_LICENSE")
}
func tosyslogGen(text string, processname string) bool {

	if processname == "hacluster-client" {
		var MyIP string
		HaClusterClientInterface := sockets.GET_INFO_STR("HaClusterClientInterface")
		if len(HaClusterClientInterface) == 0 {
			HaClusterClientInterface = ipclass.DefaultInterface()
		}
		if len(HaClusterClientInterface) > 1 {
			MyIP = ipclass.InterfaceToIPv4(HaClusterClientInterface)
		}
		if len(MyIP) > 3 {
			text = fmt.Sprintf("(%v) %v", MyIP, text)
		}
	}

	syslogger, err := syslog.New(syslog.LOG_INFO, processname)
	if err != nil {
		return false
	}
	log.Debug().Msg(text)
	_ = syslogger.Notice(text)
	_ = syslogger.Close()
	return true
}
func HTTPPostData(url string, params url.Values) (error, string) {
	pps := LoadProxySettings()
	LOGLICENSE := false
	if strings.HasPrefix(url, "direct:") {
		pps.Enabled = 0
		url = strings.ReplaceAll(url, "direct:", "")
	}
	LocalInterface := params.Get("ArticaLocalIface")
	if len(LocalInterface) > 1 {
		params.Del("ArticaLocalIface")
		pps.LocalInterface = LocalInterface
	}

	client, err := InitClient(pps)
	pps.TargetURL = url
	if params.Has("LOGLICENSE") {
		LOGLICENSE = true
		params.Del("LOGLICENSE")
	}

	if err != nil {
		return fmt.Errorf("%v [%v] Initialization failed %v", futils.GetCalleRuntime(), url, err.Error()), ""
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(params.Encode()))
	if err != nil {
		if LOGLICENSE {
			traceToLicense(futils.GetCalleRuntime(), 0, err, pps)
		}
		return fmt.Errorf("%v %v: Error creating request: %v", futils.GetCalleRuntime(), url, err.Error()), ""
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if len(pps.UserAgent) > 3 {
		req.Header.Set("User-Agent", pps.UserAgent)
	}
	LogQueries(url, futils.GetCalleRuntime())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%v %v to send POST request [%v]", futils.GetCalleRuntime(), url, err.Error()), ""
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		if LOGLICENSE {
			traceToLicense(futils.GetCalleRuntime(), resp.StatusCode, err, pps)
		}
		return fmt.Errorf("%v %v: Failed to retrieve file information %v", futils.GetCalleRuntime(), url, resp.Status), ""
	}
	body, err := io.ReadAll(resp.Body)

	if err != nil {
		if LOGLICENSE {
			traceToLicense(futils.GetCalleRuntime(), resp.StatusCode, err, pps)
		}
		return fmt.Errorf("%v %v: Error reading response body %v", futils.GetCalleRuntime(), url, err.Error()), ""
	}
	_ = resp.Body.Close()
	return nil, string(body)
}
func strToInt(svalue string) int {
	svalue = strings.TrimSpace(svalue)
	if len(svalue) == 0 {
		return 0
	}
	tkint, err := strconv.Atoi(svalue)
	if err == nil {
		return tkint
	}
	return 0
}
func GetAPI(Conf GetAPIConf) (error, string) {

	var pps ProxySettings
	pps.Enabled = 0
	pps.DoNotFollowRedirect = true

	if Conf.ForceUseProxy {
		pps = LoadProxySettings()
	}

	if Conf.Timeout == 0 {
		Conf.Timeout = 5
	}
	if len(Conf.APIKey) > 3 {
		pps.AddHeader.Key = "X-API-Key"
		pps.AddHeader.Value = Conf.APIKey
	}

	var data struct {
		Status bool   `json:"Status"`
		Error  string `json:"error"`
		Info   string `json:"Info"`
	}

	pps.TimeOut = Conf.Timeout
	fileURL := Conf.Url

	client, err := InitClient(pps)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: %v Initialization failed %v", futils.GetCalleRuntime(), fileURL, err.Error()))
		data.Status = false
		data.Error = err.Error()
		jsonBytes, _ := json.MarshalIndent(data, "", "  ")
		return err, string(jsonBytes)
	}
	req, err := http.NewRequest("GET", fileURL, nil)

	if err != nil {
		data.Status = false
		data.Error = err.Error()
		jsonBytes, _ := json.MarshalIndent(data, "", "  ")
		return err, string(jsonBytes)
	}

	if len(Conf.APIKey) > 3 {
		req.Header.Set("X-API-Key", Conf.APIKey)
	}

	if len(pps.UserAgent) > 3 {
		req.Header.Set("User-Agent", pps.UserAgent)
	}
	LogQueries(fileURL, futils.GetCalleRuntime())
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: %v Failed to send GET request %v", futils.GetCalleRuntime(), fileURL, err.Error()))
		data.Status = false
		data.Error = err.Error()
		jsonBytes, _ := json.MarshalIndent(data, "", "  ")
		return err, string(jsonBytes)
	}
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		log.Error().Msg(fmt.Sprintf("%v: %v Failed to retrieve file information %v", futils.GetCalleRuntime(), fileURL, resp.Status))
		data.Status = false
		var Headers []string
		for key, values := range resp.Header {
			for _, value := range values {
				Headers = append(Headers, fmt.Sprintf("%s: %s", key, value))
			}
		}
		data.Error = fmt.Sprintf("Failed to retrieve file information returned code %d %v [%v]", resp.StatusCode, resp.Status, strings.Join(Headers, "; "))
		jsonBytes, _ := json.MarshalIndent(data, "", "  ")
		return fmt.Errorf("bad return code %d", resp.StatusCode), string(jsonBytes)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("%v: GetAPI() Failed to retrieve body information %v", fileURL, resp.Status))
		data.Status = false
		data.Error = err.Error()
		jsonBytes, _ := json.MarshalIndent(data, "", "  ")
		return err, string(jsonBytes)
	}
	return nil, string(bodyBytes)
}
func ArticaHotFixVersion() string {
	srcfile := "/usr/share/artica-postfix/fw.updates.php"

	file, err := os.Open(srcfile)
	if err != nil {
		return ""
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) > 0 {
			_ = file.Close()
			return matches[1]
		}
	}
	if err := scanner.Err(); err != nil {
		return ""
	}
	_ = file.Close()
	return ""
}
func GetHeaders(fileURL string, proxy ProxySettings) (error, map[string]string) {

	client, err := InitClient(proxy)
	var results = make(map[string]string)
	req, err := http.NewRequest("HEAD", fileURL, nil)

	var curl []string

	curl = append(curl, "curl --verbose --head --insecure")

	if err != nil {
		return fmt.Errorf("error creating HEAD request: %v", err), results

	}

	if len(proxy.TargetHost) > 3 {
		req.Host = proxy.TargetHost
		curl = append(curl, fmt.Sprintf("-H \"Host: %v\"", req.Host))
	}
	if len(proxy.UserAgent) == 0 {
		proxy.UserAgent = "Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/120.0"
	}

	if len(proxy.UserAgent) > 3 {
		cmdcurl := strings.ReplaceAll(proxy.UserAgent, `"`, `\"`)
		curl = append(curl, fmt.Sprintf("--user-agent \"%v\"", cmdcurl))
		req.Header.Set("User-Agent", proxy.UserAgent)
	}
	req.Header.Add("Pragma", "no-cache,must-revalidate")
	req.Header.Add("Cache-Control", "no-cache,must-revalidate")
	LogQueries(fileURL, futils.GetCalleRuntime())
	curl = append(curl, fileURL)
	CurlCMD := strings.Join(curl, " ")
	resp, err := client.Do(req)

	if resp != nil {
		results["HTTP_CODE"] = fmt.Sprintf("%v", resp.StatusCode)
		log.Debug().Msg(fmt.Sprintf("%v %s: %s\n", futils.GetCalleRuntime(), "HTTP_CODE", results["HTTP_CODE"]))
		for key, values := range resp.Header {
			for _, value := range values {
				results[strings.ToUpper(key)] = value
				log.Debug().Msg(fmt.Sprintf("%v %s: %s\n", futils.GetCalleRuntime(), key, value))
			}
		}
	}
	if err != nil {
		results["GO_ERROR"] = err.Error()
		errstr := fmt.Sprintf("URL:[%v]<br>Host:[%v]<br>Error [<strong>%v</strong>]<br>use Curl to verify this error: <textarea style='width:99%%;height:50px'>%v</textarea>", fileURL, proxy.TargetHost, err.Error(), CurlCMD)
		log.Error().Msgf("%v %v Host:[%v] Proxy:%v Error [%v]", futils.GetCalleRuntime(), fileURL, proxy.TargetHost, proxy.Proxyaddr, err.Error())
		return errors.New(errstr), results

	}

	if resp != nil {
		_ = resp.Body.Close()
	}
	return nil, results

}
func GetSimpleHeaders(fileURL string, proxy ProxySettings) (error, map[string]string) {
	client, err := InitClient(proxy)
	if err != nil {
		return fmt.Errorf("error initializing HTTP client: %v", err), nil
	}

	results := make(map[string]string)

	req, err := http.NewRequest("HEAD", fileURL, nil)
	if err != nil {
		return fmt.Errorf("error creating HEAD request: %v", err), results
	}

	if len(proxy.TargetHost) > 3 {
		req.Host = proxy.TargetHost
	}
	if len(proxy.UserAgent) == 0 {
		proxy.UserAgent = "Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/120.0"
	}
	req.Header.Set("User-Agent", proxy.UserAgent)
	req.Header.Add("Pragma", "no-cache,must-revalidate")
	req.Header.Add("Cache-Control", "no-cache,must-revalidate")

	LogQueries(fileURL, futils.GetCalleRuntime())

	resp, err := client.Do(req)
	if err != nil {
		results["GO_ERROR"] = err.Error()
		log.Error().Msgf("%v %v Host:[%v] Proxy:%v Error [%v]", futils.GetCalleRuntime(), fileURL, proxy.TargetHost, proxy.Proxyaddr, err.Error())
		return err, results
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.Header != nil {
		for key, values := range resp.Header {
			for _, value := range values {
				results[strings.ToUpper(key)] = value
			}
		}
	}

	results["HTTP_CODE"] = fmt.Sprintf("%v", resp.StatusCode)
	log.Debug().Msgf("%v %s: %s", futils.GetCalleRuntime(), "HTTP_CODE", results["HTTP_CODE"])

	return nil, results
}

type IniHandler struct {
	Config *ini.File
}

func (iniHandler *IniHandler) LoadString(data string) error {
	cfg, err := ini.Load([]byte(data))
	if err != nil {
		return err
	}
	iniHandler.Config = cfg
	return nil
}
func SaveProxySettings() {
	iniHandler := &IniHandler{}

	// Load INI data from the string
	err := iniHandler.LoadString(sockets.GET_INFO_STR("ArticaProxySettings"))
	if err != nil {
		log.Error().Msgf("%v Failed to load INI data: %v", futils.GetCalleRuntime(), err)
	}

	// Retrieve settings from the INI file
	proxySection := iniHandler.Config.Section("PROXY")
	ArticaProxyServerEnabled := futils.StrToInt(proxySection.Key("ArticaProxyServerEnabled").String())
	ArticaProxyServerName := proxySection.Key("ArticaProxyServerName").String()
	ArticaProxyServerPort := proxySection.Key("ArticaProxyServerPort").MustInt(80)
	ArticaProxyServerUsername := proxySection.Key("ArticaProxyServerUsername").String()
	ArticaProxyServerUserPassword := proxySection.Key("ArticaProxyServerUserPassword").String()

	// URL encode the password
	ArticaProxyServerUserPassword = strings.ReplaceAll(ArticaProxyServerUserPassword, "@", "%40")
	ArticaProxyServerUserPassword = strings.ReplaceAll(ArticaProxyServerUserPassword, ":", "%3A")
	ArticaProxyServerUserPassword = strings.ReplaceAll(ArticaProxyServerUserPassword, "!", "%21")
	ArticaProxyServerUserPassword = strings.ReplaceAll(ArticaProxyServerUserPassword, "#", "%23")
	ArticaProxyServerUserPassword = strings.ReplaceAll(ArticaProxyServerUserPassword, "$", "%24")

	NoCheckSquid := sockets.GET_INFO_INT("NoCheckSquid")
	SQUIDEnable := sockets.GET_INFO_INT("SQUIDEnable")
	if SQUIDEnable == 0 {
		NoCheckSquid = 1
	}
	log.Debug().Msgf("%v ArticaProxyServerEnabled = %d SQUIDEnable = %d NoCheckSquid = %d", futils.GetCalleRuntime(), ArticaProxyServerEnabled, SQUIDEnable, NoCheckSquid)

	if ArticaProxyServerEnabled == 0 {
		if SQUIDEnable == 0 {
			log.Debug().Msgf("%v --> removeProxy()", futils.GetCalleRuntime())
			removeProxy()
			return
		}
		if NoCheckSquid == 1 {
			log.Debug().Msgf("%v NoCheckSquid == 0 --> removeProxy()", futils.GetCalleRuntime())
			removeProxy()
			return
		}
	}

	// Prepare proxy pattern
	var pattern string
	if ArticaProxyServerUsername != "" {
		pattern = ArticaProxyServerUsername
		if ArticaProxyServerUserPassword != "" {
			pattern += ":" + ArticaProxyServerUserPassword
		}
		pattern += "@"
	}
	proxyPattern := fmt.Sprintf("http://%s%s:%d", pattern, ArticaProxyServerName, ArticaProxyServerPort)

	if ArticaProxyServerEnabled == 0 {
		if SQUIDEnable == 1 {
			pp := LoadProxySettings()
			proxyPattern = pp.Proxyaddr
		}
	}

	log.Debug().Msgf("%v ProxyPattern = %v", futils.GetCalleRuntime(), proxyPattern)
	if !strings.HasPrefix("http:", proxyPattern) {
		proxyPattern = "http://" + proxyPattern
	}
	proxyPattern = strings.ReplaceAll(proxyPattern, "http://http://", "http://")
	Acquire := fmt.Sprintf("Acquire::http::proxy \"%v/\";\n", proxyPattern)
	_ = futils.FilePutContents("/etc/apt/apt.conf.d/proxy", Acquire)

	addProxyInEnvironmentFiles(proxyPattern)
	createProfileScript(proxyPattern)
}
func removeProxy() {
	filePath := "/etc/profile.d/proxy-mycompany.sh"
	futils.DeleteFile(filePath)
	futils.DeleteFile("/etc/profile.local")
	futils.DeleteFile("/root/.wgetrc")
	futils.DeleteFile("/etc/wgetrc")
	futils.DeleteFile("/etc/apt/apt.conf.d/proxy")
	proxyList := "http_proxy HTTP_PROXY NEWSPOST_PROXY NEWSREPLY_PROXY NEWS_PROXY WAIS_PROXY SNEWSREPLY_PROXY FINGER_PROXY HTTPS_PROXY FTP_PROXY CSO_PROXY SNEWSPOST_PROXY NNTP_PROXY GOPHER_PROXY SNEWS_PROXY"
	proxyVars := strings.Split(proxyList, " ")

	var script []string
	script = append(script, "#!/bin/sh")
	for _, xline := range proxyVars {
		xline = strings.TrimSpace(xline)
		if xline == "" {
			continue
		}
		_ = os.Unsetenv(xline)
		script = append(script, fmt.Sprintf("%s=\"\"", xline))
		script = append(script, fmt.Sprintf("unset %s", xline))
		err := os.Setenv(xline, "")
		if err != nil {
			log.Error().Msgf("%v %v", futils.GetCalleRuntime(), err.Error())
		}

	}
	NoPr := []string{"127.0.0.1", "localhost", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"}
	script = append(script, fmt.Sprintf("NO_PROXY=\"%v\"", strings.Join(NoPr, ",")))
	script = append(script, "for i in "+proxyList+"; do")
	script = append(script, `export $i=""`)
	script = append(script, `unset $i; done`)
	script = append(script, "unset i")

	err := os.WriteFile("/etc/profile.d/proxy-mycompany.sh", []byte(strings.Join(script, "\n")), 0755)
	if err != nil {
		log.Error().Msgf("%v Failed to write proxy script: %v", futils.GetCalleRuntime(), err)
	}
	_, _ = futils.ExecuteShell("/etc/profile.d/proxy-mycompany.sh")

	files := []string{"/etc/environment", "/etc/wgetrc", "/root/.wgetrc", "/etc/profile.local"}
	for _, file := range files {
		if !futils.FileExists(file) {
			continue
		}
		content, err := os.ReadFile(file)
		if err != nil {
			log.Error().Msgf("%v Failed to read %s: %v", futils.GetCalleRuntime(), file, err)
			continue
		}

		lines := strings.Split(string(content), "\n")
		var newLines []string
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "http_proxy") || strings.Contains(line, "LC_ALL") {
				continue
			}
			newLines = append(newLines, line)
		}
		err = os.WriteFile(file, []byte(strings.Join(newLines, "\n")), 0644)
		if err != nil {
			log.Error().Msgf("%v Failed to update %s: %v", futils.GetCalleRuntime(), file, err)
		}
	}
}
func addProxyInEnvironmentFiles(proxyPattern string) {
	files := []string{"/etc/environment", "/etc/wgetrc", "/root/.wgetrc", "/etc/profile.local"}
	for _, file := range files {
		if !futils.FileExists(file) {
			futils.TouchFile(file)
		}
		content, err := os.ReadFile(file)
		if err != nil {
			log.Error().Msgf("%v Failed to read %s: %v", futils.GetCalleRuntime(), file, err)
			continue
		}

		lines := strings.Split(string(content), "\n")
		var newLines []string
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "http_proxy") || strings.Contains(line, "LC_ALL") {
				continue
			}
			newLines = append(newLines, line)
		}
		newLines = append(newLines, fmt.Sprintf("http_proxy=%s\n", proxyPattern))

		err = os.WriteFile(file, []byte(strings.Join(newLines, "\n")), 0644)
		if err != nil {
			log.Error().Msgf("%v Failed to update %s: %v", futils.GetCalleRuntime(), file, err)
		}
	}
}
func createProfileScript(proxyPattern string) {
	filePath := "/etc/profile.d/proxy-mycompany.sh"
	script := []string{
		"#!/bin/sh",
		fmt.Sprintf("HTTP_PROXY=%s", proxyPattern),
		`for i in HTTP_PROXY NEWSPOST_PROXY NEWSREPLY_PROXY NEWS_PROXY WAIS_PROXY SNEWSREPLY_PROXY FINGER_PROXY HTTPS_PROXY FTP_PROXY CSO_PROXY SNEWSPOST_PROXY NNTP_PROXY GOPHER_PROXY SNEWS_PROXY; do`,
		"export $i=$HTTP_PROXY; done",
		"unset i",
	}
	NoPr := []string{"127.0.0.1", "localhost", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"}
	script = append(script, fmt.Sprintf("export NO_PROXY=\"%v\"", strings.Join(NoPr, ",")))

	err := os.WriteFile(filePath, []byte(strings.Join(script, "\n")), 0755)
	if err != nil {
		log.Error().Msgf("%v Failed to create proxy script: %v", futils.GetCalleRuntime(), err)
	}
}

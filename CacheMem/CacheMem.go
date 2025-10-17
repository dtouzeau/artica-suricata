package CacheMem

import (
	"fmt"
	"github.com/patrickmn/go-cache"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const cacheFile = "/var/db/artica-postfix/central.cache"
const cache6File = "/var/db/artica-postfix/cache6.cache"

const CacheRetention = 24 * time.Hour

var ArticaRestCache *cache.Cache
var Cache6 *cache.Cache

func LoadCache() error {
	return ArticaRestCache.LoadFile(cacheFile)
}

func Init() {
	ArticaRestCache = cache.New(CacheRetention, 10*time.Minute)
	_ = LoadCache()
}
func Init6() {
	Cache6 = cache.New(CacheRetention, 360*time.Minute)
	if Cache6 != nil {
		if fileExists(cacheFile) {
			_ = Cache6.LoadFile(cache6File)
		}
	}
}

func GetBinCache(sBin string) string {
	if Cache6 == nil {
		Init6()
		return ""
	}
	cachedValue, ok := Cache6.Get(sBin)
	if ok {
		return cachedValue.(string)
	}
	return ""
}
func SetBin(sBin string, value string) {
	if Cache6 == nil {
		Init6()
	}
	Cache6.Set(sBin, value, 30*time.Minute)
}

func GetStringFunc() string {
	if Cache6 == nil {
		Init6()
		return ""
	}

	pc, file, _, ok := runtime.Caller(1)
	if !ok {
		return ""
	}
	file = Basename(file)
	fn := runtime.FuncForPC(pc)

	TheKey := fmt.Sprintf("%s.%v", file, fn.Name())
	cachedValue, ok := Cache6.Get(TheKey)
	if ok {
		return cachedValue.(string)
	}
	return ""

}
func SetStringFunc(res string) {
	pc, file, _, ok := runtime.Caller(1)
	if !ok {
		return
	}
	if Cache6 == nil {
		Init6()
	}
	file = Basename(file)
	fn := runtime.FuncForPC(pc)

	TheKey := fmt.Sprintf("%s.%v", file, fn.Name())
	Cache6.Set(TheKey, res, 360*time.Minute)
}
func FlushStringFunc() {
	if Cache6 == nil {
		Init6()
		return
	}

	Cache6.Flush()
}
func Get6(key string) (interface{}, bool) {
	if ArticaRestCache == nil {
		Init6()
	}
	return Cache6.Get(key)
}
func Del6(key string) {
	if ArticaRestCache == nil {
		Init6()
	}
	Cache6.Delete(key)
}
func Set6(key string, value interface{}) {

	if ArticaRestCache == nil {
		Init6()
	}
	Cache6.Set(key, value, CacheRetention)
}
func Get(key string) (interface{}, bool) {
	if ArticaRestCache == nil {
		Init()
	}
	return ArticaRestCache.Get(key)
}

func Set(key string, value interface{}) {

	if ArticaRestCache == nil {
		Init()
	}
	ArticaRestCache.Set(key, value, CacheRetention)
}
func Set1hour(key string, value interface{}) {
	if ArticaRestCache == nil {
		Init()
	}
	ArticaRestCache.Set(key, value, 1*time.Hour)
}
func Set10Mins(key string, value interface{}) {
	if ArticaRestCache == nil {
		Init()
	}
	ArticaRestCache.Set(key, value, 10*time.Minute)
}
func Set3Mins(key string, value interface{}) {
	if ArticaRestCache == nil {
		Init()
	}
	ArticaRestCache.Set(key, value, 3*time.Minute)
}
func Set1hourMapInStringString(key string, value map[int]map[string]string) {
	if ArticaRestCache == nil {
		Init()
	}
	ArticaRestCache.Set(key, value, 1*time.Hour)
}
func Set1hourMapInString(key string, value map[int]string) {
	if ArticaRestCache == nil {
		Init()
	}
	ArticaRestCache.Set(key, value, 1*time.Hour)
}

func Set1hourJson(key string, value interface{}) {
	if ArticaRestCache == nil {
		Init()
	}
	ArticaRestCache.Set(key, value, 1*time.Hour)
}
func SaveCache() error {
	createDir("/var/db/artica-postfix")
	if Cache6 != nil {
		_ = Cache6.SaveFile(cache6File)
	}
	return ArticaRestCache.SaveFile(cacheFile)

}
func DeleteKey(key string) {
	if ArticaRestCache == nil {
		Init()
	}
	ArticaRestCache.Delete(key)
}
func fileExists(spath string) bool {
	spath = strings.TrimSpace(spath)
	if isLink(spath) {
		return true
	}

	if _, err := os.Stat(spath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}
func isLink(path string) bool {

	info, err := os.Lstat(path)
	if err != nil {
		return false
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return false
}
func Basename(path string) string {
	return filepath.Base(path)
}
func createDir(directoryPath string) {
	directoryPath = strings.TrimSpace(directoryPath)
	if directoryPath == "" {
		return
	}
	tb := strings.Split(directoryPath, "/")
	if len(tb) < 2 || !strings.Contains(directoryPath, "/") {
		for skip := 0; ; skip++ {
			pc, file, _, ok := runtime.Caller(skip)
			if !ok {
				break
			}
			funcName := runtime.FuncForPC(pc).Name()
			funcName = strings.ReplaceAll(funcName, "/home/dtouzeau/go/src/github.com/dtouzeau/", "")
			file = strings.ReplaceAll(file, "/home/dtouzeau/go/src/github.com/dtouzeau/", "")
			funcName = strings.ReplaceAll(funcName, "github.com/dtouzeau/articarest/", "")
			funcName = strings.ReplaceAll(funcName, "articarest/dnsdist/", "")

		}
	}
	directoryPath = strings.TrimSpace(directoryPath)
	directoryPath = strings.ReplaceAll(directoryPath, `'`, "")
	directoryPath = strings.ReplaceAll(directoryPath, `"`, "")
	directoryPath = strings.TrimSpace(directoryPath)
	_, err := os.Stat(directoryPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(directoryPath, 0755)
		if err != nil {
			return
		}
		return
	}
}

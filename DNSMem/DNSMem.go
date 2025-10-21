package DNSMem

import (
	"github.com/patrickmn/go-cache"
	"time"
)

const cacheFile = "/var/db/artica-postfix/dns.cache"
const CacheRetention = 3 * time.Minute

var DNSCache *cache.Cache

func LoadCache() error {
	return DNSCache.LoadFile(cacheFile)
}

func Init() {
	DNSCache = cache.New(CacheRetention, 10*time.Minute)
	_ = LoadCache()
}

func Get(key string) (interface{}, bool) {
	if DNSCache == nil {
		Init()
	}
	return DNSCache.Get(key)
}

func Set(key string, value interface{}) {

	if DNSCache == nil {
		Init()
	}
	DNSCache.Set(key, value, CacheRetention)
}
func Set1hour(key string, value interface{}) {
	if DNSCache == nil {
		Init()
	}
	DNSCache.Set(key, value, 1*time.Hour)
}
func Set10Mins(key string, value interface{}) {
	if DNSCache == nil {
		Init()
	}
	DNSCache.Set(key, value, 10*time.Minute)
}
func Set3Mins(key string, value interface{}) {
	if DNSCache == nil {
		Init()
	}
	DNSCache.Set(key, value, 3*time.Minute)
}
func Set1hourMapInStringString(key string, value map[int]map[string]string) {
	if DNSCache == nil {
		Init()
	}
	DNSCache.Set(key, value, 1*time.Hour)
}
func Set1hourMapInString(key string, value map[int]string) {
	if DNSCache == nil {
		Init()
	}
	DNSCache.Set(key, value, 1*time.Hour)
}

func Set1hourJson(key string, value interface{}) {
	if DNSCache == nil {
		Init()
	}
	DNSCache.Set(key, value, 1*time.Hour)
}
func SaveCache() error {
	return DNSCache.SaveFile(cacheFile)

}
func DeleteKey(key string) {
	if DNSCache == nil {
		Init()
	}
	DNSCache.Delete(key)
}

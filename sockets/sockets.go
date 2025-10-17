package sockets

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/leeqvip/gophp"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

var ctx = context.Background()

const expiration = 172800 * time.Second

func TempGet(key string) (interface{}, bool) {
	c := NeMemCache()
	return c.Get(key)

}
func SetTemp(key string, value interface{}) {
	c := NeMemCache()
	c.Set(key, value)
}
func DeleteTemp(key string) {
	c := NeMemCache()
	c.Delete(key)
	RemoveCache(key)
	DELETE_KEY(key)
	if !strings.HasPrefix(key, "SET:") {
		keyToFind := fmt.Sprintf("SET:%v", key)
		c := NeMemCache()
		c.Delete(keyToFind)
		RemoveCache(keyToFind)

	}

}
func ResetMemoryCache() {
	c := NeMemCache()
	c.Flush()
}

func ResetTempCache() {
	var TheCall string
	pc, Srcfile, line, ok := runtime.Caller(1)
	if ok {
		file := filepath.Base(Srcfile)
		fn := runtime.FuncForPC(pc)
		TheCall = fmt.Sprintf("%s.%v.%d", file, fn.Name(), line)
		TheCall = strings.ReplaceAll(TheCall, "/", ".")
	}

	log.Info().Msgf("%v reset parameters...by %v", getCalleRuntime(), TheCall)
	c := NeMemCache()
	c.Flush()
	_ = resetRedisKeys()
}

func GET_INFO_INT(key string) int64 {
	key = strings.TrimSpace(key)
	if len(key) < 2 {
		log.Error().Msgf("%v sent a key name < 2 [%v]", getCalleRuntime(), key)
		return 0
	}

	val := GET_INFO_STR(key)
	if len(val) == 0 {
		return 0
	}
	return StrToInt64(val)

}

func GET_INFO_STR(key string) string {
	if len(key) < 2 {
		return ""
	}
	var keyToFind string
	if !strings.HasPrefix(key, "SET:") {
		keyToFind = fmt.Sprintf("SET:%v", key)
	} else {
		keyToFind = key
	}
	cachedValue, found := TempGet(keyToFind)
	if found {
		if v, ok := cachedValue.(string); ok {
			if v == "!nil" {
				return ""
			}
			return v
		}
	}
	err, val := memcacheGet(keyToFind)
	tfile := fmt.Sprintf("/etc/artica-postfix/settings/Daemons/%s", key)

	if err != nil {
		if !fileExists(tfile) {
			SetTemp(keyToFind, "")
			return ""
		}
		val = strings.TrimSpace(fileGetContents(tfile))
		if len(val) == 0 || val == "!nil" {
			SetTemp(key, "")
			return ""
		}
		SetTemp(keyToFind, val)
		SetCache(keyToFind, val)
		return val
	}
	val = strings.TrimSpace(val)

	if len(val) == 0 {
		if fileExists(tfile) {
			val = strings.TrimSpace(fileGetContents(tfile))
			if len(val) == 0 || val == "!nil" {
				SetTemp(keyToFind, "")
				return ""
			}

			SetTemp(keyToFind, val)
			SetCache(keyToFind, val)
			return val
		}
	}
	SetTemp(keyToFind, val)
	if val == "!nil" {
		return ""
	}
	return strings.TrimSpace(val)
}
func fileGetContents(filename string) string {
	if !fileExists(filename) {
		return ""
	}
	tk, err := os.ReadFile(filename)
	if err != nil {
		return ""
	}
	tk = bytes.TrimSpace(tk)
	return string(tk)
}
func InitializeMemCacheClient() *redis.Client {
	client := redis.NewClient(&redis.Options{
		Network: "unix",
		Addr:    "/run/redis/redis.sock",
	})

	_, err := client.Ping(ctx).Result()
	if err != nil {
		//log.Error().Msgf("%v Error connecting to Redis: %v", getCalleRuntime(), err)
		return nil
	}

	return client
}
func GetMemCacheClient() *redis.Client {
	return InitializeMemCacheClient()
}
func StrToInt64(svalue string) int64 {
	svalue = strings.TrimSpace(svalue)
	n, err := strconv.ParseInt(svalue, 10, 64)
	if err == nil {
		return n
	}
	return 0
}
func SET_INFO_INT(key string, svalue int64) bool {
	if len(key) < 2 {
		return true
	}
	svalueStr := strconv.FormatInt(svalue, 10)
	keyToFind := fmt.Sprintf("SET:%v", key)
	SetTemp(keyToFind, svalueStr)

	if !memcacheSet(keyToFind, svalueStr) {
		//log.Error().Msgf("SET_INFO_INT(%v) Unable to set", keyToFind)
	}
	tfile := fmt.Sprintf("/etc/artica-postfix/settings/Daemons/%s", key)
	_ = filePutContents(tfile, svalueStr)
	return true
}
func DELETE_KEY(key string) {
	keyToFind := fmt.Sprintf("SET:%v", key)
	DelKey(keyToFind)
	tfile := fmt.Sprintf("/etc/artica-postfix/settings/Daemons/%s", key)
	_ = os.Remove(tfile)
}
func DelKey(key string) {
	mcClient := GetMemCacheClient()
	if mcClient == nil {
		return
	}
	_ = mcClient.Del(ctx, key).Err()
}
func SET_MAP1(key string, m map[string]string) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", "  ") // Pretty-print JSON

	err := encoder.Encode(m)
	if err != nil {
		return
	}
	SET_INFO_STR(key, buf.String())

}
func GET_MAP1(key string) map[string]string {
	m := make(map[string]string)

	jsonStr := GET_INFO_STR(key)
	err := json.Unmarshal([]byte(jsonStr), &m)
	if err != nil {
		return m
	}

	// Return the map
	return m
}
func SET_INFO_STR(key string, svalue string) bool {
	TDir := "/etc/artica-postfix/settings/Daemons"
	svalue = strings.TrimSpace(svalue)
	if len(key) < 2 {
		return true
	}
	key = strings.ReplaceAll(key, "SET:SET:", "")
	key = strings.ReplaceAll(key, "SET:", "")
	keyToFind := fmt.Sprintf("SET:%v", key)

	if len(svalue) == 0 {
		SetTemp(keyToFind, "!nil")
	} else {
		SetTemp(keyToFind, svalue)
	}

	tfile := fmt.Sprintf("/etc/artica-postfix/settings/Daemons/%s", key)
	if isDirDirectory(tfile) {
		_ = os.RemoveAll(tfile)
	}
	if len(svalue) == 0 {
		DELETE_KEY(keyToFind)
		_ = os.Remove(tfile)
		return true
	}

	createDir(TDir)
	chmod(TDir, 0755)
	chownFolder(TDir, "www-data", "www-data")
	_ = filePutContents(tfile, svalue)
	chownFile(tfile, "www-data", "www-data")
	return memcacheSet(keyToFind, svalue)

}
func ListAllKeys() {
	mcClient := GetMemCacheClient()
	if mcClient == nil {
		fmt.Println("ListAllKeys() Error: client is nil")
	}
	keys, err := mcClient.Keys(ctx, "*").Result()
	if err != nil {
		log.Error().Msgf("ListAllKeys: Error keys: %v", err)
	}
	for _, TargetKey := range keys {
		val, _ := mcClient.Get(ctx, TargetKey).Result()

		ttl, err := mcClient.TTL(ctx, TargetKey).Result()
		if err != nil {
			log.Error().Err(err).Msgf("TTL(%s)", TargetKey)
			continue
		}

		switch {
		case ttl == -2*time.Second:
			// key does not exist
			fmt.Printf("%s\tmissing\n", TargetKey)
		case ttl == -1*time.Second:
			// key exists but has no expiration
			fmt.Printf("%s\t(no expiry)\tval=%d bytes\n", TargetKey, len(val))
		default:
			// key has an expiration
			expAt := time.Now().Add(ttl)
			fmt.Printf("%s\tTTL=%s\tExpiresAt=%s\tval=%q\n", TargetKey, ttl, expAt.Format(time.RFC3339), val)
		}

	}

}

func resetallKeys() error {
	mcClient := GetMemCacheClient()
	log.Warn().Msgf("resetallKeys: Clean all keys...")
	if mcClient == nil {
		return fmt.Errorf("resetallKeys() Error: client is nil")
	}
	keys, err := mcClient.Keys(ctx, "*").Result()

	if err != nil {
		log.Error().Msgf("resetallKeys: Error keys: %v", err)
	}
	for _, TargetKey := range keys {
		if !strings.HasPrefix(TargetKey, "SET:") {
			continue
		}

		if strings.HasPrefix(TargetKey, "PHPREDIS") {
			continue
		}

		mcClient.Del(ctx, TargetKey)
	}
	_ = SweepAsync(ctx, mcClient)

	return nil
}
func SweepAsync(ctx context.Context, c *redis.Client) error {
	// Returns a simple string reply like "OK" (implementation-defined).
	res, err := c.Do(ctx, "SWEEP", "ASYNC").Text()
	if err != nil {
		return fmt.Errorf("SWEEP ASYNC: %w", err)
	}
	log.Info().Msgf("pogocache sweep async: %s", res)
	return nil
}

func resetRedisKeys() error {
	mcClient := GetMemCacheClient()
	if mcClient == nil {
		return fmt.Errorf("resetRedisKeys() Error: client is nil")
	}

	var cursor uint64
	var keys []string

	// Iterate using SCAN until the cursor returns 0
	for {
		var err error
		var k []string
		k, cursor, err = mcClient.Scan(ctx, cursor, "SET:*", 10).Result()
		if err != nil {
			if strings.Contains(err.Error(), "unknown command") {
				return resetallKeys()
			}
			log.Error().Msgf("resetRedisKeys: Error scanning keys: %v", err)
		}

		keys = append(keys, k...)
		if cursor == 0 {
			break
		}
	}
	for _, TargetKey := range keys {
		if strings.HasPrefix(TargetKey, "PHPREDIS") {
			continue
		}

		mcClient.Del(ctx, TargetKey)
	}
	return nil
}
func memcacheGet(key string) (error, string) {

	if !strings.HasPrefix(key, "SET:") {
		key = fmt.Sprintf("SET:%v", key)
	}

	mcClient := GetMemCacheClient()
	if mcClient == nil {
		return fmt.Errorf("memcacheGet() Error: client is nil"), ""
	}

	defer func(mcClient *redis.Client) {
		_ = mcClient.Close()
	}(mcClient)

	sitem, err := mcClient.Get(ctx, key).Result()

	if errors.Is(err, redis.Nil) {
		return fmt.Errorf("key not found"), ""
	} else if err != nil {
		log.Error().Msgf("Error getting key: %v %v", key, err)
		return err, ""
	}
	return nil, sitem
}
func getCalleRuntime() string {
	if pc, file, line, ok := runtime.Caller(1); ok {
		file = file[strings.LastIndex(file, "/")+1:]
		funcName := runtime.FuncForPC(pc).Name()
		funcName = strings.ReplaceAll(funcName, "github.com/dtouzeau/articarest/", "")
		funcName = strings.ReplaceAll(funcName, "articarest/dnsdist/", "")

		return fmt.Sprintf("%s[%s:%d]", file, funcName, line)
	}
	return ""
}
func MemCacheGetMap(sKey string) map[int]map[string]int {
	if !strings.HasPrefix(sKey, "SET:") {
		sKey = fmt.Sprintf("SET:%v", sKey)
	}
	retrievedMap := make(map[int]map[string]int)
	err, item := memcacheGet(sKey)
	if err != nil {
		memcacheError := err.Error()
		if strings.Contains(memcacheError, "cache miss") {
			return retrievedMap
		}
		if strings.Contains(memcacheError, "connection refused") {
			return retrievedMap
		}
		if strings.Contains(memcacheError, "connect: no such file") {
			return retrievedMap
		}
		log.Error().Msgf("%v: [%v] Error [%v]", getCalleRuntime(), sKey, memcacheError)
		return retrievedMap
	}
	err = json.Unmarshal([]byte(item), &retrievedMap)
	if err != nil {
		log.Error().Msgf("%v Error decoding JSON data: %v", getCalleRuntime(), err.Error())
	}
	return retrievedMap
}
func MemCacheSetMap(sKey string, MapArray map[int]map[string]int, MaxTimeSec int) bool {
	mcClient := GetMemCacheClient()

	if mcClient == nil {
		log.Error().Msgf("%v mcClient is nil !!", getCalleRuntime())
		return false
	}
	if ctx == nil {
		log.Error().Msgf("%v Context is nil in MemCacheSetMap", getCalleRuntime())
		return false
	}

	if !strings.HasPrefix(sKey, "SET:") {
		sKey = fmt.Sprintf("SET:%v", sKey)
	}
	if MaxTimeSec == 0 {
		MaxTimeSec = 300
	}
	defer func(mcClient *redis.Client) {
		err := mcClient.Close()
		if err != nil {

		}
	}(mcClient)

	ttl := time.Duration(MaxTimeSec) * time.Second

	jsonData, err := json.Marshal(MapArray)
	if err != nil {
		log.Error().Msgf("%v [%v] Error serializing map: %v", getCalleRuntime(), sKey, err.Error())
		return false
	}

	status := mcClient.Set(ctx, sKey, jsonData, ttl)

	if err := status.Err(); err != nil {
		log.Error().Msgf("%v Error setting key: %v", getCalleRuntime(), err)
		return false
	}

	return true

}
func SaveFreeKey(Key, value string, ExpireMins int) {
	FinalExpire := time.Duration(ExpireMins) * time.Second
	c := NeMemCache()
	c.Set(Key, value)

	mcClient := GetMemCacheClient()
	if mcClient == nil {
		return
	}
	defer func(mcClient *redis.Client) {
		_ = mcClient.Close()
	}(mcClient)

	status := mcClient.Set(ctx, Key, value, FinalExpire)
	if err := status.Err(); err != nil {
		log.Error().Msgf("%v Error setting key: %v", getCalleRuntime(), err)
		return
	}
}
func RemoveCache(key string) {
	mcClient := GetMemCacheClient()
	if mcClient == nil {
		return
	}
	defer func(mcClient *redis.Client) {
		_ = mcClient.Close()
	}(mcClient)

	mcClient.Del(ctx, key)
}
func SetCache(key, value string) bool {
	mcClient := GetMemCacheClient()
	if mcClient == nil {
		return false
	}
	defer func(mcClient *redis.Client) {
		_ = mcClient.Close()
	}(mcClient)

	status := mcClient.Set(ctx, key, value, expiration)
	if err := status.Err(); err != nil {
		log.Error().Msgf("%v Error setting key: %v", getCalleRuntime(), err)
		return false
	}

	return true
}
func SetCacheTime(key, value string, TimeMin int) bool {
	value = strings.TrimSpace(value)
	mcClient := GetMemCacheClient()
	if mcClient == nil {
		return false
	}

	zExpiration := time.Duration(TimeMin) * time.Minute

	c := NeMemCache()
	c.Set(key, value)

	defer func(mcClient *redis.Client) {
		_ = mcClient.Close()
	}(mcClient)

	status := mcClient.Set(ctx, key, value, zExpiration)
	if err := status.Err(); err != nil {
		log.Error().Msgf("%v Error setting key: %v", getCalleRuntime(), err)
		return false
	}

	return true
}
func ListKeys(search string) (error, []string) {
	mcClient := GetMemCacheClient()
	if mcClient == nil {
		return fmt.Errorf("CountKeys() Error: client is nil"), []string{}
	}
	defer func(mcClient *redis.Client) {
		err := mcClient.Close()
		if err != nil {

		}
	}(mcClient)

	keys, err := mcClient.Keys(ctx, search).Result()
	if err != nil {
		return fmt.Errorf("CountKeys() Error fetching keys: %v", err), []string{}
	}

	return nil, keys
}
func CountKeys(search string) (error, int) {
	mcClient := GetMemCacheClient()
	if mcClient == nil {
		return fmt.Errorf("CountKeys() Error: client is nil"), 0
	}
	defer func(mcClient *redis.Client) {
		err := mcClient.Close()
		if err != nil {

		}
	}(mcClient)

	keys, err := mcClient.Keys(ctx, search).Result()
	if err != nil {
		return fmt.Errorf("CountKeys() Error fetching keys: %v", err), 0
	}

	return nil, len(keys)
}
func GetCache(key string) (error, string) {

	cachedValue, found := TempGet(key)
	if found {
		if v, ok := cachedValue.(string); ok {
			return nil, v
		}
	}

	mcClient := GetMemCacheClient()
	if mcClient == nil {
		return fmt.Errorf("GetCache() Error: client is nil"), ""
	}

	defer func(mcClient *redis.Client) {
		_ = mcClient.Close()

	}(mcClient)
	sitem, err := mcClient.Get(ctx, key).Result()

	if err == redis.Nil {
		return fmt.Errorf("key not found"), ""
	} else if err != nil {
		log.Error().Msgf("Error getting key: %v %v", key, err)
		return err, ""
	}
	sitem = strings.TrimSpace(sitem)
	if sitem == "!nil" {
		sitem = ""
	}

	return nil, sitem
}
func MemcacheSetDel(skey string) bool {
	if !strings.HasPrefix(skey, "SET:") {
		skey = fmt.Sprintf("SET:%v", skey)
	}
	mcClient := GetMemCacheClient()
	if mcClient == nil {
		log.Error().Msgf("memcacheDel: client is nil")
		return false
	}
	defer func(mcClient *redis.Client) {
		err := mcClient.Close()
		if err != nil {

		}
	}(mcClient)
	log.Debug().Msgf("%v Remove Key %v", getCalleRuntime(), skey)
	status := mcClient.Del(ctx, skey)
	if err := status.Err(); err != nil {
		log.Error().Msgf("%v Error deleting key: %v", getCalleRuntime(), err)
		return false
	}

	return true
}
func memcacheSet(skey string, svalue string) bool {
	if !strings.HasPrefix(skey, "SET:") {
		skey = fmt.Sprintf("SET:%v", skey)
	}
	mcClient := GetMemCacheClient()
	if mcClient == nil {
		return false
	}

	defer func(mcClient *redis.Client) {
		_ = mcClient.Close()
	}(mcClient)
	status := mcClient.Set(ctx, skey, svalue, expiration)

	if err := status.Err(); err != nil {
		log.Error().Msgf("%v Error setting key: %v", getCalleRuntime(), err)
		return false
	}

	return true
}
func fileExists(spath string) bool {
	if _, err := os.Stat(spath); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}
func filePutContents(filename string, data string) error {
	return os.WriteFile(filename, []byte(data), 0644)
}
func createDir(directoryPath string) {
	_, err := os.Stat(directoryPath)
	if os.IsNotExist(err) {
		err := os.MkdirAll(directoryPath, 0755)
		if err != nil {
			return
		}
		return
	}
}
func chmod(TargetPath string, desiredMode os.FileMode) {
	if !fileExists(TargetPath) {
		return
	}
	err := os.Chmod(TargetPath, desiredMode)
	if err != nil {
		return
	}
}
func chownFolder(folder string, username string, group string) {

	if !isDirDirectory(folder) {
		return
	}
	chmod(folder, 0755)
	u, err := user.Lookup(username)
	if err != nil {
		return
	}
	err = os.Chown(folder, strToInt(u.Uid), strToInt(u.Gid))
	if err != nil {
		return
	}

}
func isDirDirectory(directoryPath string) bool {

	if _, err := os.Stat(directoryPath); os.IsNotExist(err) {
		return false
	}
	return true
}
func chownFile(FilePath string, username string, group string) {
	if !fileExists(FilePath) {
		return
	}
	chmod(FilePath, 0755)
	u, err := user.Lookup(username)
	if err != nil {
		return
	}
	err = os.Chown(FilePath, strToInt(u.Uid), strToInt(u.Gid))
	if err != nil {
		return
	}
}
func strToInt(svalue string) int {
	svalue = strings.TrimSpace(svalue)
	if len(svalue) == 0 {
		return 0
	}
	tkint, err := strconv.Atoi(string(svalue))
	if err == nil {
		return tkint
	}
	return 0
}
func SET_INFO_MEM_INT(key string, svalue int64) bool {
	svalueStr := strconv.FormatInt(svalue, 10)
	SetTemp(key, svalueStr)
	memcacheSet(key, svalueStr)
	return true
}
func serialize(array map[string]interface{}) ([]byte, error) {
	serialize, err := gophp.Serialize(array)
	if err != nil {
		return nil, err
	}
	return serialize, nil
}
func base64Encode(input string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(input))
	return encoded
}
func SaveConfigFile(array map[string]interface{}, token string) {
	a, err := serialize(array)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("Error %s", err))
	}

	SET_INFO_STR(token, base64Encode(string(a)))
}
func GET_INFO_BOOL(key string) bool {

	val := GET_INFO_STR(key)

	if len(val) > 0 {
		if val == "!nil" {
			return false
		}
		boolValue, errConvert := strconv.ParseBool(val)
		if errConvert != nil {
			return false
		}
		return boolValue
	}
	return false

}
func DebianVersion(Cached bool) int64 {

	if Cached {
		DebianVersionInt := GET_INFO_INT("DebianVersionInt")
		if DebianVersionInt > 8 {
			return DebianVersionInt
		}
	}

	file, err := os.Open("/etc/os-release")
	if err != nil {
		return 0
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VERSION_ID=") {
			version := strings.Trim(strings.Split(line, "=")[1], `"`)
			SET_INFO_INT("DebianVersionInt", StrToInt64(version))
			return StrToInt64(version)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0
	}
	log.Error().Msg("getDebianVersion() VERSION_ID not found in /etc/os-release")
	return 0
}

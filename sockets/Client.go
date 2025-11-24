package sockets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/valkey-io/valkey-go"
)

var CnxCount int64
var UseMemCacheClient int64 // if set to 1, use memcache protocol instead of redis protocol

var (
	mu                  sync.Mutex
	cli                 valkey.Client    // interface; nil until initialized
	mcCli               *memcache.Client // memcache client
	primaryDSN          = "unix:///run/redis/redis.sock?db=0&dial_timeout=2s"
	fallbackDSN         = "redis://127.0.0.1:6379?db=0&dial_timeout=2s"
	currentDSN          = primaryDSN // tracks which DSN is currently in use
	memcacheUnixSocket  = "/run/artmem.sock"
	memcacheTCPServer   = "127.0.0.1:11155"
	currentMemcacheAddr = memcacheUnixSocket
)

func buildClient() valkey.Client {
	// Fast path: already initialized and healthy.
	if c := cli; c != nil && pingOK(c) {
		return c
	}

	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring the lock.
	if cli != nil && pingOK(cli) {
		return cli
	}
	if currentDSN == primaryDSN {
		if _, err := os.Stat("/run/redis/redis.sock"); os.IsNotExist(err) {
			currentDSN = fallbackDSN
		}
	}

	CnxCount++
	c, err := valkey.NewClient(valkey.MustParseURL(currentDSN))
	if err == nil && pingOK(c) {
		cli = c
		return cli
	}
	if c != nil {
		c.Close()
	}

	// If current DSN failed, try fallback
	var fallbackToTry string
	if currentDSN == primaryDSN {
		fallbackToTry = fallbackDSN
		TosyslogGen(fmt.Sprintf("Unix socket connection failed, attempting TCP fallback: %s", fallbackToTry))
	} else {
		fallbackToTry = primaryDSN
		TosyslogGen(fmt.Sprintf("TCP connection failed, attempting Unix socket: %s", fallbackToTry))
	}
	CnxCount++
	c, err = valkey.NewClient(valkey.MustParseURL(fallbackToTry))
	if err == nil && pingOK(c) {
		currentDSN = fallbackToTry
		cli = c
		TosyslogGen(fmt.Sprintf("Successfully connected using: %s", currentDSN))
		return cli
	}
	if c != nil {
		c.Close()
	}
	TosyslogGen("Both Unix socket and TCP connection failed")
	return nil
}

func buildMemcacheClient() *memcache.Client {
	// Fast path: already initialized and test if it works
	if mcCli != nil {
		// Quick health check
		if err := mcCli.Ping(); err == nil {
			return mcCli
		}
		// If ping failed, close and reconnect
		mcCli = nil
	}

	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring the lock
	if mcCli != nil {
		if err := mcCli.Ping(); err == nil {
			return mcCli
		}
		mcCli = nil
	}

	// Try current address (Unix socket by default)
	CnxCount++
	mcCli = memcache.New(currentMemcacheAddr)
	// Configure for single keepalive connection
	mcCli.Timeout = 2 * time.Second
	mcCli.MaxIdleConns = 1 // Single persistent connection

	// Test connection with a ping
	if err := mcCli.Ping(); err == nil {
		TosyslogGen(fmt.Sprintf("Memcache client connected to: %s (single keepalive)", currentMemcacheAddr))
		return mcCli
	}

	// If current address failed, try fallback
	var fallbackAddr string
	if currentMemcacheAddr == memcacheUnixSocket {
		fallbackAddr = memcacheTCPServer
		TosyslogGen(fmt.Sprintf("Memcache Unix socket failed, attempting TCP fallback: %s", fallbackAddr))
	} else {
		fallbackAddr = memcacheUnixSocket
		TosyslogGen(fmt.Sprintf("Memcache TCP failed, attempting Unix socket: %s", fallbackAddr))
	}

	CnxCount++
	mcCli = memcache.New(fallbackAddr)
	// Configure for single keepalive connection
	mcCli.Timeout = 2 * time.Second
	mcCli.MaxIdleConns = 1 // Single persistent connection

	if err := mcCli.Ping(); err == nil {
		currentMemcacheAddr = fallbackAddr
		TosyslogGen(fmt.Sprintf("Memcache successfully connected using: %s (single keepalive)", currentMemcacheAddr))
		return mcCli
	}

	TosyslogGen("Both Memcache Unix socket and TCP connection failed")
	return nil
}
func Close() {
	mu.Lock()
	defer mu.Unlock()
	if cli != nil {
		cli.Close()
		cli = nil
	}
}

func pingOK(c valkey.Client) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return c.Do(ctx, c.B().Ping().Build()).Error() == nil
}
func ValkeySetValue(key, value string, ttl time.Duration) error {
	if UseMemCacheClient == 1 {
		// Use memcache client
		mc := buildMemcacheClient()
		if mc == nil {
			return errors.New("memcache client not available")
		}

		item := &memcache.Item{
			Key:   key,
			Value: []byte(value),
		}

		if ttl > 0 {
			item.Expiration = int32(ttl.Seconds())
		}

		return mc.Set(item)
	}

	// Use Redis/Valkey protocol
	c := buildClient()
	if c == nil {
		return errors.New("valkey client not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var err error
	if ttl > 0 {
		// precise expiration
		err = c.Do(ctx, c.B().Set().Key(key).Value(value).Ex(ttl).Build()).Error()
	} else {
		err = c.Do(ctx, c.B().Set().Key(key).Value(value).Build()).Error()
	}
	return err
}
func ValkeyDelKey(key string) error {
	if UseMemCacheClient == 1 {
		// Use memcache client
		mc := buildMemcacheClient()
		if mc == nil {
			return errors.New("memcache client not available")
		}
		return mc.Delete(key)
	}

	// Use Redis/Valkey protocol
	c := buildClient()
	if c == nil {
		return errors.New("valkey client not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// DEL key -> returns number of keys removed; we ignore the count.
	return c.Do(ctx, c.B().Del().Key(key).Build()).Error()
}
func ValkeyGetValue(key string) (error, string) {
	if UseMemCacheClient == 1 {
		// Use memcache client
		mc := buildMemcacheClient()
		if mc == nil {
			return errors.New("memcache client not available"), ""
		}

		item, err := mc.Get(key)
		if err != nil {
			// Missing key => not an error for us: return empty string
			if err == memcache.ErrCacheMiss {
				return nil, ""
			}
			return fmt.Errorf("- ValkeyGetValue [%v]", err), ""
		}
		return nil, string(item.Value)
	}

	// Use Redis/Valkey protocol
	c := buildClient()
	if c == nil {
		return errors.New("valkey client not available"), ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	val, err := c.Do(ctx, c.B().Get().Key(key).Build()).ToString()
	if err != nil {
		// Missing key => not an error for us: return empty string
		if errors.Is(err, valkey.Nil) {
			return nil, ""
		}
		return fmt.Errorf("- ValkeyGetValue [%v]", err), ""
	}
	return nil, val
}
func ValkeyListAllKeys() {
	c := buildClient()
	if c == nil {
		fmt.Println("ValkeyListAllKeys() Error: client is nil")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if UseMemCacheClient == 1 {
		TosyslogGen("ValkeyListAllKeys() not supported in memcache protocol mode")
		return
	}

	var cursor uint64
	for {
		// SCAN cursor MATCH * COUNT 1000
		res := c.Do(ctx, c.B().Scan().Cursor(cursor).Match("*").Count(1000).Build())
		if err := res.Error(); err != nil {
			TosyslogGen(fmt.Sprintf("SCAN error: %v", err))
			return
		}

		arr, err := res.ToArray()
		if err != nil || len(arr) != 2 {
			TosyslogGen(fmt.Sprintf("unexpected SCAN response %v", arr))
			return
		}

		// arr[0] = new cursor (string), arr[1] = array of keys
		curStr, _ := arr[0].ToString()
		newCursor, _ := strconv.ParseUint(curStr, 10, 64)

		keysArr, _ := arr[1].ToArray()
		for _, kv := range keysArr {
			TargetKey, _ := kv.ToString()

			// GET
			valRes := c.Do(ctx, c.B().Get().Key(TargetKey).Build())
			_ = valRes.Error() // ignore missing errors (nil replies)
			val, _ := valRes.ToString()

			// TTL (seconds): -2=missing, -1=no expiry, ≥0=ttl seconds
			ttlRes := c.Do(ctx, c.B().Ttl().Key(TargetKey).Build())
			if err := ttlRes.Error(); err != nil {
				TosyslogGen(fmt.Sprintf("TTL error: %v for [%v]", err, TargetKey))
				continue
			}
			ttlSec, _ := ttlRes.ToInt64()

			switch ttlSec {
			case -2:
				fmt.Printf("%s\tmissing\n", TargetKey)
			case -1:
				fmt.Printf("%s\t(no expiry)\tval=%d bytes\n", TargetKey, len(val))
			default:
				ttl := time.Duration(ttlSec) * time.Second
				expAt := time.Now().Add(ttl)
				fmt.Printf("%s\tTTL=%s\tExpiresAt=%s\tval=%q\n", TargetKey, ttl, expAt.Format(time.RFC3339), val)
			}
		}

		cursor = newCursor
		if cursor == 0 {
			break
		}
	}
}
func ValkeyResetallKeys(ctx context.Context) error {
	c := buildClient()
	TosyslogGen(fmt.Sprintf("Reseting all keys"))
	if c == nil {
		return fmt.Errorf("resetallKeys() Error: client is nil")
	}

	if UseMemCacheClient == 1 {
		// Memcache protocol doesn't support key scanning
		// Use FLUSHDB to clear all keys
		TosyslogGen("Using FLUSHDB for memcache protocol mode")
		cmd := c.B().Arbitrary("FLUSHDB").Build()
		if err := c.Do(ctx, cmd).Error(); err != nil {
			return fmt.Errorf("FLUSHDB error: %w", err)
		}
		return nil
	}

	var cursor uint64
	for {
		// SCAN cursor MATCH "SET:*" COUNT 1000
		res := c.Do(ctx, c.B().Scan().Cursor(cursor).Match("SET:*").Count(1000).Build())
		if err := res.Error(); err != nil {
			return fmt.Errorf("SCAN error: %w", err)
		}

		arr, err := res.ToArray()
		if err != nil || len(arr) != 2 {
			return fmt.Errorf("unexpected SCAN response")
		}

		curStr, _ := arr[0].ToString()
		newCursor, _ := strconv.ParseUint(curStr, 10, 64)

		keysArr, _ := arr[1].ToArray()
		for _, kv := range keysArr {
			key, _ := kv.ToString()

			// skip PHPREDIS* keys
			if strings.HasPrefix(key, "PHPREDIS") {
				continue
			}

			if err := c.Do(ctx, c.B().Del().Key(key).Build()).Error(); err != nil {
				TosyslogGen(fmt.Sprintf("DEL(%s) failed: %v", key, err))
			}
		}

		cursor = newCursor
		if cursor == 0 {
			break
		}
	}

	// keep your existing cleanup if it accepts a valkey.Client
	_ = ValkeySweepAsync(ctx, c)

	return nil
}
func ValkeySweepAsync(ctx context.Context, c valkey.Client) error {
	// Builds: [SWEEP ASYNC]
	cmd := c.B().Arbitrary("SWEEP").Args("ASYNC").Build()

	// Many modules reply with a simple string like "OK"
	s, err := c.Do(ctx, cmd).ToString()
	if err != nil {
		return fmt.Errorf("SWEEP ASYNC: %w", err)
	}
	// use your logger if you prefer
	fmt.Printf("pogocache sweep async: %s\n", s)
	return nil
}
func ValkeyMemCacheSetMap(ctx context.Context, sKey string, mapArray map[int]map[string]int, maxTimeSec int) bool {
	if ctx == nil {
		TosyslogGen("MemCacheSetMap: context is nil")
		return false
	}

	if !strings.HasPrefix(sKey, "SET:") {
		sKey = fmt.Sprintf("SET:%s", sKey)
	}
	if maxTimeSec == 0 {
		maxTimeSec = 300
	}

	jsonData, err := json.Marshal(mapArray)
	if err != nil {
		TosyslogGen(fmt.Sprintf("MemCacheSetMap[%s]: marshal error", sKey))
		return false
	}

	if UseMemCacheClient == 1 {
		// Use memcache client
		mc := buildMemcacheClient()
		if mc == nil {
			TosyslogGen("MemCacheSetMap: memcache client is nil")
			return false
		}

		item := &memcache.Item{
			Key:        sKey,
			Value:      jsonData,
			Expiration: int32(maxTimeSec),
		}

		if err := mc.Set(item); err != nil {
			TosyslogGen(fmt.Sprintf("MemCacheSetMap[%s]: SET failed", sKey))
			return false
		}
		return true
	}

	// Use Redis/Valkey protocol
	c := buildClient()
	if c == nil {
		TosyslogGen("MemCacheSetMap: valkey client is nil")
		return false
	}

	ttl := time.Duration(maxTimeSec) * time.Second
	cmd := c.B().Set().Key(sKey).Value(string(jsonData)).Ex(ttl).Build()
	if err := c.Do(ctx, cmd).Error(); err != nil {
		TosyslogGen(fmt.Sprintf("MemCacheSetMap[%s]: SET failed", sKey))
		return false
	}
	return true
}
func ValkeyListKeys(search string) (error, []string) {
	c := buildClient()
	if c == nil {
		return fmt.Errorf("ListKeys() Error: client is nil"), nil
	}

	if UseMemCacheClient == 1 {
		// Memcache protocol doesn't support key scanning
		// Return error indicating this operation is not supported
		return fmt.Errorf("ListKeys() not supported in memcache protocol mode"), nil
	}

	var (
		cursor uint64
		out    []string
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		// SCAN cursor MATCH <search> COUNT 1000
		res := c.Do(ctx, c.B().Scan().Cursor(cursor).Match(search).Count(1000).Build())
		if err := res.Error(); err != nil {
			return fmt.Errorf("ListKeys() SCAN error: %w", err), nil
		}

		arr, err := res.ToArray()
		if err != nil || len(arr) != 2 {
			return fmt.Errorf("ListKeys() unexpected SCAN response"), nil
		}

		curStr, _ := arr[0].ToString()
		newCursor, _ := strconv.ParseUint(curStr, 10, 64)

		keysArr, _ := arr[1].ToArray()
		for _, kv := range keysArr {
			k, _ := kv.ToString()
			out = append(out, k)
		}

		cursor = newCursor
		if cursor == 0 {
			break
		}
	}

	return nil, out
}
func ValkeyCountKeys(search string) (error, int) {
	c := buildClient()
	if c == nil {
		return fmt.Errorf("CountKeys() Error: client is nil"), 0
	}
	if search == "" {
		search = "*"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if UseMemCacheClient == 1 {
		// Memcache protocol doesn't support key scanning
		// Return error indicating this operation is not supported
		return fmt.Errorf("CountKeys() not supported in memcache protocol mode"), 0
	}

	var (
		cursor uint64
		count  int
	)

	for {
		// SCAN <cursor> MATCH <search> COUNT 1000
		res := c.Do(ctx, c.B().Scan().Cursor(cursor).Match(search).Count(1000).Build())
		if err := res.Error(); err != nil {
			return fmt.Errorf("CountKeys() SCAN error: %w", err), 0
		}

		arr, err := res.ToArray()
		if err != nil || len(arr) != 2 {
			return fmt.Errorf("CountKeys() unexpected SCAN response"), 0
		}

		// next cursor
		curStr, _ := arr[0].ToString()
		next, _ := strconv.ParseUint(curStr, 10, 64)

		// keys array
		keysArr, _ := arr[1].ToArray()
		count += len(keysArr)

		cursor = next
		if cursor == 0 {
			break
		}
	}

	return nil, count
}

// ValkeyFlush flushes the Valkey database to disk
// Uses SAVE for synchronous (blocking) save or BGSAVE for background save
func ValkeyFlush(async bool) error {
	c := buildClient()
	if c == nil {
		return errors.New("valkey client not available")
	}

	if UseMemCacheClient == 1 {
		// Memcache protocol doesn't support SAVE/BGSAVE
		// These are Redis-specific persistence commands
		TosyslogGen("ValkeyFlush: SAVE/BGSAVE not supported in memcache protocol mode")
		return fmt.Errorf("ValkeyFlush not supported in memcache protocol mode")
	}

	var (
		cmd     valkey.Completed
		timeout time.Duration
	)

	if async {
		// BGSAVE - background save (non-blocking)
		timeout = 5 * time.Second
		cmd = c.B().Arbitrary("BGSAVE").Build()
	} else {
		// SAVE - synchronous save (blocking, may take time for large datasets)
		timeout = 60 * time.Second
		cmd = c.B().Arbitrary("SAVE").Build()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := c.Do(ctx, cmd).Error(); err != nil {
		if async {
			return fmt.Errorf("BGSAVE failed: %w", err)
		}
		return fmt.Errorf("SAVE failed: %w", err)
	}

	return nil
}
func TosyslogGen(text string) bool {
	syslogger, err := syslog.New(syslog.LOG_INFO, "redis-client")
	text = fmt.Sprintf("cnx[%d]: %s", CnxCount, text)
	if err != nil {
		return false
	}
	_ = syslogger.Notice(text)
	_ = syslogger.Close()
	return true
}

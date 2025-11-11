package sockets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/valkey-io/valkey-go"
)

var (
	mu  sync.Mutex
	cli valkey.Client                                         // interface; nil until initialized
	dsn = "unix:///run/redis/redis.sock?db=0&dial_timeout=2s" // or tcp://127.0.0.1:6379
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

	c, err := valkey.NewClient(valkey.MustParseURL(dsn))
	if err != nil {
		return nil
	}
	if !pingOK(c) {
		c.Close()
		return nil
	}
	cli = c
	return cli
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
		// If your valkey-go version prefers milliseconds, use:
		// err = c.Do(ctx, c.B().Set().Key(key).Value(value).Px(ttl).Build()).Error()
	} else {
		err = c.Do(ctx, c.B().Set().Key(key).Value(value).Build()).Error()
	}
	return err
}
func ValkeyDelKey(key string) error {
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
	ctx := context.Background()

	var cursor uint64
	for {
		// SCAN cursor MATCH * COUNT 1000
		res := c.Do(ctx, c.B().Scan().Cursor(cursor).Match("*").Count(1000).Build())
		if err := res.Error(); err != nil {
			log.Error().Err(err).Msg("SCAN error")
			return
		}

		arr, err := res.ToArray()
		if err != nil || len(arr) != 2 {
			log.Error().Err(err).Msg("unexpected SCAN response")
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
				log.Error().Err(err).Msgf("TTL(%s)", TargetKey)
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
	log.Warn().Msg("resetallKeys: Clean all keys...")
	if c == nil {
		return fmt.Errorf("resetallKeys() Error: client is nil")
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
				log.Error().Err(err).Msgf("DEL(%s)", key)
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
	c := buildClient()
	if c == nil {
		log.Error().Msg("MemCacheSetMap: valkey client is nil")
		return false
	}
	if ctx == nil {
		log.Error().Msg("MemCacheSetMap: context is nil")
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
		log.Error().Err(err).Msgf("MemCacheSetMap[%s]: marshal error", sKey)
		return false
	}

	ttl := time.Duration(maxTimeSec) * time.Second

	// SET key value [EX ttl]
	cmd := c.B().Set().Key(sKey).Value(string(jsonData)).Ex(ttl).Build()
	if err := c.Do(ctx, cmd).Error(); err != nil {
		log.Error().Err(err).Msgf("MemCacheSetMap[%s]: SET failed", sKey)
		return false
	}
	return true
}
func ValkeyListKeys(search string) (error, []string) {
	c := buildClient()
	if c == nil {
		return fmt.Errorf("ListKeys() Error: client is nil"), nil
	}

	var (
		cursor uint64
		out    []string
	)

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

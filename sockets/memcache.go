package sockets

import (
	"sync"
	"time"
)

type Item struct {
	Value      any
	Expiration int64 // Unix timestamp in nanoseconds, 0 = no expiration
}

var CentralCache *Cache

// Cache represents the memory cache.
type Cache struct {
	data   map[string]Item
	mutex  sync.RWMutex
	ticker *time.Ticker
	done   chan struct{}
}

func NeMemCache() *Cache {
	if CentralCache == nil {
		CentralCache = New(60 * time.Minute)
	}
	return CentralCache
}

func New(cleanupInterval time.Duration) *Cache {
	c := &Cache{
		data:   make(map[string]Item),
		done:   make(chan struct{}),
		ticker: time.NewTicker(cleanupInterval),
	}

	go c.cleanupLoop()
	return c
}

// Set inserts a value with optional expiration.
func (c *Cache) Set(key string, value any) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var exp int64
	exp = time.Now().Add(time.Duration(3600) * time.Second).UnixNano()

	c.data[key] = Item{
		Value:      value,
		Expiration: exp,
	}
}

func (c *Cache) Flush() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.data = make(map[string]Item)
}

// Get retrieves a value. Returns nil if not found or expired.
func (c *Cache) Get(key string) (any, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, ok := c.data[key]
	if !ok || (item.Expiration > 0 && time.Now().UnixNano() > item.Expiration) {
		return nil, false
	}
	return item.Value, true
}

// Delete removes a key.
func (c *Cache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.data, key)
}

// cleanupLoop periodically removes expired items.
func (c *Cache) cleanupLoop() {
	for {
		select {
		case <-c.ticker.C:
			now := time.Now().UnixNano()
			c.mutex.Lock()
			for k, item := range c.data {
				if item.Expiration > 0 && now > item.Expiration {
					delete(c.data, k)
				}
			}
			c.mutex.Unlock()
		case <-c.done:
			return
		}
	}
}

// Stop cleanup goroutine.
func (c *Cache) Stop() {
	c.ticker.Stop()
	close(c.done)
}

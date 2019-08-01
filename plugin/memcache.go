package plugin

import (
	"bytes"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/servertime"
	"github.com/haxii/log"
)

// MemoryCachePool stores the response cache in concurrent map and delete the Expired ones periodically
type MemoryCachePool struct {
	p *memoryCachePool
}

func (c *MemoryCachePool) DeleteExpired() {
	c.p.deleteExpired()
}

func (c *MemoryCachePool) Get(key string) *MemoryCacheItem {
	_item, exists := c.p.Load(key)
	if !exists {
		return nil
	}
	item, ok := _item.(*MemoryCacheItem)
	if !ok {
		c.p.Delete(key)
		return nil
	} else if item.Expired() {
		c.p.Delete(key)
		return nil
	}
	return item
}

func (c *MemoryCachePool) set(key string, ttl time.Duration, resp []byte) {
	if ttl <= 0 {
		ttl = c.p.ttl
	}
	c.p.Store(key, &MemoryCacheItem{exp: servertime.CoarseTimeNow().Add(ttl), rawResp: resp})
}

type memoryCachePool struct {
	sync.Map
	ttl     time.Duration
	janitor *janitor
}

// Delete all expired items
func (c *memoryCachePool) deleteExpired() {
	c.Range(
		func(key, value interface{}) bool {
			item := value.(*MemoryCacheItem)
			if item.Expired() {
				c.Delete(key)
			}
			return true
		},
	)
}

var DefaultMemoryCacheTTL = time.Hour

func NewMemoryCachePool(ttl, cleanInterval time.Duration) *MemoryCachePool {
	if ttl <= 0 {
		ttl = DefaultMemoryCacheTTL
	}
	p := &memoryCachePool{ttl: ttl}
	P := &MemoryCachePool{p}
	if cleanInterval > 0 {
		runJanitor(p, cleanInterval)
		runtime.SetFinalizer(P, stopJanitor)
	}
	return P
}

type janitor struct {
	Interval time.Duration
	stop     chan bool
}

func (j *janitor) Run(p *memoryCachePool) {
	ticker := time.NewTicker(j.Interval)
	for {
		select {
		case <-ticker.C:
			p.deleteExpired()
		case <-j.stop:
			ticker.Stop()
			return
		}
	}
}

func stopJanitor(p *MemoryCachePool) {
	p.p.janitor.stop <- true
}

func runJanitor(p *memoryCachePool, ci time.Duration) {
	j := &janitor{
		Interval: ci,
		stop:     make(chan bool),
	}
	p.janitor = j
	go j.Run(p)
}

type MemoryCacheItem struct {
	exp     time.Time
	rawResp []byte
}

func (i *MemoryCacheItem) Expired() bool {
	return servertime.CoarseTimeNow().After(i.exp)
}

func (i *MemoryCacheItem) Value() []byte {
	return i.rawResp
}

type MemoryCache struct {
	pool *MemoryCachePool

	logger log.Logger
	cached bool

	key         string
	cacheReader *bytes.Reader

	cacheWriter     *bytes.Buffer
	expectCacheSize int64
	expectTTL       int
}

func (c *MemoryCache) Init(pool *MemoryCachePool, logger log.Logger, cacheKey string) {
	c.pool = pool
	c.logger = logger
	c.key = cacheKey
	c.expectCacheSize = -1
	c.expectTTL = -1
	item := c.pool.Get(cacheKey)
	if item != nil {
		c.cached = true
		c.cacheReader = bytes.NewReader(item.rawResp)
		c.cacheWriter = nil
		c.logger.Debug("MemoryCache", "%s, hit cache", cacheKey)
		return
	}
	c.cached = false
	c.cacheReader = nil
	c.cacheWriter = &bytes.Buffer{}
	c.logger.Debug("MemoryCache", "%s, not in cache, try to download", cacheKey)
}

func (c *MemoryCache) Cached() bool {
	return c.cached
}

func (c *MemoryCache) WriteHeader(statusLine http.ResponseLine, header http.Header, rawHeader []byte) error {
	var err error
	c.expectCacheSize, err = writeHeaderTo(c.cacheWriter, statusLine, header, rawHeader)
	if err != nil {
		return err
	}

	c.expectTTL = parseMaxAge(rawHeader)
	return nil
}

func parseMaxAge(rawHeader []byte) int {
	if cacheControlIndex := bytes.Index(rawHeader, []byte("Cache-Control")); cacheControlIndex >= 0 {
		if cacheControlEndIndex := bytes.Index(rawHeader[cacheControlIndex:], []byte("\n")); cacheControlEndIndex > 0 {
			cacheControlEndIndex = cacheControlIndex + cacheControlEndIndex
			cacheControlHeader := rawHeader[cacheControlIndex:cacheControlEndIndex]
			if maxAgeIndex := bytes.Index(cacheControlHeader, []byte("max-age")); maxAgeIndex > 0 {
				maxAgeEndIndex := bytes.IndexByte(cacheControlHeader[maxAgeIndex:], ';')
				if maxAgeEndIndex < 0 {
					maxAgeEndIndex = len(cacheControlHeader)
				} else {
					maxAgeEndIndex = maxAgeEndIndex + maxAgeIndex
				}
				maxAgeDef := cacheControlHeader[maxAgeIndex:maxAgeEndIndex]
				if sepIndex := bytes.IndexByte(maxAgeDef, '='); sepIndex > 0 {
					maxAgeBytes := maxAgeDef[sepIndex+1:]
					if maxAge, err := strconv.Atoi(string(bytes.TrimSpace(maxAgeBytes))); err == nil {
						return maxAge
					}
				}
			}
		}
	}
	return -1
}
func (c *MemoryCache) Write(p []byte) (n int, err error) {
	if c.cacheWriter == nil {
		return 0, errNothingToWrite
	}

	return c.cacheWriter.Write(p)
}

func (c *MemoryCache) Read(b []byte) (n int, err error) {
	if c.cacheReader == nil {
		return 0, errNothingToRead
	}
	return c.cacheReader.Read(b)
}

func (c *MemoryCache) Close() error {
	if c.cached || c.cacheWriter == nil {
		return nil
	}
	if c.cacheWriter.Len() < 1 {
		return errIncompleteDownload
	}
	if c.expectCacheSize > 0 && int64(c.cacheWriter.Len()) != c.expectCacheSize {
		c.logger.Error("MemoryCache", errIncompleteDownload,
			"expected cache length %d, got %d", c.expectCacheSize, c.cacheWriter.Len())
		return errIncompleteDownload
	}
	c.pool.set(c.key, time.Duration(c.expectTTL)*time.Second, c.cacheWriter.Bytes())
	return nil
}

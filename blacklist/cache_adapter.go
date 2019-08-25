package blacklist

import (
	"time"

	"github.com/allegro/bigcache"
)

type (
	cacheAdapter struct {
		conn *bigcache.BigCache
		ttl  int64
	}
)

// NewCacheAdapter is a factory function
func NewCacheAdapter(ttl int64) (Blacklist, error) {
	cache, err := bigcache.NewBigCache(bigcache.DefaultConfig(time.Duration(ttl) * time.Second))
	if err != nil {
		return nil, err
	}
	return &cacheAdapter{conn: cache, ttl: ttl}, nil
}

func (a *cacheAdapter) Add(tokenID string) error {
	return a.conn.Set(tokenID, []byte("revoked"))
}

func (a *cacheAdapter) Exists(tokenID string) bool {
	_, err := a.conn.Get(tokenID)
	return err != bigcache.ErrEntryNotFound
}

package blacklist

import "github.com/gomodule/redigo/redis"

type (
	redisAdapter struct {
		pool *redis.Pool
		ttl  int64
	}
)

// NewRedisAdapter is a factory function
func NewRedisAdapter(pool *redis.Pool, ttl int64) Blacklist {
	return &redisAdapter{pool: pool, ttl: ttl}
}

func (a *redisAdapter) Add(tokenID string) error {
	conn := a.pool.Get()
	defer conn.Close()
	_, err := conn.Do("SET", tokenID, 1, "EX", a.ttl)
	return err
}

func (a *redisAdapter) Exists(tokenID string) bool {
	conn := a.pool.Get()
	defer conn.Close()
	exists, _ := redis.Bool(conn.Do("EXISTS", tokenID))
	return exists
}

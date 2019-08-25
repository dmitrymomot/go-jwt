package blacklist

import "github.com/gomodule/redigo/redis"

type (
	redisAdapter struct {
		conn redis.Conn
		ttl  int64
	}
)

// NewRedisAdapter is a factory function
func NewRedisAdapter(conn redis.Conn, ttl int64) Blacklist {
	return &redisAdapter{conn: conn, ttl: ttl}
}

func (a *redisAdapter) Add(tokenID string) error {
	_, err := a.conn.Do("SET", tokenID, 1, "EX", a.ttl)
	return err
}

func (a *redisAdapter) Exists(tokenID string) bool {
	exists, _ := redis.Bool(a.conn.Do("EXISTS", tokenID))
	return exists
}

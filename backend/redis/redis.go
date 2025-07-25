package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type RedisSentinelConfig struct {
	SentinelHost     string `json:"sentinel_host"`
	SentinelPort     int    `json:"sentinel_port"`
	Password         string `json:"password"`
	MasterName       string `json:"master_name"`
	SentinelUsername string `json:"sentinel_username"`
	Namespace        string `json:"namespace"`
}

type RedisConfig struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Password  string `json:"password"`
	Namespace string `json:"namespace"`
}

func NewRedisClient(config *RedisConfig) (*redis.Client, error) {
	ctx := context.Background()
	addr := fmt.Sprintf("%v:%v", config.Host, config.Port)
	options := &redis.Options{
		Addr:     addr,
		Password: config.Password,
	}
	client := redis.NewClient(options)
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}

	return client, err
}

func NewRedisSentinelClient(config *RedisSentinelConfig) (*redis.Client, error) {
	ctx := context.Background()

	addr := fmt.Sprintf("%v:%v", config.SentinelHost, config.SentinelPort)
	sentinelOptions := &redis.FailoverOptions{
		MasterName:       config.MasterName,
		SentinelAddrs:    []string{addr},
		Username:         config.SentinelUsername,
		Password:         config.Password,
		SentinelUsername: config.SentinelUsername,
		SentinelPassword: config.Password,
	}

	client := redis.NewFailoverClient(sentinelOptions)
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis through Sentinel: %w", err)
	}

	return client, err
}

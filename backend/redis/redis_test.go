package redis

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedisConfig(t *testing.T) {
	config := &RedisConfig{
		Host:      "localhost",
		Port:      6379,
		Password:  "secret",
		Namespace: "test",
	}

	require.Equal(t, "localhost", config.Host)
	require.Equal(t, 6379, config.Port)
	require.Equal(t, "secret", config.Password)
	require.Equal(t, "test", config.Namespace)
}

func TestRedisSentinelConfig(t *testing.T) {
	config := &RedisSentinelConfig{
		SentinelHost:     "localhost",
		SentinelPort:     26379,
		Password:         "secret",
		MasterName:       "mymaster",
		SentinelUsername: "sentinel",
		Namespace:        "test",
	}

	require.Equal(t, "localhost", config.SentinelHost)
	require.Equal(t, 26379, config.SentinelPort)
	require.Equal(t, "secret", config.Password)
	require.Equal(t, "mymaster", config.MasterName)
	require.Equal(t, "sentinel", config.SentinelUsername)
	require.Equal(t, "test", config.Namespace)
}

func TestNewRedisClientInvalidHost(t *testing.T) {
	config := &RedisConfig{
		Host:     "invalid-redis-host-that-does-not-exist",
		Port:     6379,
		Password: "",
	}

	client, err := NewRedisClient(config)
	require.Error(t, err)
	require.Nil(t, client)
	require.Contains(t, err.Error(), "failed to connect to Redis")
}

func TestNewRedisClientInvalidPort(t *testing.T) {
	config := &RedisConfig{
		Host:     "localhost",
		Port:     99999, // Invalid port
		Password: "",
	}

	client, err := NewRedisClient(config)
	require.Error(t, err)
	require.Nil(t, client)
	require.Contains(t, err.Error(), "failed to connect to Redis")
}

func TestNewRedisClientEmptyConfig(t *testing.T) {
	config := &RedisConfig{
		Host:     "",
		Port:     0,
		Password: "",
	}

	client, err := NewRedisClient(config)
	require.Error(t, err)
	require.Nil(t, client)
}

func TestNewRedisSentinelClientInvalidHost(t *testing.T) {
	config := &RedisSentinelConfig{
		SentinelHost:     "invalid-sentinel-host-that-does-not-exist",
		SentinelPort:     26379,
		Password:         "",
		MasterName:       "mymaster",
		SentinelUsername: "",
	}

	client, err := NewRedisSentinelClient(config)
	require.Error(t, err)
	require.Nil(t, client)
	require.Contains(t, err.Error(), "failed to connect to Redis through Sentinel")
}

func TestNewRedisSentinelClientInvalidPort(t *testing.T) {
	config := &RedisSentinelConfig{
		SentinelHost:     "localhost",
		SentinelPort:     99999, // Invalid port
		Password:         "",
		MasterName:       "mymaster",
		SentinelUsername: "",
	}

	client, err := NewRedisSentinelClient(config)
	require.Error(t, err)
	require.Nil(t, client)
	require.Contains(t, err.Error(), "failed to connect to Redis through Sentinel")
}

func TestNewRedisSentinelClientEmptyMasterName(t *testing.T) {
	config := &RedisSentinelConfig{
		SentinelHost:     "localhost",
		SentinelPort:     26379,
		Password:         "",
		MasterName:       "", // Empty master name
		SentinelUsername: "",
	}

	client, err := NewRedisSentinelClient(config)
	require.Error(t, err)
	require.Nil(t, client)
}

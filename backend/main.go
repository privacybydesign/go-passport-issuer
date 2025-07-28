package main

import (
	"encoding/json"
	"flag"
	"fmt"
	log "go-passport-issuer/logging"
	redis "go-passport-issuer/redis"
	"os"
)

type Config struct {
	ServerConfig ServerConfig `json:"server_config"`

	JwtPrivateKeyPath string `json:"jwt_private_key_path"`
	IrmaServerUrl     string `json:"irma_server_url"`
	IssuerId          string `json:"issuer_id"`
	FullCredential    string `json:"full_credential"`

	StorageType         string                    `json:"storage_type"`
	RedisConfig         redis.RedisConfig         `json:"redis_config,omitempty"`
	RedisSentinelConfig redis.RedisSentinelConfig `json:"redis_sentinel_config,omitempty"`
}

func main() {
	configPath := flag.String("config", "", "Path for the config.json to use")
	flag.Parse()

	if *configPath == "" {
		log.Error.Fatal("please provide a config path using the --config flag")
	}

	log.Info.Printf("using config: %v", *configPath)

	config, err := readConfigFile(*configPath)
	if err != nil {
		log.Error.Fatalf("failed to read config file: %v", err)
	}

	log.Info.Printf("hosting on: %v:%v", config.ServerConfig.Host, config.ServerConfig.Port)

	jwtCreator, err := NewIrmaJwtCreator(
		config.JwtPrivateKeyPath,
		config.IssuerId,
		config.FullCredential,
	)
	if err != nil {
		log.Error.Fatalf("failed to instantiate jwt creator: %v", err)
	}

	tokenStorage, err := createTokenStorage(&config)
	if err != nil {
		log.Error.Fatalf("failed to instantiate token storage: %v", err)
	}

	serverState := ServerState{
		irmaServerURL: config.IrmaServerUrl,
		jwtCreator:    jwtCreator,
		tokenStorage:  tokenStorage,
	}

	server, err := NewServer(&serverState, config.ServerConfig)
	if err != nil {
		log.Error.Fatalf("failed to create server: %v", err)
	}

	err = server.ListenAndServe()
	if err != nil {
		log.Error.Fatalf("failed to listen and serve: %v", err)
	}
}

func readConfigFile(path string) (Config, error) {
	configBytes, err := os.ReadFile(path)

	if err != nil {
		return Config{}, err
	}

	var config Config
	err = json.Unmarshal(configBytes, &config)

	if err != nil {
		return Config{}, err
	}

	return config, nil
}

func createTokenStorage(config *Config) (TokenStorage, error) {
	if config.StorageType == "redis" {
		log.Info.Printf("Using redis token storage")
		client, err := redis.NewRedisClient(&config.RedisConfig)
		if err != nil {
			return nil, err
		}
		return NewRedisTokenStorage(client, config.RedisConfig.Namespace), nil
	}
	if config.StorageType == "redis_sentinel" {
		log.Info.Printf("Using redis sentinal storage")
		client, err := redis.NewRedisSentinelClient(&config.RedisSentinelConfig)
		if err != nil {
			return nil, err
		}
		return NewRedisTokenStorage(client, config.RedisSentinelConfig.Namespace), nil
	}
	if config.StorageType == "memory" {
		log.Info.Printf("Using in memory storage")
		return NewInMemoryTokenStorage(), nil
	}
	return nil, fmt.Errorf("%v is not a valid storage type", config.StorageType)
}

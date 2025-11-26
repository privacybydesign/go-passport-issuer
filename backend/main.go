package main

import (
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"go-passport-issuer/logging"
	redis "go-passport-issuer/redis"
	"log/slog"
	"os"

	"github.com/gmrtd/gmrtd/cms"
)

type Config struct {
	ServerConfig ServerConfig `json:"server_config"`

	JwtPrivateKeyPath       string   `json:"jwt_private_key_path"`
	IrmaServerUrl           string   `json:"irma_server_url"`
	IssuerId                string   `json:"issuer_id"`
	FullCredential          string   `json:"full_credential"`
	SdJwtBatchSize          uint     `json:"sd_jwt_batch_size"`
	DrivingLicenceCertPaths []string `json:"driving_licence_cert_paths"`
	LogLevel                string   `json:"log_level"`

	StorageType         string                    `json:"storage_type"`
	RedisConfig         redis.RedisConfig         `json:"redis_config,omitempty"`
	RedisSentinelConfig redis.RedisSentinelConfig `json:"redis_sentinel_config,omitempty"`
}

func main() {
	configPath := flag.String("config", "", "Path for the config.json to use")
	flag.Parse()

	if *configPath == "" {
		slog.Error("please provide a config path using the --config flag")
		os.Exit(1)
	}

	config, err := readConfigFile(*configPath)
	if err != nil {
		slog.Error("failed to read config file", "error", err)
		os.Exit(1)
	}

	// Initialize logger with the configured level, fallback to "info" if not set
	logLevel := config.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	logging.InitLogger(logLevel)

	slog.Info("using config", "path", *configPath)
	slog.Info("hosting on", "host", config.ServerConfig.Host, "port", config.ServerConfig.Port)

	jwtCreator, err := NewIrmaJwtCreator(
		config.JwtPrivateKeyPath,
		config.IssuerId,
		config.FullCredential,
		config.SdJwtBatchSize,
	)
	if err != nil {
		slog.Error("failed to instantiate jwt creator", "error", err)
		os.Exit(1)
	}

	tokenStorage, err := createTokenStorage(&config)
	if err != nil {
		slog.Error("failed to instantiate token storage", "error", err)
		os.Exit(1)
	}

	passportCertPool, err := cms.GetDefaultMasterList()
	if err != nil {
		slog.Error("CscaCertPool error", "error", err)
		os.Exit(1)
	}
	// Load here all existing generations of driving licence certs
	drivingLicenceCertPool, err := loadDrivingLicenceCertPool(config.DrivingLicenceCertPaths)
	if err != nil {
		slog.Error("Failed to load driving license cert", "error", err)
		os.Exit(1)
	}

	serverState := ServerState{
		irmaServerURL:           config.IrmaServerUrl,
		jwtCreator:              jwtCreator,
		tokenStorage:            tokenStorage,
		passportCertPool:        passportCertPool,
		drivingLicenceCertPool:  &drivingLicenceCertPool,
		passportValidator:       PassportValidatorImpl{},
		drivingLicenceValidator: DrivingLicenceValidatorImpl{},
		converter:               IssuanceRequestConverterImpl{},
	}

	server, err := NewServer(&serverState, config.ServerConfig)
	if err != nil {
		slog.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	err = server.ListenAndServe()
	if err != nil {
		slog.Error("failed to listen and serve", "error", err)
		os.Exit(1)
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
		slog.Info("Using redis token storage")
		client, err := redis.NewRedisClient(&config.RedisConfig)
		if err != nil {
			return nil, err
		}
		return NewRedisTokenStorage(client, config.RedisConfig.Namespace), nil
	}
	if config.StorageType == "redis_sentinel" {
		slog.Info("Using redis sentinal storage")
		client, err := redis.NewRedisSentinelClient(&config.RedisSentinelConfig)
		if err != nil {
			return nil, err
		}
		return NewRedisTokenStorage(client, config.RedisSentinelConfig.Namespace), nil
	}
	if config.StorageType == "memory" {
		slog.Info("Using in memory storage")
		return NewInMemoryTokenStorage(), nil
	}
	return nil, fmt.Errorf("%v is not a valid storage type", config.StorageType)
}

func loadDrivingLicenceCertPool(certPaths []string) (cms.CertPool, error) {
	certPool := &cms.GenericCertPool{}

	for _, certPath := range certPaths {
		data, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", certPath, err)
		}

		// Gen 1 cert are PEM while gen 2 and 3 are DER.
		if block, _ := pem.Decode(data); block != nil {
			err = certPool.Add(block.Bytes)
		} else {
			err = certPool.Add(data)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to add cert %s: %w", certPath, err)
		}

		slog.Info("Loaded driving licence cert", "path", certPath)
	}

	return certPool, nil
}

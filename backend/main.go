package main

import (
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"go-passport-issuer/analytics"
	"go-passport-issuer/logging"
	"go-passport-issuer/redis"
	"log/slog"
	"os"

	"github.com/gmrtd/gmrtd/cms"
)

//go:generate swag init --parseDependency --parseInternal -o docs

// @title Go Passport Issuer API
// @version 1.0
// @description API for verifying and issuing digital credentials from travel documents (passports, ID cards, and driving licences).
// @description This service validates MRTD (Machine Readable Travel Documents) and Electronic Driving Licences (EDL), then issues privacy-preserving credentials through the IRMA framework.

// @contact.name Privacy by Design Foundation

// @license.name Apache 2.0
// @license.url https://www.apache.org/licenses/LICENSE-2.0

// @BasePath /api

type Config struct {
	ServerConfig            ServerConfig              `json:"server_config"`
	IrmaServerUrl           string                    `json:"irma_server_url"`
	IssuerId                string                    `json:"issuer_id"`
	JwtPrivateKeyPath       string                    `json:"jwt_private_key_path"`
	SdJwtBatchSize          uint                      `json:"sd_jwt_batch_size"`
	DrivingLicenceCertPaths []string                  `json:"driving_licence_cert_paths"`
	Credentials             AllCredentialConfigs      `json:"credentials"`
	StorageType             string                    `json:"storage_type"`
	RedisConfig             redis.RedisConfig         `json:"redis_config"`
	RedisSentinelConfig     redis.RedisSentinelConfig `json:"redis_sentinel_config"`
	LogLevel                string                    `json:"log_level"`
	RegulaFaceApiUrl        string                    `json:"regula_face_api_url,omitempty"`
	// Similarity threshold (0-1) above which the live face is considered a match
	// for the document portrait. Defaults to DefaultFaceMatchThreshold when unset.
	RegulaFaceMatchThreshold float64 `json:"regula_face_match_threshold,omitempty"`
	// Browser-reachable origin of the Regula Face API, served to the /capture
	// liveness page and announced to the app in /api/start-validation. Distinct
	// from RegulaFaceApiUrl, which the backend uses over the internal network
	// and which a browser generally cannot resolve.
	RegulaFaceApiPublicUrl string `json:"regula_face_api_public_url,omitempty"`
	// Whether face verification applies in this environment. Enabled is
	// fail-closed: issuance without a matching liveness transaction is
	// rejected. When absent, derived from RegulaFaceApiUrl (set → enabled) so
	// old configs keep their exact behaviour. See
	// resolveFaceVerificationEnabled.
	FaceVerificationEnabled *bool `json:"face_verification_enabled,omitempty"`
	// Which face verification methods may be assigned, with their weights in
	// the draw. Absent means Regula only, so existing configs keep their exact
	// behaviour. See resolveFaceMethods.
	FaceVerificationMethods *FaceMethodsConfig `json:"face_verification_methods,omitempty"`
	// Whether a wallet's preferred_method is honoured. For staging testers;
	// off in production.
	AllowClientPreference bool `json:"allow_client_preference,omitempty"`
	// Cluster-internal base URL of the Iris verifier, e.g.
	// http://iris-verifier-svc:8081. Required when the iris method is enabled.
	IrisVerifierUrl string `json:"iris_verifier_url,omitempty"`
	// Wallet-reachable origin of the Iris verifier's stream endpoint, e.g.
	// wss://iris-verifier.staging.yivi.app. Required when iris is enabled.
	IrisVerifierPublicUrl string `json:"iris_verifier_public_url,omitempty"`
	// Where face verification attempts are recorded: "stderr" (default, one
	// JSON log line per event) or "none".
	Recorder string `json:"face_recorder,omitempty"`
}

type CredentialConfig struct {
	FullCredential string `json:"full_credential"`
}

type AllCredentialConfigs struct {
	Passport       CredentialConfig `json:"passport"`
	DrivingLicence CredentialConfig `json:"driving_licence"`
	IdCard         CredentialConfig `json:"id_card"`
}

type AllJwtCreators struct {
	Passport       JwtCreator
	DrivingLicence JwtCreator
	IdCard         JwtCreator
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

	passportJwtCreator, err := NewIrmaJwtCreator(
		config.JwtPrivateKeyPath,
		config.IssuerId,
		config.Credentials.Passport.FullCredential,
		config.SdJwtBatchSize,
	)
	if err != nil {
		slog.Error("failed to instantiate passport jwt creator", "error", err)
		os.Exit(1)
	}

	idCardJwtCreator, err := NewIrmaJwtCreator(
		config.JwtPrivateKeyPath,
		config.IssuerId,
		config.Credentials.IdCard.FullCredential,
		config.SdJwtBatchSize,
	)
	if err != nil {
		slog.Error("failed to instantiate id-card jwt creator", "error", err)
		os.Exit(1)
	}

	edlJwtCreator, err := NewIrmaJwtCreator(
		config.JwtPrivateKeyPath,
		config.IssuerId,
		config.Credentials.DrivingLicence.FullCredential,
		config.SdJwtBatchSize,
	)
	if err != nil {
		slog.Error("failed to instantiate edl jwt creator", "error", err)
		os.Exit(1)
	}

	jwtCreators := AllJwtCreators{
		Passport:       passportJwtCreator,
		DrivingLicence: edlJwtCreator,
		IdCard:         idCardJwtCreator,
	}

	tokenStorage, err := createTokenStorage(&config)
	if err != nil {
		slog.Error("failed to instantiate token storage", "error", err)
		os.Exit(1)
	}

	passportCertPool, err := cms.DefaultMasterList()
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

	faceVerification, err := resolveFaceVerificationEnabled(&config)
	if err != nil {
		slog.Error("invalid face verification configuration", "error", err)
		os.Exit(1)
	}

	var faceVerificationClient FaceVerificationClient
	var irisClient IrisClient
	var faceMethods FaceMethodPolicy
	if faceVerification {
		// Validated already by resolveFaceVerificationEnabled.
		methods, _ := resolveFaceMethods(&config)
		faceMethods = NewFaceMethodPolicy(methods, config.AllowClientPreference)
		slog.Info("Face verification enabled",
			"regula_enabled", methods.Regula.Enabled, "regula_weight", methods.Regula.Weight,
			"iris_enabled", methods.Iris.Enabled, "iris_weight", methods.Iris.Weight,
			"allow_client_preference", config.AllowClientPreference)
		if methods.Regula.Enabled {
			slog.Info("Initializing Regula Face API client",
				"url", config.RegulaFaceApiUrl,
				"match_threshold", config.RegulaFaceMatchThreshold)
			faceVerificationClient = NewRegulaFaceClient(config.RegulaFaceApiUrl, config.RegulaFaceMatchThreshold)
			if err := faceVerificationClient.HealthCheck(); err != nil {
				slog.Warn("Regula Face API health check failed, service may not be available", "error", err)
			}
		}
		if methods.Iris.Enabled {
			slog.Info("Initializing Iris verifier client", "url", config.IrisVerifierUrl)
			irisClient = NewIrisClient(config.IrisVerifierUrl)
			if err := irisClient.HealthCheck(); err != nil {
				slog.Warn("Iris verifier health check failed, service may not be available", "error", err)
			}
		}
	} else {
		slog.Info("Face verification disabled")
	}

	recorder, err := createRecorder(config.Recorder)
	if err != nil {
		slog.Error("invalid face recorder configuration", "error", err)
		os.Exit(1)
	}

	serverState := ServerState{
		irmaServerURL:          config.IrmaServerUrl,
		jwtCreators:            jwtCreators,
		tokenStorage:           tokenStorage,
		passportCertPool:       passportCertPool,
		drivingLicenceCertPool: &drivingLicenceCertPool,
		documentValidator:      DocumentValidatorImpl{},
		converter:              IssuanceRequestConverterImpl{},
		drivingLicenceParser:   DrivingLicenceParserImpl{},
		faceVerificationClient: faceVerificationClient,
		regulaFaceApiPublicUrl: config.RegulaFaceApiPublicUrl,
		faceMethods:            faceMethods,
		irisClient:             irisClient,
		irisVerifierPublicUrl:  config.IrisVerifierPublicUrl,
		recorder:               recorder,
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

// createRecorder builds the recorder named by `face_recorder`. The default
// writes one JSON log line per event; "none" discards them. A Prometheus
// recorder is the planned next option and would be selected here.
func createRecorder(name string) (analytics.Recorder, error) {
	switch name {
	case "", "stderr":
		return analytics.NewStderrRecorder(nil), nil
	case "none":
		return analytics.Noop{}, nil
	}
	return nil, fmt.Errorf("%q is not a valid face_recorder (stderr, none)", name)
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

package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type AppConfig struct {
	App        AppSettings        `mapstructure:"app"`
	Postgres   PostgresSettings   `mapstructure:"postgres"`
	Redis      RedisSettings      `mapstructure:"redis"`
	Kafka      KafkaSettings      `mapstructure:"kafka"`
	JWT        JWTSettings        `mapstructure:"jwt"`
	GRPC       GRPCSettings       `mapstructure:"grpc"`
	Telemetry  TelemetrySettings  `mapstructure:"telemetry"`
	RateLimit  RateLimitSettings  `mapstructure:"rate_limit"`
	Argon2     Argon2Settings     `mapstructure:"argon2"`
	Revocation RevocationSettings `mapstructure:"revocation"`
}

type AppSettings struct {
	Name string `mapstructure:"name"`
	Env  string `mapstructure:"env"`
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type GRPCSettings struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

type PostgresSettings struct {
	Host              string        `mapstructure:"host"`
	Port              int           `mapstructure:"port"`
	User              string        `mapstructure:"user"`
	Password          string        `mapstructure:"password"`
	Database          string        `mapstructure:"database"`
	SSLMode           string        `mapstructure:"ssl_mode"`
	MaxConns          int32         `mapstructure:"max_conns"`
	MinConns          int32         `mapstructure:"min_conns"`
	MaxConnLifetime   time.Duration `mapstructure:"max_conn_lifetime"`
	MaxConnIdleTime   time.Duration `mapstructure:"max_conn_idle_time"`
	HealthCheckPeriod time.Duration `mapstructure:"health_check_period"`
}

// RedisSettings configures Redis connection and TLS
type RedisSettings struct {
	Host                 string        `mapstructure:"host"`
	Port                 int           `mapstructure:"port"`
	DB                   int           `mapstructure:"db"`
	Password             string        `mapstructure:"password"`
	TLSEnabled           bool          `mapstructure:"tls_enabled"`
	SessionVersionPrefix string        `mapstructure:"session_version_prefix"`
	SessionVersionTTL    time.Duration `mapstructure:"session_version_ttl"`
	SubjectVersionPrefix string        `mapstructure:"subject_version_prefix"`
}

// KafkaSettings configures Kafka producer
type KafkaSettings struct {
	Brokers     []string `mapstructure:"brokers"`
	TopicPrefix string   `mapstructure:"topic_prefix"`
	Async       bool     `mapstructure:"async"`
}

// RateLimitSettings configures rate limiting windows and max attempts per endpoint
type RateLimitSettings struct {
	WindowDuration           time.Duration `mapstructure:"window_duration"`
	LoginMaxAttempts         int           `mapstructure:"login_max_attempts"`
	RegisterMaxAttempts      int           `mapstructure:"register_max_attempts"`
	RefreshMaxAttempts       int           `mapstructure:"refresh_max_attempts"`
	PasswordResetMaxAttempts int           `mapstructure:"password_reset_max_attempts"`
}

// Argon2Settings configures Argon2id password hashing parameters
type Argon2Settings struct {
	Memory      uint32 `mapstructure:"memory"`
	Iterations  uint32 `mapstructure:"iterations"`
	Parallelism uint8  `mapstructure:"parallelism"`
	SaltLength  uint32 `mapstructure:"salt_length"`
	KeyLength   uint32 `mapstructure:"key_length"`
}

type JWTSettings struct {
	KeyDirectory    string        `mapstructure:"key_directory"`
	AccessTokenTTL  time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl"`
}

type TelemetrySettings struct {
	MetricsPort     int     `mapstructure:"metrics_port"`
	TracingEndpoint string  `mapstructure:"tracing_endpoint"`
	OTLPEndpoint    string  `mapstructure:"otlp_endpoint"`
	ServiceName     string  `mapstructure:"service_name"`
	SamplingRate    float64 `mapstructure:"sampling_rate"`
}

type RevocationSettings struct {
	DegradationPolicy string                   `mapstructure:"degradation_policy"`
	Cache             RevocationCacheSettings  `mapstructure:"cache"`
	Bloom             RevocationBloomSettings  `mapstructure:"bloom"`
	Replay            RevocationReplaySettings `mapstructure:"replay"`
}

type RevocationCacheSettings struct {
	WarmupGracePeriod   time.Duration `mapstructure:"warmup_grace_period"`
	StaleTTL            time.Duration `mapstructure:"stale_ttl"`
	SubjectVersionTTL   time.Duration `mapstructure:"subject_version_ttl"`
	DenylistSnapshotTTL time.Duration `mapstructure:"denylist_snapshot_ttl"`
}

type RevocationBloomSettings struct {
	WindowDuration    time.Duration `mapstructure:"window_duration"`
	WindowCount       int           `mapstructure:"window_count"`
	FalsePositiveRate float64       `mapstructure:"false_positive_rate"`
}

type RevocationReplaySettings struct {
	MaxEventLag     time.Duration `mapstructure:"max_event_lag"`
	ReplayTolerance time.Duration `mapstructure:"replay_tolerance"`
}

func Load() (*AppConfig, error) {
	v := viper.New()

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetEnvPrefix("IAM")

	setDefaults(v)

	if err := bindEnvs(v, []string{
		"app.name",
		"app.env",
		"app.host",
		"app.port",
		"grpc.host",
		"grpc.port",
		"postgres.host",
		"postgres.port",
		"postgres.user",
		"postgres.password",
		"postgres.database",
		"postgres.ssl_mode",
		"postgres.max_conns",
		"postgres.min_conns",
		"postgres.max_conn_lifetime",
		"postgres.max_conn_idle_time",
		"postgres.health_check_period",
		"redis.host",
		"redis.port",
		"redis.db",
		"redis.password",
		"redis.tls_enabled",
		"redis.session_version_prefix",
		"redis.session_version_ttl",
		"redis.subject_version_prefix",
		"kafka.brokers",
		"kafka.topic_prefix",
		"kafka.async",
		"jwt.key_directory",
		"jwt.access_token_ttl",
		"jwt.refresh_token_ttl",
		"telemetry.metrics_port",
		"telemetry.tracing_endpoint",
		"telemetry.otlp_endpoint",
		"telemetry.service_name",
		"telemetry.sampling_rate",
		"rate_limit.window_duration",
		"rate_limit.login_max_attempts",
		"rate_limit.register_max_attempts",
		"rate_limit.refresh_max_attempts",
		"rate_limit.password_reset_max_attempts",
		"argon2.memory",
		"argon2.iterations",
		"argon2.parallelism",
		"argon2.salt_length",
		"argon2.key_length",
		"revocation.degradation_policy",
		"revocation.cache.warmup_grace_period",
		"revocation.cache.stale_ttl",
		"revocation.cache.subject_version_ttl",
		"revocation.cache.denylist_snapshot_ttl",
		"revocation.bloom.window_duration",
		"revocation.bloom.window_count",
		"revocation.bloom.false_positive_rate",
		"revocation.replay.max_event_lag",
		"revocation.replay.replay_tolerance",
	}); err != nil {
		return nil, err
	}

	v.AutomaticEnv()

	var cfg AppConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("app.name", "iam-service")
	v.SetDefault("app.env", "development")
	v.SetDefault("app.host", "0.0.0.0")
	v.SetDefault("app.port", 8080)

	v.SetDefault("grpc.host", "0.0.0.0")
	v.SetDefault("grpc.port", 50051)

	v.SetDefault("postgres.host", "localhost")
	v.SetDefault("postgres.port", 5432)
	v.SetDefault("postgres.user", "iam")
	v.SetDefault("postgres.password", "iam_password")
	v.SetDefault("postgres.database", "iam")
	v.SetDefault("postgres.ssl_mode", "disable")
	v.SetDefault("postgres.max_conns", 10)
	v.SetDefault("postgres.min_conns", 2)
	v.SetDefault("postgres.max_conn_lifetime", "60m")
	v.SetDefault("postgres.max_conn_idle_time", "15m")
	v.SetDefault("postgres.health_check_period", "30s")

	// Redis defaults (T006)
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.tls_enabled", false)
	v.SetDefault("redis.session_version_prefix", "iam:session_version")
	v.SetDefault("redis.session_version_ttl", "10m")
	v.SetDefault("redis.subject_version_prefix", "iam:subject_version")

	// Kafka defaults (T007)
	v.SetDefault("kafka.brokers", []string{"localhost:9092"})
	v.SetDefault("kafka.topic_prefix", "iam")
	v.SetDefault("kafka.async", true)

	v.SetDefault("jwt.key_directory", "./secrets")
	v.SetDefault("jwt.access_token_ttl", "15m")
	v.SetDefault("jwt.refresh_token_ttl", "168h")

	v.SetDefault("telemetry.metrics_port", 9090)
	v.SetDefault("telemetry.tracing_endpoint", "http://localhost:4317")
	// OpenTelemetry defaults (T010)
	v.SetDefault("telemetry.otlp_endpoint", "http://localhost:4318")
	v.SetDefault("telemetry.service_name", "iam-service")
	v.SetDefault("telemetry.sampling_rate", 1.0)

	// Rate limiting defaults (T008)
	v.SetDefault("rate_limit.window_duration", "1m")
	v.SetDefault("rate_limit.login_max_attempts", 5)
	v.SetDefault("rate_limit.register_max_attempts", 3)
	v.SetDefault("rate_limit.refresh_max_attempts", 10)
	v.SetDefault("rate_limit.password_reset_max_attempts", 3)

	// Argon2id defaults (T009)
	v.SetDefault("argon2.memory", 65536) // 64 MB
	v.SetDefault("argon2.iterations", 3)
	v.SetDefault("argon2.parallelism", 4)
	v.SetDefault("argon2.salt_length", 16)
	v.SetDefault("argon2.key_length", 32)

	// Revocation defaults (T003)
	v.SetDefault("revocation.degradation_policy", "lenient")
	v.SetDefault("revocation.cache.warmup_grace_period", "15s")
	v.SetDefault("revocation.cache.stale_ttl", "30s")
	v.SetDefault("revocation.cache.subject_version_ttl", "2m")
	v.SetDefault("revocation.cache.denylist_snapshot_ttl", "5m")
	v.SetDefault("revocation.bloom.window_duration", "60s")
	v.SetDefault("revocation.bloom.window_count", 6)
	v.SetDefault("revocation.bloom.false_positive_rate", 0.001)
	v.SetDefault("revocation.replay.max_event_lag", "2s")
	v.SetDefault("revocation.replay.replay_tolerance", "5s")
}

func bindEnvs(v *viper.Viper, keys []string) error {
	for _, key := range keys {
		envKey := strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
		if err := v.BindEnv(key, "IAM_"+envKey, envKey); err != nil {
			return fmt.Errorf("bind env for %s: %w", key, err)
		}
	}
	return nil
}

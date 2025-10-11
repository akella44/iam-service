package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type AppConfig struct {
	App       AppSettings       `mapstructure:"app"`
	Postgres  PostgresSettings  `mapstructure:"postgres"`
	JWT       JWTSettings       `mapstructure:"jwt"`
	GRPC      GRPCSettings      `mapstructure:"grpc"`
	Telemetry TelemetrySettings `mapstructure:"telemetry"`
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

type JWTSettings struct {
	KeyDirectory    string        `mapstructure:"key_directory"`
	AccessTokenTTL  time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl"`
}

type TelemetrySettings struct {
	MetricsPort     int    `mapstructure:"metrics_port"`
	TracingEndpoint string `mapstructure:"tracing_endpoint"`
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
		"jwt.key_directory",
		"jwt.access_token_ttl",
		"jwt.refresh_token_ttl",
		"telemetry.metrics_port",
		"telemetry.tracing_endpoint",
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

	v.SetDefault("jwt.key_directory", "./secrets")
	v.SetDefault("jwt.access_token_ttl", "15m")
	v.SetDefault("jwt.refresh_token_ttl", "168h")

	v.SetDefault("telemetry.metrics_port", 9090)
	v.SetDefault("telemetry.tracing_endpoint", "http://localhost:4317")
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

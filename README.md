# Social Platform IAM Service

Identity and Access Management (IAM) microservice powering role-based access control, authentication, and session management for the social research platform.


## Getting Started

### Prerequisites

- Go 1.25.1 toolchain or newer (uses `toolchain go1.25.1` directive)
- Docker & Docker Compose

### Quick start

```bash
cp .env.example .env
make dev-up
``` 
After containers is up, run: 
```bash
make db-init
``` 
and
```bash
make seed-dev
```
with creds from .env file. Env file structure:
```env
# PostgreSQL
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_USER=iam
POSTGRES_PASSWORD=iam_password
POSTGRES_DB=iam

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=
REDIS_TLS=false
REDIS_SESSION_VERSION_PREFIX=iam:session_version
REDIS_SESSION_VERSION_TTL=10m
REDIS_SESSION_REVOCATION_PREFIX=iam:sess:revoked
REDIS_SESSION_REVOCATION_TTL=24h

# Kafka
KAFKA_BROKERS=kafka:29092
KAFKA_TOPIC_PREFIX=iam
KAFKA_ASYNC=true
KAFKA_PORT=9092

# Rate Limiting (FR-056 to FR-060)
RATE_LIMIT_LOGIN_PER_IP=5
RATE_LIMIT_LOGIN_IP_WINDOW=1m
RATE_LIMIT_LOGIN_PER_ACCOUNT=3
RATE_LIMIT_LOGIN_ACC_WINDOW=1m
RATE_LIMIT_REGISTER_PER_IP=3
RATE_LIMIT_REGISTER_WINDOW=1h
RATE_LIMIT_RESET_PER_ACCOUNT=3
RATE_LIMIT_RESET_WINDOW=1h
RATE_LIMIT_OTP_PER_REQUEST=5
RATE_LIMIT_OTP_WINDOW=10m
RATE_LIMIT_OTP_COOLDOWN=30s

# Argon2id Parameters (FR-003)
ARGON2_MEMORY=65536
ARGON2_ITERATIONS=2
ARGON2_PARALLELISM=1
ARGON2_SALT_LENGTH=16
ARGON2_KEY_LENGTH=32

# JWT
JWT_KEY_DIRECTORY=./secrets
JWT_ACCESS_TOKEN_TTL=15m
JWT_REFRESH_TOKEN_TTL=168h

# Revocation
REVOCATION_DEGRADATION_POLICY=lenient

# Application
APP_NAME=iam-service
APP_ENV=development
APP_HOST=0.0.0.0
APP_PORT=8080

# gRPC
GRPC_HOST=0.0.0.0
GRPC_PORT=50051
```

Swagger documentation will be served at `/docs/index.html` once generated.

Start the development environment:

```bash
cd build/compose
docker-compose up iam-dev
```

For production, build and run the final target:

```bash
cd build/compose
docker-compose build --target final
docker-compose up
```
Warning: prod build have not implemented features.

### Useful commands

```bash
make dev-up        # start Postgres and IAM service in watch mode
make dev-down      # stop local stack
make migrate-up    # apply DB migrations
make test          # run unit and integration tests
make seed-dev      # load development seed data (admin + regular user)
```

## Testing

Run unit tests:

```bash
go test ./internal/usecase/... -v
```

### Revocation Verification Playbook

Follow this checklist after deploying or changing revocation behaviour:

1. **Refresh Rotation & Reuse Detection**
	- Call `POST /auth/token/refresh` and confirm a new token pair in the response plus a `refresh_rotated` Kafka event (`iam.refresh_rotated`).
	- Re-submit the previous refresh token to trigger a `reuse_detected` event and confirm the corresponding audit entry in PostgreSQL (`refresh_audit_log`).
	- Inspect metrics with `curl http://localhost:8080/metrics | grep iam_http_requests_total` to verify rotation counters increment.
2. **Access Token Revocation Cache**
	- Revoke any active session via `DELETE /auth/sessions/{sid}` or the “logout-all” flow and verify Redis now contains `sess:revoked:<sid>` with a TTL approximating the longer of access/refresh lifetimes.
	- Hit any authenticated HTTP route with the old access token; middleware now validates JWT locally, looks up `sess:revoked:<sid>` in Redis, and should respond with `401` without hitting Postgres.
	- Clear the Redis key (or wait for TTL expiry) and confirm previously revoked access tokens are rejected only after the refresh rotation forces a new session version, demonstrating the lazy Postgres lookup path is rarely exercised.
	- The `/api/v1/auth/logout` endpoint enforces `Authorization: Bearer <token>` and returns `401` for unauthenticated calls, so only the user who owns the session (or trusted service acting on their behalf) can trigger logout. Example:
	```bash
	curl -i -X POST \
	  -H "Authorization: Bearer $ACCESS_TOKEN" \
	  http://localhost:8080/api/v1/auth/logout
	```



### Development seed data

For manual end-to-end testing, apply the development-only seed script after running database migrations:

```bash
DB_USER=iam DB_PASSWORD=iam_password DB_NAME=iam DB_PORT=5432 DB_SSL_MODE=disable make seed-dev
```

This script creates the IAM schema if needed and provisions two accounts:

- **admin / AdminPass123!** — full-access administrator role
- **regular / Password123!** — standard user role

The seed is intended only for non-production environments.

## gRPC token validation API (internal only)

Platform services that need to validate bearer tokens without understanding JWT internals can call the gRPC service defined in `gen/proto/iam/v1/token_validation.proto`.

- **Endpoint:** `iam.v1.TokenValidationService/Validate`
- **Default address:** `localhost:50051` (config key `grpc.port`)
- **Audience:** other trusted services inside the platform network. External clients should use the HTTP REST API instead.
- **Request:**
	- `token` – required string containing the access token issued by this IAM service.
- **Response fields:**
	- `valid` – boolean flag indicating whether the token passed signature, expiry, and revocation checks.
	- `user_id` – identifier of the token subject when valid.
	- `roles` – snapshot of role names embedded in the token.
	- `expires_at` – UNIX epoch seconds for the token expiry (0 when unavailable).
	- `error` – human-readable reason when `valid` is `false` (e.g., `access token expired`).

### Example usage with `grpcurl`

The following command demonstrates how an internal service can validate a token over plaintext (development) transport:

```bash
grpcurl -plaintext -d '{"token":"<ACCESS_TOKEN>"}' localhost:50051 iam.v1.TokenValidationService.Validate
```
## Observability & Alerting

- Metrics endpoint: `http://<host>:8080/metrics`
- Primary counter: `iam_http_requests_total` (labelled by path/method/status) to confirm revocation-related APIs are exercised.
- Audit trails and Kafka events remain the source of truth for refresh rotation and reuse detection; no dedicated denylist metrics exist after the 2025-11 cleanup.
- Configure `telemetry.otlp_endpoint` to forward OpenTelemetry traces for outbox publishers and Kafka consumers.

## Roadmap
- Add MFA
- Adaptive session anomaly detection
- Device fingerprinting improvements
- Automated alert runbooks for revocation SLO breaches


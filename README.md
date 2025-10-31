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
## Roadmap
- Add MFA
- JTI list
- Rate-limits
- Captcha
- Token rotation on suspicious activity


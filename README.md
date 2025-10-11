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
IAM_APP_NAME=iam-service
IAM_APP_ENV=development
IAM_APP_HOST=0.0.0.0
IAM_APP_PORT=8080

# gRPC server configuration
IAM_GRPC_HOST=0.0.0.0
IAM_GRPC_PORT=50051

# Postgres connection
IAM_POSTGRES_HOST=changeme!
IAM_POSTGRES_PORT=5432
IAM_POSTGRES_USER=changeme!
IAM_POSTGRES_PASSWORD=changeme!
IAM_POSTGRES_DATABASE=iam
IAM_POSTGRES_SSL_MODE=disable
IAM_POSTGRES_MAX_CONNS=10
IAM_POSTGRES_MIN_CONNS=2
IAM_POSTGRES_MAX_CONN_LIFETIME=60m
IAM_POSTGRES_MAX_CONN_IDLE_TIME=15m
IAM_POSTGRES_HEALTH_CHECK_PERIOD=30s

# JWT settings
IAM_JWT_SIGNING_KEY_PATH=changeme
IAM_JWT_VERIFICATION_KEY_PATH=changeme
IAM_JWT_ACCESS_TOKEN_TTL=15m
IAM_JWT_REFRESH_TOKEN_TTL=168h

# Telemetry (not implemented)
IAM_TELEMETRY_METRICS_PORT=9090
IAM_TELEMETRY_TRACING_ENDPOINT=http://localhost:4317
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


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

The HTTP API listens on `http://localhost:8080`, while the internal gRPC endpoint is exposed at `localhost:50051`. Swagger documentation will be served at `/docs/index.html` once generated.

Start the development environment:

```bash
cd build/compose
docker-compose up iam-dev
```

The service will:
- Run with hot-reload enabled (using `air`)
- Mount the project directory to `/workspace`
- Use keys from `build/compose/secrets/`
- Expose port 8080

For production, build and run the final target:

```bash
cd build/compose
docker-compose build --target final
docker-compose up
```

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

### OpenAPI validation & tooling

This project uses [go-swagger](https://github.com/go-swagger/go-swagger) for OpenAPI spec validation and CLI tooling. To validate or work with the spec:

```bash
# Validate the OpenAPI spec
swagger validate gen/docs/swagger/swagger.yaml

# (Optional) Generate server/client stubs or docs
swagger generate server -f gen/docs/swagger/swagger.yaml
swagger generate client -f gen/docs/swagger/swagger.yaml
swagger generate spec -o gen/docs/swagger/swagger.yaml
```

Install the CLI with:
```bash
go install github.com/go-swagger/go-swagger/cmd/swagger@latest
```
See [go-swagger docs](https://goswagger.io/) for more advanced usage.

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

In production deployments you should secure the gRPC channel (mTLS or an internal service mesh) and restrict network access so only trusted workloads can reach this endpoint.

## Project Layout

```
cmd/api                # service entrypoint
gen/docs/swagger       # generated OpenAPI documentation
gen/proto/iam/v1       # protobuf definitions for gRPC services
internal/core/domain   # domain entities and value objects
internal/core/port     # interfaces for use cases and adapters
internal/infra/app     # application bootstrap helpers
internal/infra/config  # configuration loading and defaults
internal/infra/database# persistence connection utilities
internal/infra/logger  # structured logging setup
internal/infra/security# cryptographic helpers and token utilities
internal/infra/telemetry# metrics and tracing instrumentation
internal/repository    # data persistence adapters (e.g., Postgres)
internal/transport/grpc# gRPC servers and wiring
internal/transport/http# HTTP handlers, middleware, and routing
internal/usecase       # business logic services
migrations             # SQL migrations
scripts                # helper scripts (migrations, tooling)
```

## Roadmap

- MVP
- Add MFA
- JTI list
- Rate-limits
- Captcha
- Token rotation on suspicious activity

## License

This project is released under the MIT License.

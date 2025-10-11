BINARY_NAME := iam
PACKAGE := ./...

.PHONY: build run test lint tidy dev-up dev-down migrate-up migrate-down swag

build:
	go build -o bin/$(BINARY_NAME) ./cmd/iam

run:
	go run ./cmd/iam

test:
	go test $(PACKAGE)


lint:
	golangci-lint run

tidy:
	go mod tidy

dev-up:
	docker compose -f build/compose/docker-compose.yml up --build

dev-down:
	docker compose -f build/compose/docker-compose.yml down

migrate-up:
	migrate -path migrations -database "postgres://$${DB_USER}:$${DB_PASSWORD}@$${DB_HOST}:$${DB_PORT}/$${DB_NAME}?sslmode=$${DB_SSL_MODE}" up

migrate-down:
	migrate -path migrations -database "postgres://$${DB_USER}:$${DB_PASSWORD}@$${DB_HOST}:$${DB_PORT}/$${DB_NAME}?sslmode=$${DB_SSL_MODE}" down

# Initialize database (run migrations directly via psql)
db-init:
	PGPASSWORD=$${DB_PASSWORD} psql -h $${DB_HOST} -p $${DB_PORT} -U $${DB_USER} -d $${DB_NAME} -v ON_ERROR_STOP=1 -f migrations/0001_init.up.sql

# Load seed data for development
seed-dev:
	PGPASSWORD=$${DB_PASSWORD} psql -h $${DB_HOST} -p $${DB_PORT} -U $${DB_USER} -d $${DB_NAME} -v ON_ERROR_STOP=1 -f migrations/dev/001_seed_data.sql

# Initialize DB and load seed data (one command)
db-setup-dev: db-init seed-dev
	@echo "✅ Database initialized and seeded"

swag:
	swag init -g cmd/iam/main.go -o docs/swagger

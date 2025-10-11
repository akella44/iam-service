package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	_ "github.com/arklim/social-platform-iam/gen/docs/swagger"
	"github.com/arklim/social-platform-iam/internal/infra/app"
	"github.com/arklim/social-platform-iam/internal/infra/config"
)

func main() {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	application, err := app.New(ctx, cfg)
	if err != nil {
		log.Fatalf("failed to init app: %v", err)
	}

	if err := application.Run(ctx); err != nil {
		log.Printf("application stopped: %v", err)
		os.Exit(1)
	}
}

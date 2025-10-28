package transportgrpc

import (
	"fmt"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/transport/grpc/iamv1"
	grpcinterceptors "github.com/arklim/social-platform-iam/internal/transport/grpc/interceptors"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// ServerDependencies encapsulates services required by the gRPC server layer.
type ServerDependencies struct {
	AuthService   *usecase.AuthService
	TokenService  *usecase.TokenService
	JWTManager    *security.JWTManager
	Logger        *zap.Logger
	PublicMethods []string // methods that don't require authentication
}

// NewServer wires gRPC services with authentication enforced through interceptors.
func NewServer(deps ServerDependencies) (*grpc.Server, error) {
	if deps.AuthService == nil {
		return nil, fmt.Errorf("auth service is required")
	}

	logger := deps.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	authInterceptor := grpcinterceptors.NewAuthInterceptor(deps.AuthService, grpcinterceptors.AuthOptions{
		Logger:       logger,
		AllowMethods: deps.PublicMethods,
	})
	unaryInterceptors := []grpc.UnaryServerInterceptor{authInterceptor.UnaryServerInterceptor()}

	server := grpc.NewServer(grpc.ChainUnaryInterceptor(unaryInterceptors...))

	if deps.TokenService != nil {
		tokenServer := NewTokenServer(deps.TokenService, deps.JWTManager, logger)
		iamv1.RegisterTokenServiceServer(server, tokenServer)
	}

	// Register reflection service for tools like Postman, grpcurl, etc.
	reflection.Register(server)

	return server, nil
}

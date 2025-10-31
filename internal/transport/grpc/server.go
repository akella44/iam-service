package transportgrpc

import (
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
	JWTManager    *security.JWTManager
	Logger        *zap.Logger
	PublicMethods []string // methods that don't require authentication
}

// NewServer wires gRPC services with authentication enforced through interceptors.
func NewServer(deps ServerDependencies) (*grpc.Server, error) {
	logger := deps.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	var serverOpts []grpc.ServerOption
	if deps.AuthService != nil {
		authInterceptor := grpcinterceptors.NewAuthInterceptor(deps.AuthService, grpcinterceptors.AuthOptions{
			Logger:       logger,
			AllowMethods: deps.PublicMethods,
		})
		serverOpts = append(serverOpts, grpc.ChainUnaryInterceptor(authInterceptor.UnaryServerInterceptor()))
	}

	server := grpc.NewServer(serverOpts...)

	tokenServer := NewTokenServer(deps.JWTManager, logger)
	iamv1.RegisterTokenServiceServer(server, tokenServer)

	// Register reflection service for tools like Postman, grpcurl, etc.
	reflection.Register(server)

	return server, nil
}

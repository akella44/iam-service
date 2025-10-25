package transportgrpc

import (
	"fmt"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/arklim/social-platform-iam/internal/transport/grpc/iamv1"
	grpcinterceptors "github.com/arklim/social-platform-iam/internal/transport/grpc/interceptors"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// ServerDependencies encapsulates services required by the gRPC server layer.
type ServerDependencies struct {
	AuthService  *usecase.AuthService
	TokenService *usecase.TokenService
	Logger       *zap.Logger
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

	authInterceptor := grpcinterceptors.NewAuthInterceptor(deps.AuthService, grpcinterceptors.AuthOptions{Logger: logger})
	unaryInterceptors := []grpc.UnaryServerInterceptor{authInterceptor.UnaryServerInterceptor()}

	server := grpc.NewServer(grpc.ChainUnaryInterceptor(unaryInterceptors...))

	if deps.TokenService != nil {
		tokenServer := NewTokenServer(deps.TokenService, logger)
		iamv1.RegisterTokenServiceServer(server, tokenServer)
	}

	return server, nil
}

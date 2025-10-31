package transportgrpc

import (
	"context"
	"errors"

	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/transport/grpc/iamv1"
)

// TokenServer implements the iam.v1.TokenService gRPC contract.
type TokenServer struct {
	iamv1.UnimplementedTokenServiceServer
	jwtManager *security.JWTManager
	logger     *zap.Logger
}

// NewTokenServer constructs a gRPC token server that only serves JWKS responses.
func NewTokenServer(jwtManager *security.JWTManager, logger *zap.Logger) *TokenServer {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &TokenServer{
		jwtManager: jwtManager,
		logger:     logger,
	}
}

// GetJWKS returns the JSON Web Key Set for offline JWT validation.
func (s *TokenServer) GetJWKS(ctx context.Context, req *iamv1.GetJWKSRequest) (*iamv1.GetJWKSResponse, error) {
	resp := &iamv1.GetJWKSResponse{}

	if s == nil || s.jwtManager == nil {
		return nil, errors.New("jwks not available")
	}

	jwksJSON, err := s.jwtManager.JWKS()
	if err != nil {
		s.logger.Error("failed to generate JWKS", zap.Error(err))
		return nil, errors.New("failed to generate jwks")
	}

	resp.JwksJson = string(jwksJSON)
	return resp, nil
}

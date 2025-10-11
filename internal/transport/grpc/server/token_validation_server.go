package server

import (
	"context"
	"errors"
	"strings"

	"github.com/arklim/social-platform-iam/internal/transport/grpc/iamv1"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// TokenValidationServer implements the TokenValidationService gRPC contract.
type TokenValidationServer struct {
	iamv1.UnimplementedTokenValidationServiceServer
	auth *usecase.AuthService
}

// NewTokenValidationServer constructs a TokenValidationServer instance.
func NewTokenValidationServer(auth *usecase.AuthService) *TokenValidationServer {
	return &TokenValidationServer{auth: auth}
}

// Validate verifies the provided JWT access token and returns the associated claims.
func (s *TokenValidationServer) Validate(ctx context.Context, req *iamv1.ValidateTokenRequest) (*iamv1.ValidateTokenResponse, error) {
	if req == nil || strings.TrimSpace(req.GetToken()) == "" {
		return &iamv1.ValidateTokenResponse{
			Valid: false,
			Error: "token is required",
		}, nil
	}

	claims, err := s.auth.ParseAccessToken(req.GetToken())
	if err != nil {
		resp := &iamv1.ValidateTokenResponse{Valid: false}
		switch {
		case errors.Is(err, usecase.ErrExpiredAccessToken):
			resp.Error = "access token expired"
		case errors.Is(err, usecase.ErrInvalidAccessToken):
			resp.Error = "access token invalid"
		default:
			resp.Error = "failed to validate token"
		}
		return resp, nil
	}

	var expiresAt int64
	if claims.RegisteredClaims.ExpiresAt != nil {
		expiresAt = claims.RegisteredClaims.ExpiresAt.Unix()
	}

	return &iamv1.ValidateTokenResponse{
		Valid:     true,
		UserId:    claims.UserID,
		Roles:     append([]string(nil), claims.Roles...),
		ExpiresAt: expiresAt,
	}, nil
}

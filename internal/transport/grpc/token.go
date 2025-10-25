package transportgrpc

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/arklim/social-platform-iam/internal/transport/grpc/iamv1"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// TokenServer implements the iam.v1.TokenService gRPC contract.
type TokenServer struct {
	iamv1.UnimplementedTokenServiceServer
	service *usecase.TokenService
	logger  *zap.Logger
}

// NewTokenServer constructs a gRPC token server backed by the supplied use case.
func NewTokenServer(service *usecase.TokenService, logger *zap.Logger) *TokenServer {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &TokenServer{service: service, logger: logger}
}

// ValidateToken performs offline token validation using the TokenService.
func (s *TokenServer) ValidateToken(ctx context.Context, req *iamv1.ValidateTokenRequest) (*iamv1.ValidateTokenResponse, error) {
	resp := &iamv1.ValidateTokenResponse{}

	if s == nil || s.service == nil {
		resp.Error = "token service unavailable"
		return resp, nil
	}
	if req == nil || strings.TrimSpace(req.GetToken()) == "" {
		resp.Error = "token is required"
		return resp, nil
	}

	claims, err := s.service.ValidateToken(ctx, req.GetToken(), req.GetExpectedAudience())
	if err != nil {
		s.logger.Warn("validate token failed", zap.Error(err))
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

	resp.Valid = true
	resp.UserId = claims.UserID
	resp.Roles = append(resp.Roles, claims.Roles...)
	resp.Jti = strings.TrimSpace(claims.RegisteredClaims.ID)
	resp.SessionId = strings.TrimSpace(claims.SessionID)

	if claims.RegisteredClaims.ExpiresAt != nil {
		expiresAt := claims.RegisteredClaims.ExpiresAt.Time
		if !expiresAt.IsZero() {
			resp.ExpiresAt = timestamppb.New(expiresAt)
		}
	}

	return resp, nil
}

// Introspect provides revocation-aware token status.
func (s *TokenServer) Introspect(ctx context.Context, req *iamv1.IntrospectRequest) (*iamv1.IntrospectResponse, error) {
	resp := &iamv1.IntrospectResponse{}

	if s == nil || s.service == nil {
		resp.Error = "token service unavailable"
		return resp, nil
	}
	if req == nil || strings.TrimSpace(req.GetToken()) == "" {
		resp.Error = "token is required"
		return resp, nil
	}

	checkRevocation := true
	if req.CheckRevocation != nil {
		checkRevocation = req.GetCheckRevocation()
	}

	result, err := s.service.Introspect(ctx, req.GetToken(), checkRevocation, nil)
	if err != nil {
		s.logger.Warn("introspect token failed", zap.Error(err))
		switch {
		case errors.Is(err, usecase.ErrExpiredAccessToken):
			resp.Error = "access token expired"
		case errors.Is(err, usecase.ErrInvalidAccessToken):
			resp.Error = "access token invalid"
		default:
			resp.Error = "failed to introspect token"
		}
		return resp, nil
	}

	resp.Active = result.Active
	resp.UserId = result.UserID
	resp.Username = result.Username
	resp.Roles = append(resp.Roles, result.Roles...)
	resp.Jti = result.JTI
	resp.SessionId = result.SessionID
	resp.Revoked = result.Revoked
	resp.RevocationReason = result.RevocationReason

	if !result.IssuedAt.IsZero() {
		resp.IssuedAt = timestamppb.New(result.IssuedAt)
	}
	if !result.ExpiresAt.IsZero() {
		resp.ExpiresAt = timestamppb.New(result.ExpiresAt)
	}
	if !result.NotBefore.IsZero() {
		resp.NotBefore = timestamppb.New(result.NotBefore)
	}

	if result.Session != nil {
		sessionInfo := &iamv1.SessionInfo{
			Id:      result.Session.ID,
			Revoked: result.Session.RevokedAt != nil,
		}
		if result.Session.DeviceLabel != nil {
			sessionInfo.DeviceLabel = strings.TrimSpace(*result.Session.DeviceLabel)
		}
		if result.Session.IPLast != nil {
			sessionInfo.IpLast = strings.TrimSpace(*result.Session.IPLast)
		}
		if !result.Session.LastSeen.IsZero() {
			sessionInfo.LastSeen = timestamppb.New(result.Session.LastSeen)
		}
		if !result.Session.ExpiresAt.IsZero() {
			sessionInfo.ExpiresAt = timestamppb.New(result.Session.ExpiresAt)
		}
		resp.Session = sessionInfo
	}

	return resp, nil
}

// RevokeByJTI handles explicit JTI revocation requests.
func (s *TokenServer) RevokeByJTI(ctx context.Context, req *iamv1.RevokeByJTIRequest) (*iamv1.RevokeResponse, error) {
	resp := &iamv1.RevokeResponse{}

	if s == nil || s.service == nil {
		resp.Error = "token service unavailable"
		return resp, nil
	}
	if req == nil || strings.TrimSpace(req.GetJti()) == "" {
		resp.Error = "jti is required"
		return resp, nil
	}

	count, err := s.service.RevokeByJTI(ctx, req.GetJti(), req.GetReason(), time.Time{})
	if err != nil {
		s.logger.Warn("revoke by jti failed", zap.Error(err))
		resp.Error = "failed to revoke token"
		return resp, nil
	}

	resp.Success = true
	resp.RevokedCount = int32(count)
	return resp, nil
}

// RevokeBySession revokes all tokens bound to a session.
func (s *TokenServer) RevokeBySession(ctx context.Context, req *iamv1.RevokeBySessionRequest) (*iamv1.RevokeResponse, error) {
	resp := &iamv1.RevokeResponse{}

	if s == nil || s.service == nil {
		resp.Error = "token service unavailable"
		return resp, nil
	}
	if req == nil || strings.TrimSpace(req.GetSessionId()) == "" {
		resp.Error = "session_id is required"
		return resp, nil
	}

	count, err := s.service.RevokeBySession(ctx, req.GetSessionId(), req.GetReason())
	if err != nil {
		s.logger.Warn("revoke by session failed", zap.Error(err))
		resp.Error = "failed to revoke session tokens"
		return resp, nil
	}

	resp.Success = true
	resp.RevokedCount = int32(count)
	return resp, nil
}

// RevokeAllForUser revokes every token recorded for a user.
func (s *TokenServer) RevokeAllForUser(ctx context.Context, req *iamv1.RevokeAllForUserRequest) (*iamv1.RevokeResponse, error) {
	resp := &iamv1.RevokeResponse{}

	if s == nil || s.service == nil {
		resp.Error = "token service unavailable"
		return resp, nil
	}
	if req == nil || strings.TrimSpace(req.GetUserId()) == "" {
		resp.Error = "user_id is required"
		return resp, nil
	}

	count, err := s.service.RevokeAllForUser(ctx, req.GetUserId(), req.GetReason())
	if err != nil {
		s.logger.Warn("revoke for user failed", zap.Error(err))
		resp.Error = "failed to revoke user tokens"
		return resp, nil
	}

	resp.Success = true
	resp.RevokedCount = int32(count)
	return resp, nil
}

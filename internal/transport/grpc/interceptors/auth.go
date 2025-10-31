package interceptors

import (
	"context"
	"errors"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

const (
	authorizationKey = "authorization"
	bearerPrefix     = "bearer "
)

// TokenParser exposes the access-token parsing capability required by the auth interceptor.
type TokenParser interface {
	ParseAccessToken(ctx context.Context, token string) (*security.AccessTokenClaims, error)
}

// AuthOptions fine-tunes interceptor behaviour.
type AuthOptions struct {
	AllowMethods []string
	Logger       *zap.Logger
}

// AuthInterceptor validates incoming requests using JWT access tokens.
type AuthInterceptor struct {
	parser TokenParser
	logger *zap.Logger
	allow  map[string]struct{}
}

// NewAuthInterceptor constructs a new AuthInterceptor instance.
func NewAuthInterceptor(parser TokenParser, opts AuthOptions) *AuthInterceptor {
	allow := make(map[string]struct{}, len(opts.AllowMethods))
	for _, method := range opts.AllowMethods {
		if method = strings.TrimSpace(method); method != "" {
			allow[method] = struct{}{}
		}
	}

	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return &AuthInterceptor{parser: parser, logger: logger, allow: allow}
}

// UnaryServerInterceptor returns a gRPC unary interceptor that enforces JWT authentication.
func (ai *AuthInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if ai == nil || ai.parser == nil {
			return handler(ctx, req)
		}

		if _, ok := ai.allow[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		token, err := tokenFromMetadata(ctx)
		if err != nil {
			ai.logger.Warn("gRPC authentication failed", zap.String("method", info.FullMethod), zap.Error(err))
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		claims, err := ai.parser.ParseAccessToken(ctx, token)
		if err != nil {
			ai.logger.Warn("gRPC token validation failed", zap.String("method", info.FullMethod), zap.Error(err))
			switch {
			case errors.Is(err, usecase.ErrExpiredAccessToken):
				return nil, status.Error(codes.Unauthenticated, "access token expired")
			case errors.Is(err, usecase.ErrInvalidAccessToken):
				return nil, status.Error(codes.Unauthenticated, "invalid access token")
			default:
				return nil, status.Error(codes.Unauthenticated, "failed to validate access token")
			}
		}

		ctx = WithClaims(ctx, claims)
		return handler(ctx, req)
	}
}

// claimsContextKey stores token claims within the request context.
type claimsContextKey struct{}

// WithClaims returns a derived context containing token claims.
func WithClaims(ctx context.Context, claims *security.AccessTokenClaims) context.Context {
	if claims == nil {
		return ctx
	}
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// ClaimsFromContext extracts token claims from context when available.
func ClaimsFromContext(ctx context.Context) (*security.AccessTokenClaims, bool) {
	if ctx == nil {
		return nil, false
	}
	claims, ok := ctx.Value(claimsContextKey{}).(*security.AccessTokenClaims)
	return claims, ok && claims != nil
}

func tokenFromMetadata(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("missing metadata")
	}

	var raw string
	for _, key := range []string{authorizationKey, strings.Title(authorizationKey)} {
		values := md.Get(key)
		if len(values) > 0 && strings.TrimSpace(values[0]) != "" {
			raw = values[0]
			break
		}
	}

	if raw == "" {
		return "", errors.New("authorization token required")
	}

	value := strings.TrimSpace(raw)
	if len(value) < len(bearerPrefix) || !strings.HasPrefix(strings.ToLower(value), bearerPrefix) {
		return "", errors.New("invalid authorization header")
	}

	token := strings.TrimSpace(value[len(bearerPrefix):])
	if token == "" {
		return "", errors.New("authorization token required")
	}

	return token, nil
}

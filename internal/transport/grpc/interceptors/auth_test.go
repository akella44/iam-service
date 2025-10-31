package interceptors

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/arklim/social-platform-iam/internal/infra/security"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

type stubTokenParser struct {
	claims *security.AccessTokenClaims
	err    error
}

func (s *stubTokenParser) ParseAccessToken(context.Context, string) (*security.AccessTokenClaims, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.claims, nil
}

func TestAuthInterceptorAllowsValidTokens(t *testing.T) {
	claims := &security.AccessTokenClaims{UserID: "user-123"}
	parser := &stubTokenParser{claims: claims}
	interceptor := NewAuthInterceptor(parser, AuthOptions{Logger: zaptest.NewLogger(t)}).UnaryServerInterceptor()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		got, ok := ClaimsFromContext(ctx)
		if !ok || got.UserID != "user-123" {
			t.Fatalf("claims missing from context")
		}
		return "ok", nil
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer token-value"))
	info := &grpc.UnaryServerInfo{FullMethod: "/iam.v1.PrivateService/Action"}

	if _, err := interceptor(ctx, struct{}{}, info, handler); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuthInterceptorRejectsMissingToken(t *testing.T) {
	parser := &stubTokenParser{}
	interceptor := NewAuthInterceptor(parser, AuthOptions{}).UnaryServerInterceptor()

	info := &grpc.UnaryServerInfo{FullMethod: "/iam.v1.PrivateService/Action"}
	if _, err := interceptor(context.Background(), struct{}{}, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatalf("handler should not be invoked")
		return nil, nil
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated error, got %v", err)
	}
}

func TestAuthInterceptorPassesThroughAllowedMethods(t *testing.T) {
	parser := &stubTokenParser{err: errors.New("should not be called")}
	interceptor := NewAuthInterceptor(parser, AuthOptions{AllowMethods: []string{"/iam.v1.TokenService/GetJWKS"}}).UnaryServerInterceptor()

	info := &grpc.UnaryServerInfo{FullMethod: "/iam.v1.TokenService/GetJWKS"}
	if _, err := interceptor(context.Background(), struct{}{}, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "pong", nil
	}); err != nil {
		t.Fatalf("expected allowed method to succeed, got %v", err)
	}
}

func TestAuthInterceptorMapsExpiredTokens(t *testing.T) {
	parser := &stubTokenParser{err: usecase.ErrExpiredAccessToken}
	interceptor := NewAuthInterceptor(parser, AuthOptions{}).UnaryServerInterceptor()

	info := &grpc.UnaryServerInfo{FullMethod: "/iam.v1.PrivateService/Action"}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer token"))
	if _, err := interceptor(ctx, struct{}{}, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatalf("handler should not be invoked")
		return nil, nil
	}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated for expired token, got %v", err)
	}
}

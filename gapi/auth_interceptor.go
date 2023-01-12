package gapi

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"grpc-jwt-auth/tokens"
	"grpc-jwt-auth/utils"
	"strings"
)

type AuthInterceptor struct {
	// Exclude special endpoints
	excludeEndpoints []string
}

func NewAuthInterceptor(excludeEndpoints []string) *AuthInterceptor {
	return &AuthInterceptor{
		excludeEndpoints,
	}
}

func (ai *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		err = ai.authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

func (ai *AuthInterceptor) authorize(ctx context.Context, method string) error {
	// Exclude special endpoints
	endpoint := strings.Split(method, "/")[2]
	if utils.StringInSlice(endpoint, ai.excludeEndpoints) {
		return nil
	}

	// Check if token is provided
	accessToken, _ := utils.TokensFromCtx(ctx)
	_, err := tokens.JwtManager.VerifyAccessToken(accessToken)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "access token is invalid: %v", err)
	}

	isForbidden := server.checkForbiddenToken(accessToken)
	if isForbidden {
		return status.Errorf(codes.Unauthenticated, "access token is no more valid: %v", err)
	}

	return nil
}

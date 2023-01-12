package utils

import (
	"context"
	"github.com/golang-jwt/jwt"
	"grpc-jwt-auth/tokens"
)

func UserIdFromCtx(ctx context.Context) (string, error) {
	accessToken, refreshToken := TokensFromCtx(ctx)
	var claims jwt.MapClaims
	var err error

	if accessToken == "" {
		claims, err = tokens.JwtManager.VerifyAccessToken(refreshToken)
	} else {
		claims, err = tokens.JwtManager.VerifyAccessToken(accessToken)
	}

	if err != nil {
		return "", err
	}

	id := claims["id"].(string)

	return id, nil
}

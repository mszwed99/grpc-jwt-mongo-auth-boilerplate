package utils

import (
	"context"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"grpc-jwt-auth/models"
	"grpc-jwt-auth/tokens"
)

func UserFromCtx(ctx context.Context) (*models.User, error) {
	accessToken, _ := TokensFromCtx(ctx)

	claims, err := tokens.JwtManager.VerifyAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	id, _ := primitive.ObjectIDFromHex(claims["id"].(string))
	email := claims["username"].(string)

	user := &models.User{
		ID:    id,
		Email: email,
	}

	return user, nil
}

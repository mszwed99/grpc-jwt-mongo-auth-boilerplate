package utils

import (
	"context"
	"google.golang.org/grpc/metadata"
)

func TokensFromCtx(ctx context.Context) (string, string) {
	var accessToken string = ""
	var refreshToken string = ""
	md, _ := metadata.FromIncomingContext(ctx)

	if md["access_token"] != nil {
		accessToken = md["access_token"][0]
	}

	if md["refresh_token"] != nil {
		refreshToken = md["refresh_token"][0]
	}
	return accessToken, refreshToken
}

package tokens

import (
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt"
	"math/rand"
	"os"
	"time"
)

type JwtConfig struct {
	accessSecret      []byte
	refreshSecret     []byte
	accessExpiration  time.Duration
	refreshExpiration time.Duration
}

type JwtClaims struct {
	jwt.StandardClaims
	Username string
	Id       string
}

var JwtManager = &JwtConfig{
	accessSecret:      []byte(os.Getenv("SECRET_ACCESS")),
	refreshSecret:     []byte(os.Getenv("SECRET_REFRESH")),
	accessExpiration:  time.Minute * 60,
	refreshExpiration: time.Hour * 168,
}

func (jc *JwtConfig) VerifyRefreshToken(refreshToken string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(
		refreshToken,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("unexpected error while signing a token")
			}
			return []byte(jc.refreshSecret), nil

		})
	if err != nil {
		return nil, fmt.Errorf("invaild token: %v", err)
	}
	return claims, nil
}

func (jc *JwtConfig) VerifyAccessToken(accessToken string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(
		accessToken,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("unexpected error while signing a token")
			}
			return []byte(jc.accessSecret), nil

		})
	if err != nil {
		return nil, fmt.Errorf("invaild token: %v", err)
	}
	return claims, nil
}

func (jc *JwtConfig) GenerateTokens(username string, id string) (string, string, error) {
	bits := make([]byte, 12)
	_, err := rand.Read(bits)
	if err != nil {
		panic(err)
	}

	// Access token claims
	accessClaims := &jwt.MapClaims{
		"tokenId":  base64.StdEncoding.EncodeToString(bits),
		"exp":      time.Now().Add(jc.accessExpiration).Unix(),
		"id":       id,
		"username": username,
	}
	_token := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, _ := _token.SignedString(jc.accessSecret)

	// Refresh token claims
	refreshClaims := &jwt.MapClaims{
		"tokenId":  base64.StdEncoding.EncodeToString(bits),
		"exp":      time.Now().Add(jc.refreshExpiration).Unix(),
		"id":       id,
		"username": username,
	}
	_token = jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, _ := _token.SignedString(jc.refreshSecret)

	return accessToken, refreshToken, nil
}

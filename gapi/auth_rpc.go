package gapi

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"grpc-jwt-auth/database"
	"grpc-jwt-auth/models"
	"grpc-jwt-auth/passwords"
	authpb "grpc-jwt-auth/protos"
	"grpc-jwt-auth/tokens"
	"grpc-jwt-auth/utils"
	"grpc-jwt-auth/validators"
)

func (s *Server) Info(ctx context.Context, req *authpb.EmptyRequestResponse) (*authpb.InfoResponse, error) {
	user, err := utils.UserFromCtx(ctx)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, err.Error())
	}
	fmt.Println("User: ", user)

	userId := user.ID.Hex()
	res := &authpb.InfoResponse{
		Id:    userId,
		Email: user.Email,
	}
	return res, nil
}

func (s *Server) Logout(ctx context.Context, req *authpb.LogoutRequest) (*authpb.LogoutResponse, error) {
	var usersCollection = database.NewUsersCollection()
	user, err := utils.UserFromCtx(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "")
	}
	usersCollection.UpdateRtHash(user.ID.Hex(), "")
	logoutToken, _ := utils.TokensFromCtx(ctx)
	s.addForbiddenToken(logoutToken)
	return &authpb.LogoutResponse{}, nil
}

func (s *Server) Refresh(ctx context.Context, req *authpb.RefreshRequest) (*authpb.RefreshResponse, error) {
	var usersCollection = database.NewUsersCollection()
	id, err := utils.UserIdFromCtx(ctx)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}

	user, err := usersCollection.FindOneById(id)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}
	_, rt := utils.TokensFromCtx(ctx)

	// Verify
	_, err = tokens.JwtManager.VerifyRefreshToken(rt)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "refresh token is invalid: %v", err)
	}

	if user.HashedRt == "" {
		return nil, status.Errorf(codes.Unauthenticated, "refresh token is invalid")
	}

	match, _ := passwords.HashManager.Verify(user.HashedRt, rt)
	if !match {
		return nil, status.Errorf(codes.Unauthenticated, "refresh token is invalid")
	}

	accessToken, refreshToken, err := tokens.JwtManager.GenerateTokens(user.Email, id)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}

	err = usersCollection.UpdateRtHash(id, refreshToken)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}

	return &authpb.RefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Server) SignIn(ctx context.Context, req *authpb.SignInRequest) (*authpb.SignInResponse, error) {
	// Users collection
	var usersCollection = database.NewUsersCollection()

	// Request body
	var email string = req.Email
	var password string = req.Password

	// Find user
	user, err := usersCollection.FindOneByEmail(email)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, status.Error(codes.NotFound, "user with a given credentials not found")
		}
		return nil, status.Error(codes.Unknown, "try again later")
	}

	match, _ := passwords.HashManager.Verify(user.Password, password)

	if !match {
		return nil, status.Error(codes.NotFound, "user with a given credentials not found")
	}

	userId := user.ID.Hex()
	accessToken, refreshToken, err := tokens.JwtManager.GenerateTokens(user.Email, userId)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}

	err = usersCollection.UpdateRtHash(userId, refreshToken)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}

	// Response
	res := &authpb.SignInResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	return res, nil

}

func (s *Server) SignUp(ctx context.Context, req *authpb.SignUpRequest) (*authpb.SignUpResponse, error) {

	// Users collection
	var usersCollection = database.NewUsersCollection()

	// Request body
	var email string = req.Email
	var password string = req.Password

	// Validation
	validationErr := validators.SignUpValidator(email, password)
	if len(validationErr) != 0 {
		return nil, status.Errorf(codes.InvalidArgument, "%v", validationErr)
	}

	// Hash passwords
	hash, err := passwords.HashManager.Hash(password)
	if err != nil {
		return nil, status.Error(codes.Unknown, "try again later")
	}

	// Save user in DB
	var user = models.User{
		ID:       primitive.NewObjectID(),
		Email:    email,
		Password: hash}
	userId, err := usersCollection.InsertUser(&user)
	if err != nil {
		// Get duplicate error key
		if mongo.IsDuplicateKeyError(err) {
			return nil, status.Error(codes.AlreadyExists, "A user already exists with the credentials you've provided")
		}

		return nil, status.Error(codes.Unavailable, "")
	}

	accessToken, refreshToken, err := tokens.JwtManager.GenerateTokens(user.Email, userId)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, err.Error())
	}
	err = usersCollection.UpdateRtHash(userId, refreshToken)
	// Response
	res := &authpb.SignUpResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	return res, nil
}

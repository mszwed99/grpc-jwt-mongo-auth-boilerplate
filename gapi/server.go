package gapi

import (
	"fmt"
	"google.golang.org/grpc"
	authpb "grpc-jwt-auth/protos"
	"log"
	"net"
	"os"
)

type Server struct {
	authpb.UnimplementedAuthServiceServer
	forbiddenTokens []string
}

func (s *Server) addForbiddenToken(loggedOutToken string) {
	s.forbiddenTokens = append(s.forbiddenTokens, loggedOutToken)
}

func (s *Server) checkForbiddenToken(token string) bool {
	for _, t := range s.forbiddenTokens {
		if t == token {
			return true
		}
	}
	return false
}

var server Server

func Run() error {
	port := os.Getenv("PORT")
	fmt.Printf("Server running at port: [%v]...", port)
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%v", port))
	if err != nil {
		log.Fatalf("Error while running a gRPC server: %v", err)
	}

	// Grpc Server
	authInterceptor := NewAuthInterceptor([]string{
		// Excluded endpoint - no access token needed
		"SignUp",
		"SignIn",
		"Refresh",
	})

	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(authInterceptor.Unary()),
	}

	s := grpc.NewServer(serverOptions...)
	authpb.RegisterAuthServiceServer(s, &server)

	if err := s.Serve(lis); err != nil {
		return err
	}

	return nil
}

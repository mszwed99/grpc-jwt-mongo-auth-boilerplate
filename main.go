package main

import (
	"grpc-jwt-auth/database"
	"grpc-jwt-auth/gapi"
	"grpc-jwt-auth/initializers"
)

func main() {
	initializers.LoadEnvVariables()
	database.MongoManager.Connect()
	gapi.Run()
}

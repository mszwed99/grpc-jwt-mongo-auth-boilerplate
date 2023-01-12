package database

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"grpc-jwt-auth/models"
	"grpc-jwt-auth/passwords"
)

type UsersCollection struct {
	*mongo.Collection
}

func NewUsersCollection() *UsersCollection {
	return &UsersCollection{
		MongoManager.Client.Database("authentication").Collection("users"),
	}
}

func (uc *UsersCollection) InsertUser(user *models.User) (string, error) {
	res, err := uc.InsertOne(context.TODO(), user)
	if err != nil {
		return "", err
	}

	objId := res.InsertedID.(primitive.ObjectID).Hex()
	return objId, nil
}

func (uc *UsersCollection) UpdateRtHash(id string, rt string) error {
	hashRt, err := passwords.HashManager.Hash(rt)
	if err != nil {
		return err
	}

	idObj, _ := primitive.ObjectIDFromHex(id)
	filter := bson.D{{"_id", idObj}}
	update := bson.D{{"$set", bson.D{{"hashedrt", hashRt}}}}

	_, err = uc.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		return err
	}
	return nil
}

func (uc *UsersCollection) FindOneByEmail(email string) (*models.User, error) {
	var res *models.User

	filter := bson.D{{"email", email}}

	err := uc.FindOne(context.TODO(), filter).Decode(&res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (uc *UsersCollection) FindOneById(id string) (*models.User, error) {
	var res *models.User
	idObj, _ := primitive.ObjectIDFromHex(id)
	filter := bson.D{{"_id", idObj}}

	err := uc.FindOne(context.TODO(), filter).Decode(&res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

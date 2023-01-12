package database

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/bsonx"
	"log"
	"os"
	"strings"
	"time"
)

type MongoConfig struct {
	Client *mongo.Client
}

var MongoManager = &MongoConfig{}

func (m *MongoConfig) Connect() {
	var err error
	m.Client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(os.Getenv("DB_URL")))
	if err != nil {
		panic(err)
	}

	if err := m.Client.Ping(context.TODO(), readpref.Primary()); err != nil {
		panic(err)
	}

	// Set unique property - username
	m.CreateUniqueField("authentication", "users", "email")

	fmt.Println("Connected to MongoDB!")
}

func (m *MongoConfig) CreateUniqueField(database string, collection string, keys ...string) {
	keysDoc := bsonx.Doc{}
	for _, key := range keys {
		if strings.HasPrefix(key, "-") {
			keysDoc = keysDoc.Append(strings.TrimLeft(key, "-"), bsonx.Int32(-1))
		} else {
			keysDoc = keysDoc.Append(key, bsonx.Int32(1))
		}
	}
	_, err := m.Client.Database(database).Collection(collection).Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    keysDoc,
			Options: options.Index().SetUnique(true),
		},
		options.CreateIndexes().SetMaxTime(10*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}
}

package database

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func Open(ctx context.Context, uri string) (*mongo.Database, error) {
	if strings.TrimSpace(uri) == "" {
		return nil, errors.New("MONGODB_URI is required")
	}
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetTimeout(5 * time.Second))
	if err != nil {
		return nil, errors.New("invalid MongoDB configuration")
	}

	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := client.Ping(startup, nil); err != nil {
		Close(client)
		return nil, errors.New("MongoDB startup ping failed")
	}
	db := client.Database("go-mongodb")
	_, err = db.Collection("user").Indexes().CreateOne(startup, mongo.IndexModel{
		Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true),
	})
	if err != nil {
		Close(client)
		return nil, errors.New("MongoDB unique email index unavailable")
	}
	return db, nil
}

func Close(client *mongo.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = client.Disconnect(ctx)
}

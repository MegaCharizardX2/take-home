package models

import "go.mongodb.org/mongo-driver/v2/bson"

type Todo struct {
	ID     bson.ObjectID `json:"ID" bson:"_id"`
	Name   string        `json:"name" bson:"name"`
	Status string        `json:"status" bson:"status"`
	UserID string        `json:"user_id" bson:"userid"`
}

type User struct {
	ID       bson.ObjectID `bson:"_id"`
	Name     string        `bson:"name"`
	Email    string        `bson:"email"`
	Password string        `bson:"password" json:"-"`
}

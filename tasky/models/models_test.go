package models

import (
	"go.mongodb.org/mongo-driver/v2/bson"
	"testing"
)

func TestLegacyTaskLayout(t *testing.T) {
	id, owner := bson.NewObjectID(), bson.NewObjectID().Hex()
	task := Todo{ID: id, UserID: owner, Name: "fixture", Status: "pending"}
	wire, err := bson.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	doc := bson.Raw(wire)
	if doc.Lookup("_id").ObjectID() != id || doc.Lookup("userid").StringValue() != owner ||
		doc.Lookup("name").StringValue() != "fixture" || doc.Lookup("status").StringValue() != "pending" {
		t.Fatal("stored task schema changed")
	}
	wire, err = bson.Marshal(bson.M{"_id": id, "name": "fixture", "email": "test@example.invalid", "password": "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	var user User
	if err := bson.Unmarshal(wire, &user); err != nil || user.ID != id || user.Name != "fixture" || user.Email != "test@example.invalid" || user.Password != "fixture" {
		t.Fatal("legacy user document unreadable")
	}
}

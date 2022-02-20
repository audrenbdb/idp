package mongo_test

import (
	"context"
	"flag"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"
)

var testDB = flag.Bool("db", false, "Do integration tests with your mongo implementation")

func newDB() *mongo.Database {
	uri := os.Getenv("MONGO_URI")
	if uri == "" {
		log.Fatal("No \"MONGO_URI\"")
	}
	client, err := mongo.Connect(context.Background(),
		options.Client().ApplyURI(uri),
	)
	if err != nil {
		log.Fatal(err)
	}
	return client.Database("idp_test")
}

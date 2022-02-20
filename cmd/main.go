package main

import (
	"context"
	"flag"
	mgo "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"idp"
	"idp/repo/mongo"
	"log"
	"os"
)

var port = flag.Int("port", 8086, "Set the idp server port")

func main() {
	db := startMongo()
	accessRepo := mongo.NewAccessRepository(db)
	authRepo := mongo.NewAuthorizationRepository(db)
	clientRepo := mongo.NewClientRepository(db)
	sessionRepo := mongo.NewSessionRepository(db)
	userRepo := mongo.NewUserRepository(db)

	oauthService := idp.NewOAuthService(idp.OAuthServiceOpt{
		AccessRepo:        accessRepo,
		AuthorizationRepo: authRepo,
		ClientRepo:        clientRepo,
		SessionRepo:       sessionRepo,
	})

	loginService := idp.NewLoginService(idp.LoginServiceOpt{
		UserRepo:    userRepo,
		SessionRepo: sessionRepo,
	})

	if err := idp.StartServer(*port, oauthService, loginService); err != nil {
		log.Fatal(err)
	}
}

func startMongo() *mgo.Database {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		log.Fatal("Env MONGO_URI not set and is required for persistence")
	}
	client, err := mgo.Connect(context.Background(),
		options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal(err)
	}
	return client.Database("idp")
}

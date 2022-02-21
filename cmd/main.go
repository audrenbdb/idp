package main

import (
	"context"
	"flag"
	"fmt"
	mgo "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"idp"
	"idp/repo/mongo"
	"log"
	"os"
)

var addr = flag.String("addr", "localhost:8080", "Set the idp server address")
var idpName = flag.String("name", "App", "Your idp name")

func main() {
	flag.Parse()

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

	if err := idp.StartServer(*idpName, *addr, oauthService, loginService); err != nil {
		log.Fatal(err)
	}
}

func startMongo() *mgo.Database {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		fmt.Sprintf(
			"env variable \"%s\" is not set.\nUsing default: \"%s\" instead.",
			"MONGO_URI", "mongodb://localhost:27017",
		)
		mongoURI = "mongodb://localhost:27017"
	}
	client, err := mgo.Connect(context.Background(),
		options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal(err)
	}
	return client.Database("idp")
}

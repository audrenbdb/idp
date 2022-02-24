package main

import (
	"context"
	"flag"
	"fmt"
	mgo "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"idp"
	"idp/repo/inmem"
	"idp/repo/mongo"
	"idp/send/mail"
	"log"
	"os"
)

var port = flag.Int("port", 8080, "Set the idp port")

// addr when creating external link to your service
var addr = flag.String("addr", "http://localhost:8080", "Set the idp url address")
var name = flag.String("name", "App", "Your idp name")

// mailer client to use
// accepted values :
//     - smtp
//     - postfix
// defaults to postfix
var mailer = flag.String("mailer", "postfix", "Set email system. Defaults to postfix")

func main() {
	flag.Parse()

	db := startMongo()
	accessRepo := mongo.NewAccessRepository(db)
	authRepo := mongo.NewAuthorizationRepository(db)
	clientRepo := mongo.NewClientRepository(db)
	sessionRepo := mongo.NewSessionRepository(db)
	userRepo := mongo.NewUserRepository(db)

	passwordResetRepo := inmem.NewPasswordResetRepository()

	oauthService := idp.NewOAuthService(idp.OAuthServiceOpt{
		AccessRepo:        accessRepo,
		AuthorizationRepo: authRepo,
		ClientRepo:        clientRepo,
		SessionRepo:       sessionRepo,
	})

	loginService := idp.NewLoginService(idp.LoginServiceOpt{
		UserRepo:          userRepo,
		SessionRepo:       sessionRepo,
		PasswordResetRepo: passwordResetRepo,
		Sender:            getSender(),
	})

	if err := idp.StartServer(*name, fmt.Sprintf(":%d", *port), oauthService, loginService); err != nil {
		log.Fatal(err)
	}
}

func startMongo() *mgo.Database {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		fmt.Println(fmt.Sprintf(
			"env variable \"%s\" is not set.\nUsing default: \"%s\" instead.",
			"MONGO_URI", "mongodb://localhost:27017",
		))
		mongoURI = "mongodb://localhost:27017"
	}
	client, err := mgo.Connect(context.Background(),
		options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal(err)
	}
	return client.Database("idp")
}

func getSender() idp.Sender {
	switch *mailer {
	case "smtp":
		return mail.NewSMTPClient(*addr, *name)
	default:
		return mail.NewPostFixClient(*addr, *name)
	}
}

package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"idp"
)

type clientRepository struct {
	clients *mongo.Collection
}

func NewClientRepository(db *mongo.Database) *clientRepository {
	return &clientRepository{
		clients: db.Collection("clients"),
	}
}

func (r *clientRepository) SaveClient(ctx context.Context, client idp.Client) (idp.Client, error) {
	_, err := r.clients.InsertOne(ctx, client)
	return client, err
}

func (r *clientRepository) GetClientByID(ctx context.Context, id string) (client idp.Client, err error) {
	err = r.clients.FindOne(ctx, bson.M{"id": id}).Decode(&client)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return client, idp.ErrClientNotFound
	}
	return client, err
}

package mongo

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"idp"
)

type authorizationRepository struct {
	authorizations *mongo.Collection
}

func NewAuthorizationRepository(db *mongo.Database) *authorizationRepository {
	return &authorizationRepository{
		authorizations: db.Collection("authorizations"),
	}
}

func (r *authorizationRepository) SaveAuthorization(ctx context.Context, auth idp.Authorization) (idp.Authorization, error) {
	_, err := r.authorizations.InsertOne(ctx, auth)
	return auth, err
}

func (r *authorizationRepository) GetAuthorizationByCode(ctx context.Context, code string) (auth idp.Authorization, err error) {
	cursor, err := r.authorizations.Aggregate(ctx, mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.M{
			"code": code,
		}}},
		bson.D{{Key: "$lookup", Value: bson.M{
			"from":         "users",
			"localField":   "userUID",
			"foreignField": "uid",
			"as":           "user",
		}}},
		bson.D{{Key: "$unwind", Value: bson.M{
			"path": "$user",
		}}},
		bson.D{{Key: "$lookup", Value: bson.M{
			"from":         "clients",
			"localField":   "clientID",
			"foreignField": "id",
			"as":           "client",
		}}},
		bson.D{{Key: "$unwind", Value: bson.M{
			"path": "$client",
		}}},
	})
	if err != nil {
		return auth, err
	}
	defer cursor.Close(ctx)
	if !cursor.Next(ctx) {
		return auth, idp.ErrAuthorizationNotFound
	}
	return auth, cursor.Decode(&auth)
}

func (r *authorizationRepository) DeleteAuthorization(ctx context.Context, code string) error {
	_, err := r.authorizations.DeleteOne(ctx, bson.M{"code": code})
	return err
}

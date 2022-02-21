package mongo

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"idp"
)

type accessRepository struct {
	accesses *mongo.Collection
}

func NewAccessRepository(db *mongo.Database) *accessRepository {
	return &accessRepository{
		accesses: db.Collection("accesses"),
	}
}

func (r *accessRepository) SaveAccess(ctx context.Context, access idp.Access) (idp.Access, error) {
	_, err := r.accesses.InsertOne(ctx, access)
	return access, err
}

func (r *accessRepository) DeleteAccess(ctx context.Context, id string) error {
	_, err := r.accesses.DeleteOne(ctx, bson.M{"id": id})
	return err
}

func (r *accessRepository) GetAccessByID(ctx context.Context, id string) (access idp.Access, err error) {
	return r.findAccess(ctx, mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.M{
			"id": id,
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
	})
}

func (r *accessRepository) GetAccessByRefreshTokenID(ctx context.Context, refreshTokenID string) (access idp.Access, err error) {
	return r.findAccess(ctx, mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.M{
			"refreshToken.id": refreshTokenID,
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
	})
}

func (r *accessRepository) findAccess(ctx context.Context, pl mongo.Pipeline) (access idp.Access, err error) {
	cursor, err := r.accesses.Aggregate(ctx, pl)
	if err != nil {
		return access, err
	}
	defer cursor.Close(ctx)
	if !cursor.Next(ctx) {
		return access, idp.ErrAccessNotFound
	}
	return access, cursor.Decode(&access)
}

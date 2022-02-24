package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"idp"
)

type userRepository struct {
	users *mongo.Collection
}

func NewUserRepository(db *mongo.Database) *userRepository {
	return &userRepository{
		users: db.Collection("users"),
	}
}

func (r *userRepository) SaveUser(ctx context.Context, user idp.User) (idp.User, error) {
	opts := options.Update().SetUpsert(true)
	_, err := r.users.UpdateOne(ctx,
		bson.M{"uid": user.UID},
		bson.M{"$set": user},
		opts)
	return user, err
}

func (r *userRepository) GetUserByEmail(ctx context.Context, email string) (user idp.User, err error) {
	err = r.users.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return user, idp.ErrUserNotFound
	}
	return user, err
}

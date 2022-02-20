package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
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
	_, err := r.users.InsertOne(ctx, user)
	return user, err
}

func (r *userRepository) GetUserByEmail(ctx context.Context, email string) (user idp.User, err error) {
	err = r.users.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return user, idp.ErrUserNotFound
	}
	return user, err
}

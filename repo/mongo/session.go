package mongo

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"idp"
)

type sessionRepository struct {
	sessions *mongo.Collection
}

func NewSessionRepository(db *mongo.Database) *sessionRepository {
	return &sessionRepository{
		sessions: db.Collection("sessions"),
	}
}

func (r *sessionRepository) SaveSession(ctx context.Context, session idp.Session) (idp.Session, error) {
	_, err := r.sessions.InsertOne(ctx, session)
	return session, err
}

func (r *sessionRepository) GetSessionByID(ctx context.Context, sessionID string) (session idp.Session, err error) {
	cursor, err := r.sessions.Aggregate(ctx, mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.M{
			"id": sessionID,
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
	if err != nil {
		return session, err
	}
	defer cursor.Close(ctx)
	if !cursor.Next(ctx) {
		return session, idp.ErrSessionNotFound
	}
	return session, cursor.Decode(&session)
}

package mongo_test

import (
	"context"
	"github.com/stretchr/testify/assert"
	"idp"
	"idp/rand"
	"idp/repo/mongo"
	"testing"
)

func TestSessionRepo(t *testing.T) {
	if !*testDB {
		t.Skip()
	}

	generateID := rand.IDGenerator(40)

	jon := idp.User{UID: generateID(), Email: "jon@doe.com"}
	jonSession := idp.Session{
		ID:   generateID(),
		User: jon,
	}

	ctx := context.Background()
	db := newDB()
	db.Collection("users").InsertOne(ctx, jon)

	sessionRepo := mongo.NewSessionRepository(db)

	session, err := sessionRepo.SaveSession(ctx, jonSession)
	assert.NoError(t, err)
	assert.Equal(t, jonSession, session)

	session, err = sessionRepo.GetSessionByID(ctx, jonSession.ID)
	assert.NoError(t, err)
	assert.Equal(t, jonSession, session)
}

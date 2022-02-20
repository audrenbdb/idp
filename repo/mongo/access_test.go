package mongo_test

import (
	"context"
	"github.com/stretchr/testify/assert"
	"idp"
	"idp/rand"
	"idp/repo/mongo"
	"testing"
)

func TestAccessRepo(t *testing.T) {
	if !*testDB {
		t.Skip()
	}

	generateID := rand.IDGenerator(40)

	jon := idp.User{UID: generateID(), Email: "jon@doe.com"}

	ctx := context.Background()
	db := newDB()
	db.Collection("users").InsertOne(ctx, jon)

	accessRepository := mongo.NewAccessRepository(db)

	jonAccess, err := accessRepository.SaveAccess(ctx, idp.Access{
		ID:   generateID(),
		User: jon,
	})
	assert.NoError(t, err)

	access, err := accessRepository.GetAccessByID(ctx, jonAccess.ID)
	assert.NoError(t, err)
	assert.Equal(t, jonAccess, access)
	assert.Equal(t, jon, jonAccess.User)
}

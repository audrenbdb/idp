package mongo_test

import (
	"context"
	"github.com/stretchr/testify/assert"
	"idp"
	"idp/rand"
	"idp/repo/mongo"
	"testing"
	"time"
)

func TestAccessRepo(t *testing.T) {
	if !*testDB {
		t.Skip()
	}

	generateID := rand.IDGenerator(40)

	jon := idp.User{
		UID:       generateID(),
		Email:     "jon@doe.com",
		FirstName: "Jon",
		LastName:  "Doe",
	}

	jonAccess := idp.Access{
		ID:   generateID(),
		User: jon,
		RefreshToken: idp.RefreshToken{
			ID:         generateID(),
			Expiration: time.Now().UTC().Truncate(time.Millisecond),
		},
		Expiration: time.Now().UTC().Truncate(time.Millisecond),
	}

	ctx := context.Background()
	db := newDB()
	db.Collection("users").InsertOne(ctx, jon)

	accessRepository := mongo.NewAccessRepository(db)

	_, err := accessRepository.SaveAccess(ctx, jonAccess)
	assert.NoError(t, err)

	access, err := accessRepository.GetAccessByID(ctx, jonAccess.ID)
	assert.NoError(t, err)
	assert.Equal(t, jonAccess, access)

	access, err = accessRepository.GetAccessByRefreshTokenID(ctx, jonAccess.RefreshToken.ID)
	assert.NoError(t, err)
	assert.Equal(t, jonAccess, access)

	err = accessRepository.DeleteAccess(ctx, jonAccess.ID)
	assert.NoError(t, err)

	_, err = accessRepository.GetAccessByID(ctx, jonAccess.ID)
	assert.Equal(t, idp.ErrAccessNotFound, err)
}

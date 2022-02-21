package mongo_test

import (
	"context"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"idp"
	"idp/rand"
	"idp/repo/mongo"
	"testing"
)

func TestUserRepo(t *testing.T) {
	if !*testDB {
		t.Skip()
	}

	generateID := rand.IDGenerator(40)

	jon := idp.User{
		UID:            generateID(),
		Email:          "jon@deau.fr",
		HashedPassword: []byte("top_secret"),
	}

	ctx := context.Background()
	db := newDB()
	db.Collection("users").DeleteMany(ctx, bson.M{"email": jon.Email})

	repo := mongo.NewUserRepository(db)

	user, err := repo.SaveUser(ctx, jon)
	assert.NoError(t, err)
	assert.Equal(t, jon, user)

	user, err = repo.GetUserByEmail(ctx, jon.Email)
	assert.NoError(t, err)
	assert.Equal(t, jon, user)
}

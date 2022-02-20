package mongo_test

import (
	"context"
	"github.com/stretchr/testify/assert"
	"idp"
	"idp/rand"
	"idp/repo/mongo"
	"testing"
)

func TestAuthorizationRepo(t *testing.T) {
	if !*testDB {
		t.Skip()
	}

	generateID := rand.IDGenerator(40)

	bob := idp.User{UID: generateID(), Email: "bobsap@ufc.org"}
	avengers := idp.Client{
		ID:                  generateID(),
		Secret:              generateID(),
		Name:                "Avengers Org.",
		AuthorizedRedirects: []string{"http://marvel/redirect"},
	}

	ctx := context.Background()
	db := newDB()
	db.Collection("users").InsertOne(ctx, bob)
	db.Collection("clients").InsertOne(ctx, avengers)

	authRepo := mongo.NewAuthorizationRepository(db)

	bobAuthorization, err := authRepo.SaveAuthorization(ctx, idp.Authorization{
		Code:        generateID(),
		User:        bob,
		RedirectURI: "http://re.di.rect",
		Client:      avengers,
	})
	assert.NoError(t, err)

	auth, err := authRepo.GetAuthorizationByCode(ctx, bobAuthorization.Code)
	assert.NoError(t, err)
	assert.Equal(t, bobAuthorization, auth)

	err = authRepo.DeleteAuthorization(ctx, bobAuthorization.Code)
	assert.NoError(t, err)

	_, err = authRepo.GetAuthorizationByCode(ctx, bobAuthorization.Code)
	assert.Equal(t, idp.ErrAuthorizationNotFound, err)
}

package mongo_test

import (
	"context"
	"github.com/stretchr/testify/assert"
	"idp"
	"idp/rand"
	"idp/repo/mongo"
	"testing"
)

func TestClientRepo(t *testing.T) {
	if !*testDB {
		t.Skip()
	}

	generateID := rand.IDGenerator(40)

	avengers := idp.Client{
		ID:                  generateID(),
		Secret:              generateID(),
		Name:                "Avengers org.",
		AuthorizedRedirects: []string{"https://marvel/redirect"},
	}

	ctx := context.Background()
	db := newDB()

	repo := mongo.NewClientRepository(db)

	client, err := repo.SaveClient(ctx, avengers)
	assert.NoError(t, err)
	assert.Equal(t, avengers, client)

	client, err = repo.GetClientByID(ctx, avengers.ID)
	assert.NoError(t, err)
	assert.Equal(t, avengers, client)
}

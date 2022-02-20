package inmem

import (
	"context"
	"idp"
)

type clientRepository struct {
	clients map[string]idp.Client
}

func NewClientRepository() *clientRepository {
	return &clientRepository{
		clients: map[string]idp.Client{},
	}
}

func (r clientRepository) SaveClient(ctx context.Context, client idp.Client) (idp.Client, error) {
	r.clients[client.ID] = client
	return client, nil
}

func (r clientRepository) GetClientByID(ctx context.Context, clientID string) (idp.Client, error) {
	client, ok := r.clients[clientID]
	if !ok {
		return idp.Client{}, idp.ErrClientNotFound
	}
	return client, nil
}

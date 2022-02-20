package inmem

import (
	"context"
	"idp"
)

type accessRepository struct {
	accesses map[string]idp.Access
}

func NewAccessRepository() *accessRepository {
	return &accessRepository{
		accesses: map[string]idp.Access{},
	}
}

func (r *accessRepository) SaveAccess(ctx context.Context, access idp.Access) (idp.Access, error) {
	r.accesses[access.ID] = access
	return access, nil
}

func (r *accessRepository) GetAccessByID(ctx context.Context, id string) (idp.Access, error) {
	access, ok := r.accesses[id]
	if !ok {
		return idp.Access{}, idp.ErrAccessNotFound
	}
	return access, nil
}

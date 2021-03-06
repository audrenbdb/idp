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

func (r *accessRepository) GetAccessByRefreshTokenID(ctx context.Context, refreshID string) (idp.Access, error) {
	for _, access := range r.accesses {
		if access.RefreshToken.ID == refreshID {
			return access, nil
		}
	}
	return idp.Access{}, idp.ErrAccessNotFound
}

func (r *accessRepository) DeleteAccess(ctx context.Context, id string) error {
	delete(r.accesses, id)
	return nil
}

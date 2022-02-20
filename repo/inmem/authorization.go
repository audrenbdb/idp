package inmem

import (
	"context"
	"idp"
)

type authorizationRepository struct {
	authorizations map[string]idp.Authorization
}

func NewAuthorizationRepository() *authorizationRepository {
	return &authorizationRepository{
		authorizations: map[string]idp.Authorization{},
	}
}

func (r *authorizationRepository) SaveAuthorization(ctx context.Context, authorization idp.Authorization) (idp.Authorization, error) {
	r.authorizations[authorization.Code] = authorization
	return authorization, nil
}

func (r *authorizationRepository) GetAuthorizationByCode(ctx context.Context, code string) (idp.Authorization, error) {
	authorization, ok := r.authorizations[code]
	if !ok {
		return idp.Authorization{}, idp.ErrAuthorizationNotFound
	}
	return authorization, nil
}

func (r *authorizationRepository) DeleteAuthorization(ctx context.Context, code string) error {
	delete(r.authorizations, code)
	return nil
}

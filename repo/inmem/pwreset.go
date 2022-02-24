package inmem

import (
	"context"
	"idp"
)

type passwordResetRepository struct {
	resets map[string]idp.PasswordReset
}

func NewPasswordResetRepository() *passwordResetRepository {
	return &passwordResetRepository{
		resets: map[string]idp.PasswordReset{},
	}
}

func (r *passwordResetRepository) GetPasswordReset(ctx context.Context, id string) (idp.PasswordReset, error) {
	pwReset, ok := r.resets[id]
	if !ok {
		return idp.PasswordReset{}, idp.ErrPasswordResetNotFound
	}
	return pwReset, nil
}

func (r *passwordResetRepository) SavePasswordReset(ctx context.Context, reset idp.PasswordReset) (idp.PasswordReset, error) {
	r.resets[reset.Token] = reset
	return reset, nil
}

func (r *passwordResetRepository) DeletePasswordReset(ctx context.Context, id string) error {
	delete(r.resets, id)
	return nil
}

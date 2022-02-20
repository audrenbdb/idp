package inmem

import (
	"context"
	"idp"
)

type userRepository struct {
	users map[string]idp.User
}

func NewUserRepository() *userRepository {
	return &userRepository{
		users: map[string]idp.User{},
	}
}

func (r *userRepository) SaveUser(ctx context.Context, user idp.User) (idp.User, error) {
	r.users[user.UID] = user
	return user, nil
}

func (r *userRepository) GetUserByEmail(ctx context.Context, email string) (idp.User, error) {
	for _, user := range r.users {
		if user.Email == email {
			return user, nil
		}
	}
	return idp.User{}, idp.ErrUserNotFound
}

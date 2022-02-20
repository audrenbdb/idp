package idp_test

import (
	"context"
	"github.com/stretchr/testify/assert"
	"idp"
	"idp/repo/inmem"
	"testing"
	"time"
)

func fakeHash(pw string) ([]byte, error) {
	return []byte(pw), nil
}

func fakeMatchHash(pw string, hash []byte) bool {
	return pw == string(hash)
}

func TestAuthenticateUser(t *testing.T) {
	ctx := context.Background()

	t.Run("Cannot authenticate user when password is insecure", func(t *testing.T) {
		service := idp.NewLoginService(idp.LoginServiceOpt{})

		_, err := service.AuthenticateUser(ctx, idp.Credential{
			Email:    "bob@sap.fr",
			Password: "123",
		})
		assert.Equal(t, idp.ErrPasswordInvalid, err)
	})

	t.Run("Cannot authenticate user when email is invalid", func(t *testing.T) {
		service := idp.NewLoginService(idp.LoginServiceOpt{})

		_, err := service.AuthenticateUser(ctx, idp.Credential{
			Email:    "bob",
			Password: "123456",
		})
		assert.Equal(t, idp.ErrEmailInvalid, err)
	})

	t.Run("Cannot authenticate a user with mismatching email or password", func(t *testing.T) {
		jon := idp.User{
			UID:            "xyz",
			Email:          "jean@deau.fr",
			HashedPassword: []byte("top_secret"),
		}

		userRepository := inmem.NewUserRepository()
		userRepository.SaveUser(ctx, jon)

		service := idp.NewLoginService(idp.LoginServiceOpt{
			UserRepo:          userRepository,
			HashPassword:      fakeHash,
			PasswordMatchHash: fakeMatchHash,
		})

		_, err := service.AuthenticateUser(ctx, idp.Credential{
			Email:    jon.Email,
			Password: "not_secret",
		})
		assert.Equal(t, idp.ErrEmailOrPasswordMismatch, err)
	})

	t.Run("A new user and its session should be saved when credentials are valid", func(t *testing.T) {
		bobCredential := idp.Credential{
			Email:    "bob@sap.org",
			Password: "top_secret",
		}

		userRepository := inmem.NewUserRepository()
		sessionRepository := inmem.NewSessionRepository()

		generatedID := "qjkhdqjbcbqcw"

		service := idp.NewLoginService(idp.LoginServiceOpt{
			UserRepo:          userRepository,
			SessionRepo:       sessionRepository,
			HashPassword:      fakeHash,
			PasswordMatchHash: fakeMatchHash,
			NewRandID:         newDeterminedIDGenerator(generatedID),
			Now:               fakeNow,
		})

		wantBobSession := idp.Session{
			ID:         generatedID,
			Expiration: testTime.Add(24 * time.Hour * 30 * 3),
			User: idp.User{
				UID:            generatedID,
				Email:          bobCredential.Email,
				HashedPassword: []byte(bobCredential.Password),
			},
		}

		session, err := service.AuthenticateUser(ctx, bobCredential)
		assert.NoError(t, err)
		assert.Equal(t, wantBobSession, session)

		session, err = sessionRepository.GetSessionByID(ctx, session.ID)
		assert.NoError(t, err)
		assert.Equal(t, wantBobSession, session)

		user, err := userRepository.GetUserByEmail(ctx, bobCredential.Email)
		assert.NoError(t, err)
		assert.Equal(t, wantBobSession.User, user)
	})
}

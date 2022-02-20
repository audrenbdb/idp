package idp_test

import (
	"context"
	"github.com/stretchr/testify/assert"
	"idp"
	"idp/repo/inmem"
	"strings"
	"testing"
	"time"
)

func fakeHash(pw string) ([]byte, error) {
	return []byte(pw), nil
}

func fakeMatchHash(pw string, hash []byte) bool {
	return pw == string(hash)
}

func TestRegisterUser(t *testing.T) {
	ctx := context.Background()

	t.Run("Cannot register a user with an invalid first name", func(t *testing.T) {
		jonForm := idp.UserForm{
			FirstName: "J",
			LastName:  "Doe",
			Email:     "jon@doe.com",
			Password:  "123456",
		}

		service := idp.NewLoginService(idp.LoginServiceOpt{})
		_, err := service.RegisterUser(ctx, jonForm)
		assert.Equal(t, idp.ErrUserFirstNameInvalid, err)
	})

	t.Run("Cannot register a user with an invalid last name", func(t *testing.T) {
		bobForm := idp.UserForm{
			FirstName: "Bob",
			LastName:  "S",
			Email:     "bobsap@ufc.org",
			Password:  "123456",
		}

		service := idp.NewLoginService(idp.LoginServiceOpt{})
		_, err := service.RegisterUser(ctx, bobForm)
		assert.Equal(t, idp.ErrUserLastNameInvalid, err)
	})

	t.Run("Cannot register a user with an invalid email", func(t *testing.T) {
		joeyForm := idp.UserForm{
			FirstName: "Joey",
			LastName:  "Tribiani",
			Email:     "joey",
			Password:  "123456",
		}

		service := idp.NewLoginService(idp.LoginServiceOpt{})
		_, err := service.RegisterUser(ctx, joeyForm)
		assert.Equal(t, idp.ErrEmailInvalid, err)
	})

	t.Run("Cannot register a user with an invalid password", func(t *testing.T) {
		joeyForm := idp.UserForm{
			FirstName: "Joey",
			LastName:  "Tribiani",
			Email:     "joey@friends.org",
			Password:  "1",
		}

		service := idp.NewLoginService(idp.LoginServiceOpt{})
		_, err := service.RegisterUser(ctx, joeyForm)
		assert.Equal(t, idp.ErrPasswordInvalid, err)
	})

	t.Run("Cannot register a user that already exists", func(t *testing.T) {
		bob := idp.User{
			UID:            "xyz",
			FirstName:      "Bob",
			LastName:       "SAP",
			Email:          "bobsap@gmail.com",
			HashedPassword: []byte("top_secret"),
		}

		bobForm := idp.UserForm{
			FirstName: "Bob",
			LastName:  "Sap",
			Email:     "bobsap@gmail.com",
			Password:  "top_secret",
		}

		userRepository := inmem.NewUserRepository()
		userRepository.SaveUser(ctx, bob)
		sessionRepository := inmem.NewSessionRepository()

		service := idp.NewLoginService(idp.LoginServiceOpt{
			UserRepo:          userRepository,
			SessionRepo:       sessionRepository,
			HashPassword:      fakeHash,
			PasswordMatchHash: fakeMatchHash,
			NewRandID:         newDeterminedIDGenerator("abc"),
			Now:               fakeNow,
		})

		_, err := service.RegisterUser(ctx, bobForm)
		assert.Equal(t, idp.ErrUserAlreadyExists, err)
	})

	t.Run("A new user and its session should be saved upon registration", func(t *testing.T) {
		bobForm := idp.UserForm{
			FirstName: "Bob",
			LastName:  "Sap",
			Email:     "bobsap@ufc.org",
			Password:  "top_secret",
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

		wantUser := idp.User{
			UID:            generatedID,
			FirstName:      bobForm.FirstName,
			LastName:       strings.ToUpper(bobForm.LastName),
			Email:          strings.ToLower(bobForm.Email),
			HashedPassword: []byte(bobForm.Password),
		}

		wantBobSession := idp.Session{
			ID:         generatedID,
			Expiration: testTime.Add(24 * time.Hour * 30 * 3),
			User:       wantUser,
		}

		session, err := service.RegisterUser(ctx, bobForm)
		assert.NoError(t, err)
		assert.Equal(t, wantBobSession, session)

		session, err = sessionRepository.GetSessionByID(ctx, session.ID)
		assert.NoError(t, err)
		assert.Equal(t, wantBobSession, session)

		user, err := userRepository.GetUserByEmail(ctx, bobForm.Email)
		assert.NoError(t, err)
		assert.Equal(t, wantUser, user)
	})
}

func TestAuthenticateUser(t *testing.T) {
	ctx := context.Background()

	t.Run("Cannot authenticate user when password is insecure", func(t *testing.T) {
		service := idp.NewLoginService(idp.LoginServiceOpt{})

		_, err := service.SignIn(ctx, idp.Credential{
			Email:    "bob@sap.fr",
			Password: "123",
		})
		assert.Equal(t, idp.ErrPasswordInvalid, err)
	})

	t.Run("Cannot authenticate user when email is invalid", func(t *testing.T) {
		service := idp.NewLoginService(idp.LoginServiceOpt{})

		_, err := service.SignIn(ctx, idp.Credential{
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

		_, err := service.SignIn(ctx, idp.Credential{
			Email:    jon.Email,
			Password: "not_secret",
		})
		assert.Equal(t, idp.ErrEmailOrPasswordMismatch, err)
	})

	t.Run("An existing user and its session should be saved when credentials are valid", func(t *testing.T) {
		bob := idp.User{
			UID:            "qdojzdhcnn",
			FirstName:      "Bob",
			LastName:       "Sap",
			Email:          "bobsap@ufc.org",
			HashedPassword: []byte("top_secret"),
		}

		bobCredential := idp.Credential{
			Email:    bob.Email,
			Password: string(bob.HashedPassword),
		}

		userRepository := inmem.NewUserRepository()
		userRepository.SaveUser(ctx, bob)
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
			User:       bob,
		}

		session, err := service.SignIn(ctx, bobCredential)
		assert.NoError(t, err)
		assert.Equal(t, wantBobSession, session)

		session, err = sessionRepository.GetSessionByID(ctx, session.ID)
		assert.NoError(t, err)
		assert.Equal(t, wantBobSession, session)
	})

}

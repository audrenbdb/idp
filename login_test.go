package idp_test

import (
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"idp"
	"idp/mock"
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

func TestSendResetPassword(t *testing.T) {
	t.Run("Given email does not match any user should be unauthorized to reset password", func(t *testing.T) {
		userRepo := inmem.NewUserRepository()
		service := idp.NewLoginService(idp.LoginServiceOpt{
			UserRepo: userRepo,
		})
		err := service.ResetPassword(context.Background(), "jon@doe.com", "abc")
		assert.Equal(t, idp.ErrUserNotFound, err)
	})
	t.Run("Given sender fails to send reset token should return error", func(t *testing.T) {
		ctx := context.Background()

		jon := idp.User{
			UID:       "xyz",
			FirstName: "Jon",
			LastName:  "Doe",
			Email:     "jondoe@gmail.com",
		}

		newRandID := newDeterminedIDGenerator("abcd")

		userRepo := inmem.NewUserRepository()
		userRepo.SaveUser(ctx, jon)
		ctrl := gomock.NewController(t)
		mailer := mock.NewSender(ctrl)
		mailer.EXPECT().
			SendResetPasswordToken(ctx, jon.Email, "token=abcd").
			Return(errors.New("fail to send password link"))

		service := idp.NewLoginService(idp.LoginServiceOpt{
			NewRandID:         newRandID,
			UserRepo:          userRepo,
			PasswordResetRepo: inmem.NewPasswordResetRepository(),
			Sender:            mailer,
		})

		err := service.ResetPassword(ctx, jon.Email, "")
		assert.Equal(t, errors.New("fail to send password link"), err)
	})
	t.Run("Given email and query should create and send a reset token to the user", func(t *testing.T) {
		ctx := context.Background()

		jon := idp.User{
			UID:       "xyz",
			FirstName: "Jon",
			LastName:  "Doe",
			Email:     "jondoe@gmail.com",
		}

		fakeID := "abcd"
		newRandID := newDeterminedIDGenerator(fakeID)

		userRepo := inmem.NewUserRepository()
		userRepo.SaveUser(ctx, jon)
		pwResetRepo := inmem.NewPasswordResetRepository()

		ctrl := gomock.NewController(t)
		mailer := mock.NewSender(ctrl)
		mailer.EXPECT().
			SendResetPasswordToken(ctx, jon.Email, "token=abcd&foo=bar").
			Return(nil)

		service := idp.NewLoginService(idp.LoginServiceOpt{
			NewRandID:         newRandID,
			UserRepo:          userRepo,
			PasswordResetRepo: pwResetRepo,
			Sender:            mailer,
		})

		err := service.ResetPassword(ctx, jon.Email, "?foo=bar")
		assert.NoError(t, err)

		pwReset, err := pwResetRepo.GetPasswordReset(ctx, fakeID)
		assert.NoError(t, err)
		assert.Equal(t, idp.PasswordReset{
			Token:        fakeID,
			User:         jon,
			InitialQuery: "?foo=bar",
		}, pwReset)
	})
}

func TestUpdatePassword(t *testing.T) {
	ctx := context.Background()
	t.Run("Given password is too small should return an error", func(t *testing.T) {
		service := idp.NewLoginService(idp.LoginServiceOpt{})
		err := service.UpdatePasswordFromResetToken(ctx, "", "abc")
		assert.Equal(t, idp.ErrPasswordInvalid, err)
	})

	t.Run("Given token does not match any password reset should return not found", func(t *testing.T) {
		repo := inmem.NewPasswordResetRepository()
		service := idp.NewLoginService(idp.LoginServiceOpt{
			PasswordResetRepo: repo,
		})
		err := service.UpdatePasswordFromResetToken(ctx, "qoziduqzd", "qzdqzd")
		assert.Equal(t, idp.ErrPasswordResetNotFound, err)
	})
	t.Run("Given token is valid new password should be set and token depleted", func(t *testing.T) {
		bob := idp.User{
			UID:            "xyz",
			FirstName:      "Bob",
			LastName:       "SAP",
			Email:          "bobsap@ufc.org",
			HashedPassword: []byte("top_secret"),
		}

		reset := idp.PasswordReset{
			Token:        "abc",
			User:         bob,
			InitialQuery: "?foo=boar",
		}

		userRepo := inmem.NewUserRepository()
		userRepo.SaveUser(ctx, bob)

		pwResetRepo := inmem.NewPasswordResetRepository()
		pwResetRepo.SavePasswordReset(ctx, reset)

		service := idp.NewLoginService(idp.LoginServiceOpt{
			UserRepo:          userRepo,
			PasswordResetRepo: pwResetRepo,
			HashPassword:      fakeHash,
		})

		err := service.UpdatePasswordFromResetToken(ctx, reset.Token, "top_secret_ultra")
		assert.NoError(t, err)

		user, err := userRepo.GetUserByEmail(ctx, bob.Email)
		assert.NoError(t, err)
		assert.Equal(t, []byte("top_secret_ultra"), user.HashedPassword)

		_, err = pwResetRepo.GetPasswordReset(ctx, reset.Token)
		assert.Equal(t, idp.ErrPasswordResetNotFound, err)
	})
}

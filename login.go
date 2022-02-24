package idp

import (
	"context"
	"fmt"
	"idp/password"
	"idp/rand"
	"strings"
	"time"
)

//go:generate mockgen -source $GOFILE -destination mock/$GOFILE -package mock -mock_names Sender=Sender

type UserRepository interface {
	SaveUser(ctx context.Context, user User) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
}

type SessionRepository interface {
	SaveSession(ctx context.Context, session Session) (Session, error)
	GetSessionByID(ctx context.Context, id string) (Session, error)
}

type PasswordResetRepository interface {
	SavePasswordReset(ctx context.Context, reset PasswordReset) (PasswordReset, error)
	GetPasswordReset(ctx context.Context, id string) (PasswordReset, error)
	DeletePasswordReset(ctx context.Context, id string) error
}

type Sender interface {
	SendResetPasswordToken(ctx context.Context, email, link string) error
}

type loginService struct {
	userRepo    UserRepository
	sessionRepo SessionRepository
	pwResetRepo PasswordResetRepository
	sender      Sender

	hashPassword      func(pw string) ([]byte, error)
	passwordMatchHash func(pw string, hash []byte) bool
	newRandID         func() string
	now               func() time.Time
}

type LoginServiceOpt struct {
	UserRepo          UserRepository
	SessionRepo       SessionRepository
	PasswordResetRepo PasswordResetRepository
	Sender            Sender

	HashPassword      func(pw string) ([]byte, error)
	PasswordMatchHash func(pw string, hash []byte) bool
	NewRandID         func() string
	Now               func() time.Time
}

func NewLoginService(opt LoginServiceOpt) *loginService {
	if opt.HashPassword == nil {
		opt.HashPassword = password.Hash
	}
	if opt.PasswordMatchHash == nil {
		opt.PasswordMatchHash = password.MatchHash
	}
	if opt.NewRandID == nil {
		opt.NewRandID = rand.IDGenerator(40)
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &loginService{
		userRepo:    opt.UserRepo,
		sessionRepo: opt.SessionRepo,
		pwResetRepo: opt.PasswordResetRepo,

		sender: opt.Sender,

		hashPassword:      opt.HashPassword,
		passwordMatchHash: opt.PasswordMatchHash,
		newRandID:         opt.NewRandID,
		now:               opt.Now,
	}
}

func (s *loginService) ResetPassword(ctx context.Context, email, initialQuery string) error {
	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return err
	}
	pwReset, err := s.pwResetRepo.SavePasswordReset(ctx, PasswordReset{
		Token:        s.newRandID(),
		User:         user,
		InitialQuery: initialQuery,
	})
	if err != nil {
		return err
	}
	link := fmt.Sprintf("token=%s", pwReset.Token)
	if pwReset.InitialQuery != "" {
		link += "&" + strings.TrimPrefix(initialQuery, "?")
	}
	return s.sender.SendResetPasswordToken(ctx, user.Email, link)
}

func (s *loginService) UpdatePasswordFromResetToken(ctx context.Context, token, password string) error {
	if len(password) < 6 {
		return ErrPasswordInvalid
	}
	pwReset, err := s.pwResetRepo.GetPasswordReset(ctx, token)
	if err != nil {
		return err
	}
	user := pwReset.User
	err = s.pwResetRepo.DeletePasswordReset(ctx, pwReset.Token)
	if err != nil {
		return err
	}
	user.HashedPassword, err = s.hashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.userRepo.SaveUser(ctx, user)
	return err
}

func (s *loginService) SignIn(ctx context.Context, cred Credential) (Session, error) {
	if err := cred.EnsureValid(); err != nil {
		return Session{}, err
	}
	user, err := s.userRepo.GetUserByEmail(ctx, cred.Email)
	if err != nil {
		return Session{}, err
	}
	return s.authenticateExistingUser(ctx, cred, user)
}

func (s *loginService) RegisterUser(ctx context.Context, form UserForm) (Session, error) {
	if err := form.EnsureValid(); err != nil {
		return Session{}, err
	}
	_, err := s.userRepo.GetUserByEmail(ctx, form.Email)
	if err == nil {
		return Session{}, ErrUserAlreadyExists
	}
	return s.authenticateNewUser(ctx, form)
}

func (s *loginService) authenticateNewUser(ctx context.Context, form UserForm) (Session, error) {
	pw, err := s.hashPassword(form.Password)
	if err != nil {
		return Session{}, err
	}
	user := User{
		UID:            s.newRandID(),
		FirstName:      form.FirstName,
		LastName:       strings.ToUpper(form.LastName),
		Email:          strings.ToLower(form.Email),
		HashedPassword: pw,
	}
	user, err = s.userRepo.SaveUser(ctx, user)
	if err != nil {
		return Session{}, err
	}
	return s.newSession(ctx, user)
}

func (s *loginService) authenticateExistingUser(ctx context.Context, cred Credential, user User) (Session, error) {
	if !s.passwordMatchHash(cred.Password, user.HashedPassword) {
		return Session{}, ErrEmailOrPasswordMismatch
	}
	return s.newSession(ctx, user)
}

func (s *loginService) newSession(ctx context.Context, user User) (Session, error) {
	return s.sessionRepo.SaveSession(ctx, Session{
		ID:         s.newRandID(),
		User:       user,
		Expiration: s.now().Add(24 * time.Hour * 30 * 3), // 3 months ~,
	})
}

package idp

import (
	"context"
	"errors"
	"idp/password"
	"idp/rand"
	"time"
)

type UserRepository interface {
	SaveUser(ctx context.Context, user User) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
}

type SessionRepository interface {
	SaveSession(ctx context.Context, session Session) (Session, error)
	GetSessionByID(ctx context.Context, id string) (Session, error)
}

type loginService struct {
	userRepo    UserRepository
	sessionRepo SessionRepository

	hashPassword      func(pw string) ([]byte, error)
	passwordMatchHash func(pw string, hash []byte) bool
	newRandID         func() string
	now               func() time.Time
}

type LoginServiceOpt struct {
	UserRepo    UserRepository
	SessionRepo SessionRepository

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
		userRepo:          opt.UserRepo,
		sessionRepo:       opt.SessionRepo,
		hashPassword:      opt.HashPassword,
		passwordMatchHash: opt.PasswordMatchHash,
		newRandID:         opt.NewRandID,
		now:               opt.Now,
	}
}

func (s *loginService) AuthenticateUser(ctx context.Context, cred Credential) (Session, error) {
	if err := cred.EnsureValid(); err != nil {
		return Session{}, err
	}
	user, err := s.userRepo.GetUserByEmail(ctx, cred.Email)
	switch {
	case errors.Is(err, ErrUserNotFound):
		return s.authenticateNewUser(ctx, cred)
	case !errors.Is(err, nil):
		return Session{}, err
	default:
		return s.authenticateExistingUser(ctx, cred, user)
	}
}

func (s *loginService) authenticateNewUser(ctx context.Context, cred Credential) (Session, error) {
	pw, err := s.hashPassword(cred.Password)
	if err != nil {
		return Session{}, err
	}
	user := User{
		UID:            s.newRandID(),
		Email:          cred.Email,
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

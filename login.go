package idp

import (
	"context"
	"idp/password"
	"idp/rand"
	"strings"
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
		opt.NewRandID = rand.IDGenerator(70)
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

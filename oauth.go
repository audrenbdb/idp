package idp

import (
	"context"
	"idp/rand"
	"time"
)

type ClientRepository interface {
	SaveClient(ctx context.Context, client Client) (Client, error)
	GetClientByID(ctx context.Context, id string) (Client, error)
}

type AuthorizationRepository interface {
	SaveAuthorization(ctx context.Context, authorization Authorization) (Authorization, error)
	GetAuthorizationByCode(ctx context.Context, code string) (Authorization, error)
	DeleteAuthorization(ctx context.Context, code string) error
}

type AccessRepository interface {
	SaveAccess(ctx context.Context, access Access) (Access, error)
	GetAccessByID(ctx context.Context, id string) (Access, error)
	GetAccessByRefreshTokenID(ctx context.Context, refreshID string) (Access, error)
	DeleteAccess(ctx context.Context, id string) error
}

type oauthService struct {
	accessRepo        AccessRepository
	clientRepo        ClientRepository
	sessionRepo       SessionRepository
	authorizationRepo AuthorizationRepository
	newRandID         func() string
	now               func() time.Time
}

type OAuthServiceOpt struct {
	AccessRepo        AccessRepository
	ClientRepo        ClientRepository
	SessionRepo       SessionRepository
	AuthorizationRepo AuthorizationRepository
	NewRandID         func() string
	Now               func() time.Time
}

func NewOAuthService(opt OAuthServiceOpt) *oauthService {
	if opt.NewRandID == nil {
		opt.NewRandID = rand.IDGenerator(70)
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &oauthService{
		accessRepo:        opt.AccessRepo,
		clientRepo:        opt.ClientRepo,
		sessionRepo:       opt.SessionRepo,
		authorizationRepo: opt.AuthorizationRepo,
		newRandID:         opt.NewRandID,
		now:               opt.Now,
	}
}

func (s *oauthService) NewClient(ctx context.Context, appName string, appRedirectURIs []string) (Client, error) {
	client := Client{
		ID:                  s.newRandID(),
		Secret:              s.newRandID(),
		Name:                appName,
		AuthorizedRedirects: appRedirectURIs,
		CreatedAt:           s.now(),
	}
	return s.clientRepo.SaveClient(ctx, client)
}

func (s *oauthService) AccessUser(ctx context.Context, accessID string) (User, error) {
	access, err := s.accessRepo.GetAccessByID(ctx, accessID)
	if err != nil {
		return User{}, err
	}
	if s.isAccessExpired(access) {
		return User{}, ErrAccessExpired
	}
	// explicit new structure over access.User
	// to avoid passing hashed password
	return User{
		UID:       access.User.UID,
		FirstName: access.User.FirstName,
		LastName:  access.User.LastName,
		Email:     access.User.Email,
	}, nil
}

func (s *oauthService) isAccessExpired(access Access) bool {
	return access.Expiration.Before(s.now())
}

func (s *oauthService) isRefreshTokenExpired(refreshToken RefreshToken) bool {
	return refreshToken.Expiration.Before(s.now())
}

func (s *oauthService) RefreshToken(ctx context.Context, form RefreshTokenForm) (Token, error) {
	access, err := s.accessRepo.GetAccessByRefreshTokenID(ctx, form.GetRefreshTokenID())
	if err != nil {
		return Token{}, ErrInvalidRefreshToken
	}
	if s.isRefreshTokenExpired(access.RefreshToken) {
		return Token{}, ErrInvalidRefreshToken
	}
	err = s.accessRepo.DeleteAccess(ctx, access.ID)
	if err != nil {
		return Token{}, err
	}
	return s.newUserToken(ctx, access.User)
}

func (s *oauthService) NewToken(ctx context.Context, form AccessTokenForm) (Token, error) {
	authorization, err := s.getAuthorization(ctx, form)
	if err != nil {
		return Token{}, err
	}
	err = s.authorizationRepo.DeleteAuthorization(ctx, form.GetCode())
	if err != nil {
		return Token{}, err
	}
	return s.newUserToken(ctx, authorization.User)
}

func (s *oauthService) newUserToken(ctx context.Context, user User) (Token, error) {
	access, err := s.accessRepo.SaveAccess(ctx, Access{
		ID: s.newRandID(),
		RefreshToken: RefreshToken{
			ID:         s.newRandID(),
			Expiration: s.now().Add(24 * time.Hour * 360), // a year ~
		},
		User:       user,
		Expiration: s.now().Add(time.Hour),
	})
	if err != nil {
		return Token{}, err
	}
	return s.tokenFromAccess(access), nil
}

func (s *oauthService) tokenFromAccess(access Access) Token {
	return Token{
		Access:  access.ID,
		Refresh: access.RefreshToken.ID,
		Expires: int(access.Expiration.Sub(s.now()).Seconds()),
	}
}

func (s *oauthService) getAuthorization(ctx context.Context, form AccessTokenForm) (Authorization, error) {
	authorization, err := s.authorizationRepo.GetAuthorizationByCode(ctx, form.GetCode())
	if err != nil {
		return authorization, err
	}
	if authorization.RedirectURI != form.GetRedirectURI() {
		return authorization, ErrMismatchingRedirectURI
	}
	authorization.Client, err = s.clientRepo.GetClientByID(ctx, form.GetClientID())
	if err != nil {
		return authorization, err
	}
	if authorization.Client.ID != form.GetClientID() {
		return authorization, ErrClientUnauthorized
	}
	if authorization.Expiration.Before(s.now()) {
		return authorization, ErrAuthorizationExpired
	}
	return authorization, nil
}

func (s *oauthService) NewAuthCode(ctx context.Context, sessionID string, form AuthorizationForm) (string, error) {
	session, err := s.sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return "", err
	}
	if s.isSessionExpired(session) {
		return "", ErrSessionExpired
	}
	client, err := s.clientRepo.GetClientByID(ctx, form.ClientID)
	if err != nil {
		return "", err
	}
	authorization, err := s.authorizationRepo.SaveAuthorization(ctx, Authorization{
		Code:        s.newRandID(),
		User:        session.User,
		Client:      client,
		RedirectURI: form.RedirectURI,
		Expiration:  s.now().Add(10 * time.Minute),
	})
	return authorization.Code, err
}

func (s *oauthService) isSessionExpired(session Session) bool {
	return session.Expiration.Before(s.now())
}

func (s *oauthService) AuthorizeClient(ctx context.Context, form AuthorizationForm) error {
	client, err := s.clientRepo.GetClientByID(ctx, form.ClientID)
	if err != nil {
		return err
	}
	if isNotInArray(client.AuthorizedRedirects, form.RedirectURI) {
		return ErrMismatchingRedirectURI
	}
	return nil
}

func isNotInArray(arr []string, item string) bool {
	return !isInArray(arr, item)
}

func isInArray(arr []string, item string) bool {
	switch {
	case len(arr) == 0:
		return false
	case arr[0] == item:
		return true
	default:
		return isInArray(arr[1:], item)
	}
}

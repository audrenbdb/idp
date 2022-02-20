package idp_test

import (
	"context"
	"github.com/stretchr/testify/assert"
	"idp"
	"idp/repo/inmem"
	"testing"
	"time"
)

func newDeterminedIDGenerator(out string) func() string {
	return func() string {
		return out
	}
}

// fakeNow returns a fixed testTime
func fakeNow() time.Time {
	return testTime
}

var testTime = time.Date(2000, 1, 1, 1, 1, 1, 1, time.UTC)

func TestNewClient(t *testing.T) {
	ctx := context.Background()

	t.Run("Returns a new client from given app name and redirect URIS", func(t *testing.T) {
		clientRepository := inmem.NewClientRepository()
		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			ClientRepo: clientRepository,
			Now:        fakeNow,
			NewRandID:  newDeterminedIDGenerator("abc"),
		})

		appName := "Super Bowl"
		appRedirectURIs := []string{"https://super.bowl/redirect"}

		wantClient := idp.Client{
			ID:                  "abc",
			Secret:              "abc",
			Name:                appName,
			AuthorizedRedirects: appRedirectURIs,
			CreatedAt:           testTime,
		}

		client, err := service.NewClient(ctx, appName, appRedirectURIs)
		assert.NoError(t, err)
		assert.Equal(t, wantClient, client)

		client, err = clientRepository.GetClientByID(ctx, "abc")
		assert.NoError(t, err)
		assert.Equal(t, wantClient, client)
	})
}

func TestAccessUser(t *testing.T) {
	ctx := context.Background()

	t.Run("An access that does not exist cannot be used to get user identity", func(t *testing.T) {
		accessID := "xyz"

		accessRepository := inmem.NewAccessRepository()
		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			AccessRepo: accessRepository,
		})
		_, err := service.AccessUser(ctx, accessID)
		assert.Equal(t, idp.ErrAccessNotFound, err)
	})

	t.Run("An expired access cannot be used to get user identity", func(t *testing.T) {
		jonAccess := idp.Access{
			ID: "abc",
			User: idp.User{
				UID:   "xyz",
				Email: "jean@deau.fr",
			},
			Expiration: fakeNow().Add(-10 * time.Minute),
		}

		accessRepository := inmem.NewAccessRepository()
		accessRepository.SaveAccess(ctx, jonAccess)
		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			AccessRepo: accessRepository,
			Now:        fakeNow,
		})

		_, err := service.AccessUser(ctx, jonAccess.ID)
		assert.Equal(t, idp.ErrAccessExpired, err)
	})

	t.Run("User is returned freely with acces id", func(t *testing.T) {
		bobAccess := idp.Access{
			ID: "fgh",
			User: idp.User{
				UID:   "xyz",
				Email: "bobsap@gmail.com",
			},
			Expiration: fakeNow().Add(10 * time.Minute),
		}

		accessRepository := inmem.NewAccessRepository()
		accessRepository.SaveAccess(ctx, bobAccess)
		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			AccessRepo: accessRepository,
			Now:        fakeNow,
		})

		identity, err := service.AccessUser(ctx, bobAccess.ID)
		assert.NoError(t, err)
		assert.Equal(t, bobAccess.User, identity)
	})
}

func TestNewToken(t *testing.T) {
	ctx := context.Background()

	jon := idp.User{UID: "abc", Email: "jean@deau.fr"}

	avengers := idp.Client{
		ID:                  "qzoiudqd",
		Secret:              "qoizudoqiuzdndn",
		Name:                "Avengers",
		AuthorizedRedirects: []string{"http://marvel/redirect"},
		CreatedAt:           fakeNow(),
	}

	clientRepo := inmem.NewClientRepository()
	clientRepo.SaveClient(ctx, avengers)

	t.Run("A token cannot be generated if URI provided mismatch the one used for auth code", func(t *testing.T) {
		jonAccessTokenForm := idp.AccessTokenForm{
			Code:        "xwy",
			RedirectURI: "http://re.di.rect",
			ClientID:    avengers.ID,
		}

		authorizationRepo := inmem.NewAuthorizationRepository()
		authorizationRepo.SaveAuthorization(ctx, idp.Authorization{
			Code:        jonAccessTokenForm.Code,
			User:        jon,
			RedirectURI: "http://malicious.redirect",
			Client:      avengers,
			Expiration:  time.Now().Add(10 * time.Minute),
		})

		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			AuthorizationRepo: authorizationRepo,
			ClientRepo:        clientRepo,
		})

		_, err := service.NewToken(ctx, jonAccessTokenForm)
		assert.Equal(t, idp.ErrMismatchingRedirectURI, err)
	})

	t.Run("A token cannot be generated if no authorization is found with given form", func(t *testing.T) {
		jonAccessTokenForm := idp.AccessTokenForm{
			Code:        "xwy",
			RedirectURI: "http://re.di.rect",
			ClientID:    avengers.ID,
		}

		authorizationRepo := inmem.NewAuthorizationRepository()
		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			AuthorizationRepo: authorizationRepo,
			ClientRepo:        clientRepo,
		})

		_, err := service.NewToken(ctx, jonAccessTokenForm)
		assert.Equal(t, idp.ErrAuthorizationNotFound, err)
	})

	t.Run("A token cannot be generated if client is not found", func(t *testing.T) {
		jonAccessTokenForm := idp.AccessTokenForm{
			Code:        "xwy",
			RedirectURI: avengers.AuthorizedRedirects[0],
			ClientID:    "malicious_client",
		}

		authorizationRepo := inmem.NewAuthorizationRepository()
		authorizationRepo.SaveAuthorization(ctx, idp.Authorization{
			User:        jon,
			Code:        jonAccessTokenForm.Code,
			RedirectURI: jonAccessTokenForm.RedirectURI,
			Client:      avengers,
			Expiration:  time.Now().Add(10 * time.Minute),
		})

		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			AuthorizationRepo: authorizationRepo,
			ClientRepo:        clientRepo,
		})

		_, err := service.NewToken(ctx, jonAccessTokenForm)
		assert.Equal(t, idp.ErrClientNotFound, err)
	})

	t.Run("A token cannot be generated if authorization expired", func(t *testing.T) {
		jonAccessTokenForm := idp.AccessTokenForm{
			Code:        "xwy",
			RedirectURI: avengers.AuthorizedRedirects[0],
			ClientID:    avengers.ID,
		}

		authorizationRepo := inmem.NewAuthorizationRepository()
		authorizationRepo.SaveAuthorization(ctx, idp.Authorization{
			User:        jon,
			Code:        jonAccessTokenForm.Code,
			RedirectURI: jonAccessTokenForm.RedirectURI,
			Client:      avengers,
			Expiration:  time.Now().Add(-10 * time.Minute),
		})

		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			AuthorizationRepo: authorizationRepo,
			ClientRepo:        clientRepo,
		})

		_, err := service.NewToken(ctx, jonAccessTokenForm)
		assert.Equal(t, idp.ErrAuthorizationExpired, err)
	})

	t.Run("Created token should also delete authorizations to avoid further use", func(t *testing.T) {
		jonAccessTokenForm := idp.AccessTokenForm{
			Code:        "xwy",
			RedirectURI: avengers.AuthorizedRedirects[0],
			ClientID:    avengers.ID,
		}

		authorizationRepo := inmem.NewAuthorizationRepository()
		authorizationRepo.SaveAuthorization(ctx, idp.Authorization{
			User:        jon,
			Code:        jonAccessTokenForm.Code,
			RedirectURI: jonAccessTokenForm.RedirectURI,
			Client:      avengers,
			Expiration:  fakeNow().Add(10 * time.Minute),
		})
		accessRepo := inmem.NewAccessRepository()

		accessID := "qouziydqbn"
		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			AuthorizationRepo: authorizationRepo,
			ClientRepo:        clientRepo,
			AccessRepo:        accessRepo,
			Now:               fakeNow,
			NewRandID:         newDeterminedIDGenerator(accessID),
		})

		token, err := service.NewToken(ctx, jonAccessTokenForm)
		assert.NoError(t, err)
		assert.Equal(t, idp.Token{Access: accessID}, token)

		access, err := accessRepo.GetAccessByID(ctx, token.Access)
		assert.NoError(t, err)
		assert.Equal(t, idp.Access{
			ID:         accessID,
			User:       jon,
			Expiration: fakeNow().Add(180 * time.Hour * 24),
		}, access)

		_, err = authorizationRepo.GetAuthorizationByCode(ctx, jonAccessTokenForm.Code)
		assert.Equal(t, idp.ErrAuthorizationNotFound, err)
	})
}

func TestNewAuthCode(t *testing.T) {
	ctx := context.Background()

	jon := idp.User{
		UID:   "abc",
		Email: "jean_deau@gmail.com",
	}

	avengers := idp.Client{
		ID:                  "qzoiudqd",
		Secret:              "qoizudoqiuzdndn",
		Name:                "Avengers",
		AuthorizedRedirects: []string{"http://marvel/redirect"},
		CreatedAt:           fakeNow(),
	}

	clientRepo := inmem.NewClientRepository()
	clientRepo.SaveClient(ctx, avengers)

	t.Run("An authorization code cannot be delivered when a session is expired", func(t *testing.T) {
		jonSession := idp.Session{
			ID:         "xyz",
			User:       jon,
			Expiration: time.Now().Add(-10 * time.Hour),
		}
		jonAuthForm := idp.AuthorizationForm{ClientID: "ufc"}

		repo := inmem.NewSessionRepository()
		repo.SaveSession(ctx, jonSession)

		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			SessionRepo: repo,
		})

		_, err := service.NewAuthCode(ctx, jonSession.ID, jonAuthForm)
		assert.Equal(t, idp.ErrSessionExpired, err)
	})
	t.Run("An authorization code cannot be delivered when a session is not foudn", func(t *testing.T) {
		jonSession := idp.Session{
			ID:   "xyz",
			User: jon,
		}
		jonAuthForm := idp.AuthorizationForm{ClientID: "ufc"}

		repo := inmem.NewSessionRepository()
		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			SessionRepo: repo,
		})

		_, err := service.NewAuthCode(ctx, jonSession.ID, jonAuthForm)
		assert.Equal(t, idp.ErrSessionNotFound, err)
	})
	t.Run("An new code should be generated, and its code request saved", func(t *testing.T) {
		wantCode := "paoiuzdaou"
		jonSession := idp.Session{
			ID:         "abc",
			User:       jon,
			Expiration: time.Now().Add(10 * time.Hour),
		}
		jonAuthForm := idp.AuthorizationForm{ClientID: avengers.ID}

		sessionRepository := inmem.NewSessionRepository()
		sessionRepository.SaveSession(ctx, jonSession)
		authorizationRepository := inmem.NewAuthorizationRepository()

		service := idp.NewOAuthService(idp.OAuthServiceOpt{
			AuthorizationRepo: authorizationRepository,
			ClientRepo:        clientRepo,
			SessionRepo:       sessionRepository,
			NewRandID:         newDeterminedIDGenerator(wantCode),
			Now:               fakeNow,
		})

		code, err := service.NewAuthCode(ctx, jonSession.ID, jonAuthForm)
		assert.NoError(t, err)

		authorization, err := authorizationRepository.GetAuthorizationByCode(ctx, code)
		assert.NoError(t, err)
		assert.Equal(t, idp.Authorization{
			Code:        wantCode,
			User:        jon,
			RedirectURI: jonAuthForm.RedirectURI,
			Client:      avengers,
			Expiration:  fakeNow().Add(10 * time.Minute),
		}, authorization)
	})
}

func TestAuthorizeClient(t *testing.T) {
	t.Run("A client that is not found cannot be authorized", func(t *testing.T) {
		repo := inmem.NewClientRepository()
		s := idp.NewOAuthService(idp.OAuthServiceOpt{
			ClientRepo: repo,
		})
		err := s.AuthorizeClient(context.Background(), idp.AuthorizationForm{
			ClientID: "unknown",
		})
		assert.Equal(t, idp.ErrClientNotFound, err)
	})

	t.Run("A redirection URI that is not registered cannot be used to authorize a a client", func(t *testing.T) {
		client := idp.Client{
			ID:                  "xyz",
			AuthorizedRedirects: []string{"http://redirect"},
		}
		repo := inmem.NewClientRepository()
		repo.SaveClient(context.Background(), client)
		s := idp.NewOAuthService(idp.OAuthServiceOpt{
			ClientRepo: repo,
		})
		err := s.AuthorizeClient(context.Background(), idp.AuthorizationForm{
			ClientID:    client.ID,
			RedirectURI: "http://malicious.redirect",
		})
		assert.Equal(t, idp.ErrMismatchingRedirectURI, err)
	})

	t.Run("A client providing arguments matching client found should be authorized", func(t *testing.T) {
		client := idp.Client{
			ID:                  "xyz",
			AuthorizedRedirects: []string{"http://redirect"},
		}
		repo := inmem.NewClientRepository()
		repo.SaveClient(context.Background(), client)
		s := idp.NewOAuthService(idp.OAuthServiceOpt{
			ClientRepo: repo,
		})
		err := s.AuthorizeClient(context.Background(), idp.AuthorizationForm{
			ClientID:    client.ID,
			RedirectURI: client.AuthorizedRedirects[0],
		})
		assert.NoError(t, err)
	})

}

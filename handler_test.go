package idp_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"idp"
	"idp/mock"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPostClient(t *testing.T) {
	t.Run("Given request without application name should return bad request", func(t *testing.T) {
		form := url.Values{}
		form.Set("redirect_uris", "http://redirect")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))

		idp.HandlePostClient(nil)(w, r)
		result := w.Result()
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request without redirect uris should return bad request", func(t *testing.T) {
		form := url.Values{}
		form.Set("name", "Super Bowl")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandlePostClient(nil)(w, r)
		result := w.Result()
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request should return client created", func(t *testing.T) {
		appName := "Super Bowl"
		appRedirectURIs := []string{"http://superbowl/oauth2/redirect"}
		form := url.Values{}
		form.Set("name", appName)
		form.Set("redirect_uris", strings.Join(appRedirectURIs, ","))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		wantClient := idp.Client{
			ID:                  "abc",
			Secret:              "def",
			Name:                appName,
			AuthorizedRedirects: appRedirectURIs,
		}

		ctrl := gomock.NewController(t)
		clientMaker := mock.NewClientMaker(ctrl)
		clientMaker.EXPECT().
			NewClient(r.Context(), appName, appRedirectURIs).
			Return(wantClient, nil)

		idp.HandlePostClient(clientMaker)(w, r)
		result := w.Result()
		b, err := io.ReadAll(result.Body)
		assert.NoError(t, err)

		var client idp.Client
		err = json.Unmarshal(b, &client)
		assert.NoError(t, err)
		assert.Equal(t, wantClient, client)
	})
}

func TestHandleGetUserIdentity(t *testing.T) {
	t.Run("Given request without bearer token in header should return unauthorized", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		idp.HandleGetUser(nil)(w, r)
		result := w.Result()
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
	})

	t.Run("Given request with an expired access token should return unauthorized", func(t *testing.T) {
		w := httptest.NewRecorder()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("authorization", "Bearer xyz")

		ctrl := gomock.NewController(t)
		identityGetter := mock.NewUserAccesser(ctrl)
		identityGetter.EXPECT().
			AccessUser(r.Context(), "xyz").
			Return(idp.User{}, errors.New("failure"))

		idp.HandleGetUser(identityGetter)(w, r)

		result := w.Result()
		b, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
		assert.Contains(t, string(b), "failure")
	})

	t.Run("Given request with an expired access token should return unauthorized", func(t *testing.T) {
		w := httptest.NewRecorder()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("authorization", "Bearer xyz")

		ctrl := gomock.NewController(t)
		identityGetter := mock.NewUserAccesser(ctrl)
		identityGetter.EXPECT().
			AccessUser(r.Context(), "xyz").
			Return(idp.User{}, errors.New("failure"))

		idp.HandleGetUser(identityGetter)(w, r)

		result := w.Result()
		b, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
		assert.Contains(t, string(b), "failure")
	})

	t.Run("Given request should return user identity", func(t *testing.T) {
		w := httptest.NewRecorder()

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("authorization", "Bearer xyz")

		ctrl := gomock.NewController(t)
		jon := idp.User{
			Email: "jean@deau.fr",
			UID:   "xyz",
		}
		identityGetter := mock.NewUserAccesser(ctrl)
		identityGetter.EXPECT().
			AccessUser(r.Context(), "xyz").
			Return(jon, nil)

		idp.HandleGetUser(identityGetter)(w, r)

		result := w.Result()
		b, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(b), `{"uid":"xyz","email":"jean@deau.fr"}`)
	})
}

func TestHandleGetToken_WithoutGrant(t *testing.T) {
	t.Run("Given request is missing an accepted grant_type (authorizatioon_code or refresh_token) should return bad request", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("code", "abc")
		formValues.Set("redirect_uri", "http://re.di.rect")
		formValues.Set("client_id", "xyz")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleGetToken(nil)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMissingGrantType.Error())
	})
}

func TestHandleGetToken_WithRefreshToken(t *testing.T) {
	t.Run("Given request is missing client_id should return bad request", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("grant_type", "refresh_token")
		formValues.Set("client_id", "")
		formValues.Set("client_secret", "xyz")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleGetToken(nil)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMissingClientID.Error())
	})

	t.Run("Given request is missing client_secret should return bad request", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("grant_type", "refresh_token")
		formValues.Set("client_id", "abc")
		formValues.Set("client_secret", "")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleGetToken(nil)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMissingClientSecret.Error())
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request is missing refresh_token should return bad request", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("grant_type", "refresh_token")
		formValues.Set("client_id", "abc")
		formValues.Set("client_secret", "xyz")
		formValues.Set("refresh_token", "")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleGetToken(nil)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMissingRefreshToken.Error())
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request is unauthorized to refresh token should return unauthorized", func(t *testing.T) {
		form := idp.TokenForm{
			Grant:        idp.Refresh,
			ClientID:     "abc",
			ClientSecret: "xyz",
			RefreshToken: "qdpoziudoqizd",
		}

		formValues := url.Values{}
		formValues.Set("grant_type", "refresh_token")
		formValues.Set("client_id", form.ClientID)
		formValues.Set("client_secret", form.ClientSecret)
		formValues.Set("refresh_token", form.RefreshToken)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		tokenGetter := mock.NewTokenGetter(ctrl)
		tokenGetter.EXPECT().
			RefreshToken(r.Context(), form).
			Return(idp.Token{}, idp.ErrUnauthorized{Err: "nop"})

		idp.HandleGetToken(tokenGetter)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrUnauthorized{Err: "nop"}.Error())
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
	})

	t.Run("Given request is authorized, a new token is encoded to json body", func(t *testing.T) {
		form := idp.TokenForm{
			Grant:        idp.Refresh,
			ClientID:     "abc",
			ClientSecret: "xyz",
			RefreshToken: "qdpoziudoqizd",
		}

		formValues := url.Values{}
		formValues.Set("grant_type", "refresh_token")
		formValues.Set("client_id", form.ClientID)
		formValues.Set("client_secret", form.ClientSecret)
		formValues.Set("refresh_token", form.RefreshToken)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		tokenGetter := mock.NewTokenGetter(ctrl)
		tokenGetter.EXPECT().
			RefreshToken(r.Context(), form).
			Return(idp.Token{Access: "123", Refresh: "456", Expires: 123}, nil)

		idp.HandleGetToken(tokenGetter)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), `{"access_token":"123","refresh_token":"456","expires":123}`)
		assert.Equal(t, http.StatusOK, result.StatusCode)
	})
}

func TestHandleGetToken_WithAuthCode(t *testing.T) {
	t.Run("Given request is missing Code should return bad request", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("grant_type", "authorization_code")
		formValues.Set("redirect_uri", "http://re.di.rect")
		formValues.Set("client_id", "xyz")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleGetToken(nil)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMissingAuthCode.Error())
	})

	t.Run("Given request is missing redirect uri should return status unauthorized", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("code", "abc")
		formValues.Set("grant_type", "authorization_code")
		formValues.Set("client_id", "xyz")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleGetToken(nil)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMissingRedirectURI.Error())
	})

	t.Run("Given request is missing client_id should return bad request", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("code", "abc")
		formValues.Set("grant_type", "authorization_code")
		formValues.Set("redirect_uri", "http://re.di.rect")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleGetToken(nil)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMissingClientID.Error())
	})

	t.Run("Given request fails with mismatching URI should return error mismatching_uri", func(t *testing.T) {
		form := idp.TokenForm{
			Grant:       idp.Code,
			ClientID:    "xyz",
			RedirectURI: "http://re.di.rect",
			Code:        "abc",
		}

		formValues := url.Values{}
		formValues.Set("code", form.Code)
		formValues.Set("grant_type", string(form.Grant))
		formValues.Set("redirect_uri", form.RedirectURI)
		formValues.Set("client_id", form.ClientID)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		tokenGetter := mock.NewTokenGetter(ctrl)
		tokenGetter.EXPECT().
			NewToken(r.Context(), form).
			Return(idp.Token{}, idp.ErrMismatchingRedirectURI)

		idp.HandleGetToken(tokenGetter)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMismatchingRedirectURI.Error())
	})

	t.Run("Given request fails internally should return internal server error", func(t *testing.T) {
		form := idp.TokenForm{
			Grant:       idp.Code,
			Code:        "abc",
			RedirectURI: "http://re.di.rect",
			ClientID:    "xyz",
		}

		formValues := url.Values{}
		formValues.Set("code", form.Code)
		formValues.Set("grant_type", string(form.Grant))
		formValues.Set("redirect_uri", form.RedirectURI)
		formValues.Set("client_id", form.ClientID)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		tokenGetter := mock.NewTokenGetter(ctrl)
		tokenGetter.EXPECT().
			NewToken(r.Context(), form).
			Return(idp.Token{}, errors.New("internal server error"))

		idp.HandleGetToken(tokenGetter)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), "internal server error")
	})

	t.Run("Given request should return user access token freely", func(t *testing.T) {
		form := idp.TokenForm{
			Grant:       idp.Code,
			Code:        "abc",
			RedirectURI: "http://re.di.rect",
			ClientID:    "xyz",
		}

		formValues := url.Values{}
		formValues.Set("code", form.Code)
		formValues.Set("grant_type", string(form.Grant))
		formValues.Set("redirect_uri", form.RedirectURI)
		formValues.Set("client_id", form.ClientID)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		token := idp.Token{
			Access: "abcdefgh",
		}
		ctrl := gomock.NewController(t)
		tokenGetter := mock.NewTokenGetter(ctrl)
		tokenGetter.EXPECT().
			NewToken(r.Context(), form).
			Return(token, nil)

		idp.HandleGetToken(tokenGetter)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), `"access_token":"abcdefgh"`)
	})
}

func TestHandleSignUp(t *testing.T) {
	idpName := "Gogal"

	t.Run("Given request should return bad request if form is not validated by server", func(t *testing.T) {
		form := idp.UserForm{
			FirstName: "Jean",
			LastName:  "Do",
			Email:     "jean@do.org",
			Password:  "123456",
		}

		formValues := url.Values{}
		formValues.Set("first_name", form.FirstName)
		formValues.Set("last_name", form.LastName)
		formValues.Set("email", form.Email)
		formValues.Set("password", form.Password)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		authenticator := mock.NewAuthenticator(ctrl)
		authenticator.EXPECT().
			RegisterUser(r.Context(), form).
			Return(idp.Session{}, idp.ErrEmailInvalid)

		idp.HandleSignUp(idpName, authenticator)(w, r)
		result := w.Result()

		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request should succeed should return to auth with session", func(t *testing.T) {
		form := idp.UserForm{
			FirstName: "Jean",
			LastName:  "Do",
			Email:     "jean@do.org",
			Password:  "123456",
		}

		formValues := url.Values{}
		formValues.Set("first_name", form.FirstName)
		formValues.Set("last_name", form.LastName)
		formValues.Set("email", form.Email)
		formValues.Set("password", form.Password)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		authenticator := mock.NewAuthenticator(ctrl)
		authenticator.EXPECT().
			RegisterUser(r.Context(), form).
			Return(idp.Session{
				ID: "123",
			}, nil)

		idp.HandleSignUp(idpName, authenticator)(w, r)
		assert.Contains(t, w.Header().Get("Set-Cookie"), idpName+"_oauth_session=123")

	})
}

func TestHandleSignIn(t *testing.T) {
	idpName := "Gogal"

	t.Run("Given request is missing email in its form body should return bad request", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("password", "123")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleSignIn(idpName, nil)(w, r)
		result := w.Result()

		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request is missing password in its form body should return bad request", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("email", "jean@deau.fr")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleSignIn(idpName, nil)(w, r)
		result := w.Result()

		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request should return bad request if authentication fails to validate email", func(t *testing.T) {
		cred := idp.Credential{
			Email:    "jean@deau.fr",
			Password: "123456",
		}

		formValues := url.Values{}
		formValues.Set("email", cred.Email)
		formValues.Set("password", cred.Password)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		authenticator := mock.NewAuthenticator(ctrl)
		authenticator.EXPECT().
			SignIn(r.Context(), cred).
			Return(idp.Session{}, idp.ErrEmailInvalid)

		idp.HandleSignIn(idpName, authenticator)(w, r)
		result := w.Result()

		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request should return bad request if authentication fails to validate password", func(t *testing.T) {
		cred := idp.Credential{
			Email:    "jean@deau.fr",
			Password: "123456",
		}

		formValues := url.Values{}
		formValues.Set("email", cred.Email)
		formValues.Set("password", cred.Password)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		authenticator := mock.NewAuthenticator(ctrl)
		authenticator.EXPECT().
			SignIn(r.Context(), cred).
			Return(idp.Session{}, idp.ErrPasswordInvalid)

		idp.HandleSignIn(idpName, authenticator)(w, r)
		result := w.Result()

		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request should return unauthorized when authentication is not authorized with given credentials", func(t *testing.T) {
		cred := idp.Credential{
			Email:    "jean@da.fr",
			Password: "98798732",
		}

		formValues := url.Values{}
		formValues.Set("email", cred.Email)
		formValues.Set("password", cred.Password)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		authenticator := mock.NewAuthenticator(ctrl)
		authenticator.EXPECT().
			SignIn(r.Context(), cred).
			Return(idp.Session{}, idp.ErrEmailOrPasswordMismatch)

		idp.HandleSignIn(idpName, authenticator)(w, r)
		result := w.Result()

		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
	})

	t.Run("Given request succeed in authenticating a user, a new session should be set", func(t *testing.T) {
		cred := idp.Credential{
			Email:    "jacques@bob.fr",
			Password: "qzdqdzqzd",
		}

		formValues := url.Values{}
		formValues.Set("email", cred.Email)
		formValues.Set("password", cred.Password)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		session := idp.Session{
			ID:         "xyz",
			Expiration: time.Date(2000, 1, 1, 1, 1, 1, 1, time.UTC),
		}
		ctrl := gomock.NewController(t)
		authenticator := mock.NewAuthenticator(ctrl)
		authenticator.EXPECT().
			SignIn(r.Context(), cred).
			Return(session, nil)

		idp.HandleSignIn(idpName, authenticator)(w, r)
		assert.Contains(t, w.Header().Get("Set-Cookie"), idpName+"_oauth_session=xyz")
	})
}

func TestHandleAuth(t *testing.T) {
	idpName := "Gogal"
	t.Run("Given request is missing redirection URI in its form body, "+
		"authorization server SHOULD inform the resource owner and NOT redirect", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("response_type", "code")
		formValues.Set("client_id", "xyz")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleAuth(idpName, nil)(w, r)
		result := w.Result()

		b, err := io.ReadAll(result.Body)
		assert.NoError(t, err)

		assert.Contains(t, string(b), "400: request is missing redirect_uri")
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request is missing client identifier in its form body, "+
		"authorization server SHOULD inform the resource owner and NOT redirect", func(t *testing.T) {
		w := httptest.NewRecorder()
		formValues := url.Values{}
		formValues.Set("response_type", "code")
		formValues.Set("redirect_uri", "http://re.di.rect")

		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleAuth(idpName, nil)(w, r)
		result := w.Result()

		b, err := io.ReadAll(result.Body)
		assert.NoError(t, err)

		assert.Contains(t, string(b), "400: request is missing client_id")
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request does not have response_type set to Code in its form body, "+
		"authorization server SHOULD inform the resource owner and NOT redirect", func(t *testing.T) {
		w := httptest.NewRecorder()
		formValues := url.Values{}
		formValues.Set("response_type", "cade")
		formValues.Set("client_id", "xyz")
		formValues.Set("redirect_uri", "http://re.di.rect")

		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleAuth(idpName, nil)(w, r)
		result := w.Result()

		b, err := io.ReadAll(result.Body)
		assert.NoError(t, err)

		assert.Contains(t, string(b), "400: request should include response_type=Code")
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request provides a mismatching redirect URI, "+
		"authorization server SHOULD inform the resource owner and NOT redirect", func(t *testing.T) {
		w := httptest.NewRecorder()

		form := idp.AuthorizationForm{
			ResponseType: "code",
			ClientID:     "xyz",
			RedirectURI:  "http://re.di.rect",
			State:        "abc",
		}

		formValues := url.Values{}
		formValues.Set("response_type", form.ResponseType)
		formValues.Set("client_id", form.ClientID)
		formValues.Set("redirect_uri", form.RedirectURI)
		formValues.Set("state", form.State)

		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		authorizer := mock.NewAuthorizer(ctrl)
		authorizer.EXPECT().
			AuthorizeClient(r.Context(), form).
			Return(idp.ErrMismatchingRedirectURI)

		idp.HandleAuth(idpName, authorizer)(w, r)
		result := w.Result()

		b, err := io.ReadAll(result.Body)
		assert.NoError(t, err)

		assert.Contains(t, string(b), "400: mismatching redirect_uri")
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request provides an unkown client id, "+
		"authorization server SHOULD inform the resource owner and NOT redirect", func(t *testing.T) {
		w := httptest.NewRecorder()

		form := idp.AuthorizationForm{
			ResponseType: "code",
			ClientID:     "xyz-unregistered",
			RedirectURI:  "http://re.di.rect",
			State:        "abc",
		}

		formValues := url.Values{}
		formValues.Set("response_type", form.ResponseType)
		formValues.Set("client_id", form.ClientID)
		formValues.Set("redirect_uri", form.RedirectURI)
		formValues.Set("state", form.State)

		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		authorizer := mock.NewAuthorizer(ctrl)
		authorizer.EXPECT().
			AuthorizeClient(r.Context(), form).
			Return(idp.ErrInvalidClientID)

		idp.HandleAuth(idpName, authorizer)(w, r)
		result := w.Result()

		b, err := io.ReadAll(result.Body)
		assert.NoError(t, err)

		assert.Contains(t, string(b), "400: client_id provided is invalid")
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
	})

	t.Run("Given request fails to authorize client for reasons that requires redirection, "+
		"authorization server SHOULD inform the resource owner by adding "+
		"parameters to the query component of the redirection URI", func(t *testing.T) {

		form := idp.AuthorizationForm{
			ResponseType: "code",
			ClientID:     "xyz",
			RedirectURI:  "http://re.di.rect",
			State:        "abc",
		}

		tests := []struct {
			authClientErr error

			wantErrParamValue string
		}{
			{
				authClientErr: idp.ErrClientUnauthorized,

				wantErrParamValue: "unauthorized_client",
			},
			{
				authClientErr: errors.New("internal error"),

				wantErrParamValue: "server_error",
			},
			{
				authClientErr: idp.ErrTemporarilyUnavailable,

				wantErrParamValue: "temporarily_unavailable",
			},
		}

		for _, test := range tests {
			formValues := url.Values{}
			formValues.Set("response_type", form.ResponseType)
			formValues.Set("client_id", form.ClientID)
			formValues.Set("redirect_uri", form.RedirectURI)
			formValues.Set("state", form.State)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			ctrl := gomock.NewController(t)
			authorizer := mock.NewAuthorizer(ctrl)
			authorizer.EXPECT().
				AuthorizeClient(r.Context(), form).
				Return(test.authClientErr)

			idp.HandleAuth(idpName, authorizer)(w, r)
			result := w.Result()

			wantLoc := fmt.Sprintf("%s?%s", form.RedirectURI, "error="+test.wantErrParamValue)
			assert.Contains(t, result.Header.Get("location"), wantLoc)
			assert.Equal(t, http.StatusFound, result.StatusCode)
		}
	})

	t.Run("Given request is valid and user is already connected, generate an authentication Code from its session", func(t *testing.T) {
		sessionID := "1234"
		wantAuthCode := "1234"

		form := idp.AuthorizationForm{
			ResponseType: "code",
			ClientID:     "xyz",
			RedirectURI:  "http://re.di.rect",
			State:        "abc",
		}

		formValues := url.Values{}
		formValues.Set("response_type", form.ResponseType)
		formValues.Set("client_id", form.ClientID)
		formValues.Set("redirect_uri", form.RedirectURI)
		formValues.Set("state", form.State)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{
			Name:  idpName + "_oauth_session",
			Value: sessionID,
		})

		ctrl := gomock.NewController(t)
		authorizer := mock.NewAuthorizer(ctrl)
		authorizer.EXPECT().
			AuthorizeClient(r.Context(), form).
			Return(nil)

		authorizer.EXPECT().
			NewAuthCode(r.Context(), sessionID, form).
			Return(wantAuthCode, nil)

		idp.HandleAuth(idpName, authorizer)(w, r)
		result := w.Result()

		loc := result.Header.Get("location")
		wantLoc := fmt.Sprintf("%s?code=%s&state=%s",
			form.RedirectURI, wantAuthCode, form.State)
		assert.Equal(t, wantLoc, loc)
		assert.Equal(t, http.StatusFound, result.StatusCode)
	})

	t.Run("Given request is valid and user session is not found, redirect to sign-in page with same request params", func(t *testing.T) {
		sessionID := "1234"

		form := idp.AuthorizationForm{
			ResponseType: "code",
			ClientID:     "xyz",
			RedirectURI:  "http://re.di.rect",
			State:        "abc",
		}

		formValues := url.Values{}
		formValues.Set("response_type", form.ResponseType)
		formValues.Set("client_id", form.ClientID)
		formValues.Set("redirect_uri", form.RedirectURI)
		formValues.Set("state", form.State)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		authorizer := mock.NewAuthorizer(ctrl)
		authorizer.EXPECT().
			AuthorizeClient(r.Context(), form).
			Return(nil)

		r.AddCookie(&http.Cookie{
			Name:  idpName + "_oauth_session",
			Value: sessionID,
		})

		authorizer.EXPECT().
			NewAuthCode(r.Context(), sessionID, form).
			Return("", errors.New("session not found"))

		idp.HandleAuth(idpName, authorizer)(w, r)
		result := w.Result()

		loc := result.Header.Get("location")
		wantLoc := fmt.Sprintf("%s?%s", "/sign-in", formValues.Encode())
		assert.Equal(t, loc, wantLoc)
		assert.Equal(t, http.StatusFound, result.StatusCode)
	})

	t.Run("Given request is valid and user session is found but user prompt login, redirect to login page with same request params", func(t *testing.T) {
		sessionID := "1234"

		form := idp.AuthorizationForm{
			ResponseType: "code",
			ClientID:     "xyz",
			RedirectURI:  "http://re.di.rect",
			State:        "abc",
			Prompt:       "login",
		}

		formValues := url.Values{}
		formValues.Set("response_type", form.ResponseType)
		formValues.Set("client_id", form.ClientID)
		formValues.Set("redirect_uri", form.RedirectURI)
		formValues.Set("state", form.State)
		formValues.Set("prompt", form.Prompt)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		ctrl := gomock.NewController(t)
		authorizer := mock.NewAuthorizer(ctrl)
		authorizer.EXPECT().
			AuthorizeClient(r.Context(), form).
			Return(nil)

		r.AddCookie(&http.Cookie{
			Name:  idpName + "_oauth_session",
			Value: sessionID,
		})

		idp.HandleAuth(idpName, authorizer)(w, r)
		result := w.Result()

		loc := result.Header.Get("location")
		wantLoc := fmt.Sprintf("%s?%s", "/sign-in", formValues.Encode())
		assert.Equal(t, loc, wantLoc)
		assert.Equal(t, http.StatusFound, result.StatusCode)
	})
}

func TestHandleAskPasswordReset(t *testing.T) {
	t.Run("Given request is missing email in its body, should return bad request", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))

		idp.HandleAskPasswordReset(nil)(w, r)

		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
		assert.Contains(t, string(body), idp.ErrEmailMissing.Error())
	})

	t.Run("Given server fails should return its error in the response", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
			"email":"jon@doe.com",
			"initialQuery":"?foo=bar"
		}`))

		ctrl := gomock.NewController(t)
		setter := mock.NewPasswordSetter(ctrl)
		setter.EXPECT().
			ResetPassword(r.Context(), "jon@doe.com", "?foo=bar").
			Return(idp.ErrUnauthorized{Err: "email not authorized"})

		idp.HandleAskPasswordReset(setter)(w, r)

		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, result.StatusCode)
		assert.Contains(t, string(body), "email not authorized")
	})

	t.Run("Given server succeed should return 202 success", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
			"email":"bobsap@ufc.org",
			"initialQuery":"?bar=foo"
		}`))

		ctrl := gomock.NewController(t)
		setter := mock.NewPasswordSetter(ctrl)
		setter.EXPECT().
			ResetPassword(r.Context(), "bobsap@ufc.org", "?bar=foo").
			Return(nil)

		idp.HandleAskPasswordReset(setter)(w, r)

		result := w.Result()
		assert.Equal(t, http.StatusAccepted, result.StatusCode)
	})
}

func TestHandlePutPassword(t *testing.T) {
	t.Run("Given request is missing token should return bad request", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
			"newPassword":"123456"
		}`))

		idp.HandleSetPasswordFromResetToken(nil)(w, r)

		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
		assert.Contains(t, string(body), idp.ErrMissingResetPasswordToken.Error())
	})
	t.Run("Given request is missing new password should return bad request", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
			"token":"abc"
		}`))
		idp.HandleSetPasswordFromResetToken(nil)(w, r)

		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, result.StatusCode)
		assert.Contains(t, string(body), idp.ErrMissingPassword.Error())
	})
	t.Run("Given request should return error if server fails to set new password", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
			"token":"abc",
			"newPassword":"xyz_secret"
		}`))

		ctrl := gomock.NewController(t)
		setter := mock.NewPasswordSetter(ctrl)
		setter.EXPECT().
			UpdatePasswordFromResetToken(r.Context(), "abc", "xyz_secret").
			Return(errors.New("internal error"))

		idp.HandleSetPasswordFromResetToken(setter)(w, r)

		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, result.StatusCode)
		assert.Contains(t, string(body), "internal error")
	})

	t.Run("Given request should update password properly and return 202 status", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{
			"token":"abc",
			"newPassword":"xyz_secret"
		}`))

		ctrl := gomock.NewController(t)
		setter := mock.NewPasswordSetter(ctrl)
		setter.EXPECT().
			UpdatePasswordFromResetToken(r.Context(), "abc", "xyz_secret").
			Return(nil)

		idp.HandleSetPasswordFromResetToken(setter)(w, r)

		result := w.Result()
		assert.Equal(t, http.StatusAccepted, result.StatusCode)
	})
}

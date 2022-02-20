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

func TestHandleGetAccessToken(t *testing.T) {
	t.Run("Given request is missing grant_type=authorization_code should return bad request", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("code", "abc")
		formValues.Set("redirect_uri", "http://re.di.rect")
		formValues.Set("client_id", "xyz")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleGetAccessToken(nil)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMissingGrantType.Error())
	})

	t.Run("Given request is missing code should return bad request", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("grant_type", "authorization_code")
		formValues.Set("redirect_uri", "http://re.di.rect")
		formValues.Set("client_id", "xyz")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleGetAccessToken(nil)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMissingAuthCode.Error())
	})

	t.Run("Given request is missing redirect uri should return bad request", func(t *testing.T) {
		formValues := url.Values{}
		formValues.Set("code", "abc")
		formValues.Set("grant_type", "authorization_code")
		formValues.Set("client_id", "xyz")

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(formValues.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		idp.HandleGetAccessToken(nil)(w, r)
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

		idp.HandleGetAccessToken(nil)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMissingClientID.Error())
	})

	t.Run("Given request fails with mismatching URI should return error mismatching_uri", func(t *testing.T) {
		form := idp.AccessTokenForm{
			GrantType:   "authorization_code",
			Code:        "abc",
			RedirectURI: "http://re.di.rect",
			ClientID:    "xyz",
		}

		formValues := url.Values{}
		formValues.Set("code", form.Code)
		formValues.Set("grant_type", form.GrantType)
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

		idp.HandleGetAccessToken(tokenGetter)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), idp.ErrMismatchingRedirectURI.Error())
	})

	t.Run("Given request fails internally should return internal server error", func(t *testing.T) {
		form := idp.AccessTokenForm{
			GrantType:   "authorization_code",
			Code:        "abc",
			RedirectURI: "http://re.di.rect",
			ClientID:    "xyz",
		}

		formValues := url.Values{}
		formValues.Set("code", form.Code)
		formValues.Set("grant_type", form.GrantType)
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

		idp.HandleGetAccessToken(tokenGetter)(w, r)
		result := w.Result()
		body, err := io.ReadAll(result.Body)
		assert.NoError(t, err)
		assert.Contains(t, string(body), "internal server error")
	})

	t.Run("Given request should return user access token freely", func(t *testing.T) {
		form := idp.AccessTokenForm{
			GrantType:   "authorization_code",
			Code:        "abc",
			RedirectURI: "http://re.di.rect",
			ClientID:    "xyz",
		}

		formValues := url.Values{}
		formValues.Set("code", form.Code)
		formValues.Set("grant_type", form.GrantType)
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

		idp.HandleGetAccessToken(tokenGetter)(w, r)
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

	t.Run("Given request does not have response_type set to code in its form body, "+
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

		assert.Contains(t, string(b), "400: request should include response_type=code")
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

	t.Run("Given request is valid and user is already connected, generate an authentication code from its session", func(t *testing.T) {
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
		assert.Equal(t, loc, wantLoc)
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

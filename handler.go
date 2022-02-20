package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

//go:generate mockgen -source $GOFILE -destination mock/$GOFILE -package mock -mock_names Authorizer=Authorizer,Authenticator=Authenticator,TokenGetter=TokenGetter,UserAccesser=UserAccesser,ClientMaker=ClientMaker

const (
	unauthorizedClient     = "unauthorized_client"
	serverError            = "server_error"
	temporarilyUnavailable = "temporarily_unavailable"
)

// Authorizer authorizes a client to fetch user identity on behalf of a user
type Authorizer interface {
	AuthorizeClient(ctx context.Context, form AuthorizationForm) error
	NewAuthCode(ctx context.Context, session string, form AuthorizationForm) (string, error)
}

// Authenticator authenticates a user
type Authenticator interface {
	AuthenticateUser(ctx context.Context, cred Credential) (Session, error)
}

type TokenGetter interface {
	NewToken(ctx context.Context, form AccessTokenForm) (Token, error)
}

type UserAccesser interface {
	AccessUser(ctx context.Context, accessToken string) (User, error)
}

type ClientMaker interface {
	NewClient(ctx context.Context, appName string, redirectURIs []string) (Client, error)
}

type authError struct {
	IDP        string
	StatusCode int
	Message    string
}

func HandlePostClient(maker ClientMaker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app, err := parsePostClientForm(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		client, err := maker.NewClient(r.Context(), app.name, app.redirectURIs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(client)
	}
}

type clientForm struct {
	name         string
	redirectURIs []string
}

func parsePostClientForm(r *http.Request) (clientForm, error) {
	if err := r.ParseForm(); err != nil {
		return clientForm{}, err
	}
	name := r.Form.Get("name")
	redirectURIs := r.Form.Get("redirect_uris")
	if name == "" {
		return clientForm{}, ErrMissingAppName
	}
	if redirectURIs == "" {
		return clientForm{}, ErrMissingAppRedirectURIs
	}
	return clientForm{
		name:         name,
		redirectURIs: strings.Split(redirectURIs, ","),
	}, nil
}

func HandleGetUser(userAccesser UserAccesser) http.HandlerFunc {
	const bearerSchema = "Bearer "
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("authorization")
		if !strings.HasPrefix(auth, bearerSchema) {
			http.Error(w, ErrMissingBearerToken.Error(), http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		id, err := userAccesser.AccessUser(r.Context(), token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(id)
	}
}

func HandleGetAccessToken(tokenGetter TokenGetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form, err := parseAccessTokenForm(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		token, err := tokenGetter.NewToken(r.Context(), form)
		if err != nil {
			handleGetAccessTokenError(w, err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}
}

func handleGetAccessTokenError(w http.ResponseWriter, err error) {
	switch err {
	case ErrMismatchingRedirectURI:
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func parseAccessTokenForm(r *http.Request) (AccessTokenForm, error) {
	err := r.ParseForm()
	if err != nil {
		return AccessTokenForm{}, err
	}
	form := AccessTokenForm{
		GrantType:   r.Form.Get("grant_type"),
		ClientID:    r.Form.Get("client_id"),
		RedirectURI: r.Form.Get("redirect_uri"),
		Code:        r.Form.Get("code"),
	}
	if form.RedirectURI == "" {
		return form, ErrMissingRedirectURI
	}
	if form.ClientID == "" {
		return form, ErrMissingClientID
	}
	if form.GrantType != "authorization_code" {
		return form, ErrMissingGrantType
	}
	if form.Code == "" {
		return form, ErrMissingAuthCode
	}
	return form, nil
}

func HandleLogin(idpName string, auth Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cred, err := parseLoginForm(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		session, err := auth.AuthenticateUser(r.Context(), cred)
		if err != nil {
			handleAuthenticatingError(w, err)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     idpName + "_oauth_session",
			Secure:   true,
			Path:     "/",
			HttpOnly: true,
			Value:    session.ID,
			Expires:  session.Expiration,
		})
	}
}

func handleAuthenticatingError(w http.ResponseWriter, err error) {
	switch err {
	case ErrEmailInvalid, ErrPasswordInvalid:
		http.Error(w, err.Error(), http.StatusBadRequest)
	case ErrEmailOrPasswordMismatch:
		http.Error(w, err.Error(), http.StatusUnauthorized)
	}
}

func parseLoginForm(r *http.Request) (Credential, error) {
	err := r.ParseForm()
	if err != nil {
		return Credential{}, err
	}
	cred := Credential{
		Email:    r.Form.Get("email"),
		Password: r.Form.Get("password"),
	}
	if cred.Email == "" {
		return cred, ErrEmailMissing
	}
	if cred.Password == "" {
		return cred, ErrPasswordMissing
	}
	return cred, nil
}

func HandleAuth(idpName string, auth Authorizer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		form, err := parseAuthorizationForm(r)
		if err != nil {
			informBadRequest(w, err, idpName)
			return
		}

		err = auth.AuthorizeClient(ctx, form)
		if err != nil {
			handleAuthClientError(w, r, idpName, form.RedirectURI, err)
			return
		}

		session, _ := r.Cookie(idpName + "_oauth_session")
		if session == nil || form.Prompt == "login" {
			redirectToLogin(w, r)
			return
		}

		code, err := auth.NewAuthCode(ctx, session.Value, form)
		if err != nil {
			redirectToLogin(w, r)
			return
		}

		redirectAuthCode(code, form, w, r)
	}
}

func redirectAuthCode(code string, form AuthorizationForm, w http.ResponseWriter, r *http.Request) {
	params := url.Values{}
	params.Set("code", code)
	if form.State != "" {
		params.Set("state", form.State)
	}
	http.Redirect(w, r, form.RedirectURI+"?"+params.Encode(), http.StatusFound)
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login?"+r.Form.Encode(), http.StatusFound)
	return
}

func handleAuthClientError(w http.ResponseWriter, r *http.Request, idpName, redirectURI string, err error) {
	var errParam string
	switch err {
	case ErrMismatchingRedirectURI, ErrInvalidClientID:
		informBadRequest(w, err, idpName)
	case ErrClientUnauthorized:
		errParam = unauthorizedClient
	case ErrTemporarilyUnavailable:
		errParam = temporarilyUnavailable
	default:
		errParam = serverError
	}
	param := url.Values{}
	param.Set("error", errParam)
	param.Set("error_description", err.Error())
	target := fmt.Sprintf("%s?%s", redirectURI, param.Encode())
	http.Redirect(w, r, target, http.StatusFound)
}

func parseAuthorizationForm(r *http.Request) (form AuthorizationForm, err error) {
	err = r.ParseForm()
	if err != nil {
		return form, err
	}
	form = AuthorizationForm{
		ResponseType: r.Form.Get("response_type"),
		ClientID:     r.Form.Get("client_id"),
		RedirectURI:  r.Form.Get("redirect_uri"),
		State:        r.Form.Get("state"),
		Prompt:       r.Form.Get("prompt"),
	}
	if form.RedirectURI == "" {
		return form, ErrMissingRedirectURI
	}
	if form.ClientID == "" {
		return form, ErrMissingClientID
	}
	if form.ResponseType != "code" {
		return form, ErrResponseTypeIsNotCode
	}
	return form, nil
}

func informBadRequest(w http.ResponseWriter, err error, idpName string) {
	informErrorOccured(w, authError{
		StatusCode: http.StatusBadRequest,
		Message:    err.Error(),
		IDP:        idpName,
	})
}

func informErrorOccured(w http.ResponseWriter, authErr authError) {
	w.WriteHeader(authErr.StatusCode)
	t := templates["err.html"]
	if err := t.Execute(w, authErr); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

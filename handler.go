package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

//go:generate mockgen -source $GOFILE -destination mock/$GOFILE -package mock -mock_names Authorizer=Authorizer,Authenticator=Authenticator,TokenGetter=TokenGetter,UserAccesser=UserAccesser,ClientMaker=ClientMaker,PasswordSetter=PasswordSetter

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
	SignIn(ctx context.Context, cred Credential) (Session, error)
	RegisterUser(ctx context.Context, form UserForm) (Session, error)
}

type TokenGetter interface {
	NewToken(ctx context.Context, form AccessTokenForm) (Token, error)
	RefreshToken(ctx context.Context, form RefreshTokenForm) (Token, error)
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

func HandleGetToken(tokenGetter TokenGetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form, err := parseTokenForm(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var token Token
		switch form.Grant {
		case Code:
			token, err = tokenGetter.NewToken(r.Context(), form)
		case Refresh:
			token, err = tokenGetter.RefreshToken(r.Context(), form)
		}
		if err != nil {
			handleErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}
}

// TokenForm will be populated from token request
type TokenForm struct {
	Grant        GrantType
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Code         string
	RefreshToken string
}

type GrantType string

const (
	Code    GrantType = "authorization_code"
	Refresh GrantType = "refresh_token"
)

func (f TokenForm) GetGrantType() GrantType {
	return f.Grant
}

func (f TokenForm) GetClientID() string {
	return f.ClientID
}

func (f TokenForm) GetClientSecret() string {
	return f.ClientSecret
}

func (f TokenForm) GetRedirectURI() string {
	return f.RedirectURI
}

func (f TokenForm) GetCode() string {
	return f.Code
}

func (f TokenForm) GetRefreshTokenID() string {
	return f.RefreshToken
}

func parseTokenForm(r *http.Request) (form TokenForm, err error) {
	err = r.ParseForm()
	if err != nil {
		return form, err
	}
	grantType := r.Form.Get("grant_type")
	switch grantType {
	case "authorization_code":
		return parseAccessTokenForm(r.Form)
	case "refresh_token":
		return parseRefreshTokenForm(r.Form)
	default:
		return form, ErrMissingGrantType
	}
}

func parseRefreshTokenForm(values url.Values) (TokenForm, error) {
	form := TokenForm{
		Grant:        Refresh,
		ClientID:     values.Get("client_id"),
		ClientSecret: values.Get("client_secret"),
		RefreshToken: values.Get("refresh_token"),
	}
	if form.ClientID == "" {
		return form, ErrMissingClientID
	}
	if form.ClientSecret == "" {
		return form, ErrMissingClientSecret
	}
	if form.RefreshToken == "" {
		return form, ErrMissingRefreshToken
	}
	return form, nil
}

func parseAccessTokenForm(values url.Values) (TokenForm, error) {
	form := TokenForm{
		Grant:       Code,
		ClientID:    values.Get("client_id"),
		RedirectURI: values.Get("redirect_uri"),
		Code:        values.Get("code"),
	}
	if form.RedirectURI == "" {
		return form, ErrMissingRedirectURI
	}
	if form.ClientID == "" {
		return form, ErrMissingClientID
	}
	if form.Code == "" {
		return form, ErrMissingAuthCode
	}
	return form, nil
}

func HandleSignUp(idpName string, auth Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		form, err := parseSignUpForm(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		session, err := auth.RegisterUser(r.Context(), form)
		if err != nil {
			handleErr(w, err)
			return
		}
		setSessionCookie(idpName, session, w)
	}
}

func handleErr(w http.ResponseWriter, err error) {
	switch err.(type) {
	case ErrBadRequest:
		http.Error(w, err.Error(), http.StatusBadRequest)
	case ErrUnauthorized:
		http.Error(w, err.Error(), http.StatusUnauthorized)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func HandleSignIn(idpName string, auth Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cred, err := parseSignInForm(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		session, err := auth.SignIn(r.Context(), cred)
		if err != nil {
			handleErr(w, err)
			return
		}
		setSessionCookie(idpName, session, w)
	}
}

func setSessionCookie(idpName string, session Session, w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     idpName + "_oauth_session",
		Secure:   true,
		Path:     "/",
		HttpOnly: true,
		Value:    session.ID,
		Expires:  session.Expiration,
	})
}

func parseSignUpForm(r *http.Request) (UserForm, error) {
	err := r.ParseForm()
	if err != nil {
		return UserForm{}, err
	}
	form := UserForm{
		FirstName: r.Form.Get("first_name"),
		LastName:  r.Form.Get("last_name"),
		Email:     r.Form.Get("email"),
		Password:  r.Form.Get("password"),
	}
	return form, nil
}

func parseSignInForm(r *http.Request) (Credential, error) {
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
	http.Redirect(w, r, "/sign-in?"+r.Form.Encode(), http.StatusFound)
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

type PasswordSetter interface {
	ResetPassword(ctx context.Context, email string, initialQuery string) error
	UpdatePasswordFromResetToken(ctx context.Context, token, password string) error
}

func HandleSetPasswordFromResetToken(setter PasswordSetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token       string `json:"token"`
			NewPassword string `json:"newPassword"`
		}
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body.Token == "" {
			handleErr(w, ErrMissingResetPasswordToken)
			return
		}
		if body.NewPassword == "" {
			handleErr(w, ErrMissingPassword)
			return
		}
		err = setter.UpdatePasswordFromResetToken(r.Context(), body.Token, body.NewPassword)
		if err != nil {
			handleErr(w, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}
}

func HandleAskPasswordReset(setter PasswordSetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Email        string `json:"email"`
			InitialQuery string `json:"initialQuery"`
		}
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body.Email == "" {
			handleErr(w, ErrEmailMissing)
			return
		}
		err = setter.ResetPassword(r.Context(), body.Email, body.InitialQuery)
		if err != nil {
			handleErr(w, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}
}

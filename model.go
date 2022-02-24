package idp

import (
	"go.mongodb.org/mongo-driver/bson"
	"net/mail"
	"time"
)

type PasswordReset struct {
	Token        string
	User         User
	InitialQuery string
}

type AccessTokenForm interface {
	GetCode() string
	GetRedirectURI() string
	GetClientID() string
}

type RefreshTokenForm interface {
	GetClientID() string
	GetClientSecret() string
	GetRefreshTokenID() string
}

type AuthorizationForm struct {
	// REQUIRED.
	//
	// Value MUST be set to "Code".
	ResponseType string
	// OPTIONAL.
	//
	// As described in https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.
	RedirectURI string
	// REQUIRED.
	//
	// The client identifier as described in https://datatracker.ietf.org/doc/html/rfc6749#section-2.2.
	ClientID string
	//  RECOMMENDED.
	//
	//  An opaque value used by the client to maintain
	//  state between the request and callback.  The authorization
	//  server includes this value when redirecting the user-agent back
	//  to the client.  The parameter SHOULD be used for preventing
	//  cross-site request forgery as described in
	//  https://datatracker.ietf.org/doc/html/rfc6749#section-10.12.
	State string
	// OPTIONAL
	//
	// Prompt may be set to "login" should client wants to force
	// a new login challenge.
	Prompt string
}

type Client struct {
	// ID is the public unique client identifier
	ID     string `json:"id" bson:"id"`
	Secret string `json:"secret" bson:"secret"`
	Name   string `json:"name" bson:"name"`
	// A list of authorized redirect uris
	AuthorizedRedirects []string  `json:"authorizedRedirects" bson:"authorizedRedirects"`
	CreatedAt           time.Time `json:"-" bson:"createdAt"`
}

type Credential struct {
	Email    string
	Password string
}

func (c Credential) EnsureValid() error {
	if len(c.Password) < 6 {
		return ErrPasswordInvalid
	}
	_, err := mail.ParseAddress(c.Email)
	if err != nil {
		return ErrEmailInvalid
	}
	return nil
}

type Session struct {
	ID         string
	Expiration time.Time
	User       User
}

type Token struct {
	Access  string `json:"access_token,omitempty"`
	Refresh string `json:"refresh_token,omitempty"`
	// Expires in second before the ACCESS token is invalid
	Expires int `json:"expires"`
}

type User struct {
	UID            string `json:"uid,omitempty" bson:"uid"`
	FirstName      string `json:"firstName,omitempty" bson:"firstName"`
	LastName       string `json:"lastName,omitempty" bson:"lastName"`
	Email          string `json:"email,omitempty" bson:"email"`
	HashedPassword []byte `json:"-" bson:"hashedPassword"`
}

type UserForm struct {
	FirstName string
	LastName  string
	Email     string
	Password  string
}

func (u UserForm) EnsureValid() error {
	if len(u.FirstName) < 2 {
		return ErrUserFirstNameInvalid
	}
	if len(u.LastName) < 2 {
		return ErrUserLastNameInvalid
	}
	_, err := mail.ParseAddress(u.Email)
	if err != nil {
		return ErrEmailInvalid
	}
	if len(u.Password) < 6 {
		return ErrPasswordInvalid
	}
	return nil
}

type Authorization struct {
	Code        string
	User        User
	RedirectURI string
	Client      Client
	Expiration  time.Time
}

type Access struct {
	ID           string
	RefreshToken RefreshToken
	User         User
	Expiration   time.Time
}

type RefreshToken struct {
	ID         string    `bson:"id"`
	Expiration time.Time `bson:"expiration"`
}

func (s Session) MarshalBSON() ([]byte, error) {
	session := struct {
		ID         string    `bson:"id"`
		UserUID    string    `bson:"userUID"`
		Expiration time.Time `bson:"expiration"`
	}{
		ID:         s.ID,
		UserUID:    s.User.UID,
		Expiration: s.Expiration,
	}
	return bson.Marshal(session)
}

func (a Access) MarshalBSON() ([]byte, error) {
	access := struct {
		ID           string       `bson:"id"`
		UserUID      string       `bson:"userUID"`
		RefreshToken RefreshToken `bson:"refreshToken"`
		Expiration   time.Time    `bson:"expiration"`
	}{
		ID:           a.ID,
		UserUID:      a.User.UID,
		RefreshToken: a.RefreshToken,
		Expiration:   a.Expiration,
	}
	return bson.Marshal(access)
}

func (a Authorization) MarshalBSON() ([]byte, error) {
	authorization := struct {
		Code        string    `bson:"code"`
		UserUID     string    `bson:"userUID"`
		RedirectURI string    `bson:"redirectURI"`
		ClientID    string    `bson:"clientID"`
		Expiration  time.Time `bson:"expiration"`
	}{
		Code:        a.Code,
		UserUID:     a.User.UID,
		RedirectURI: a.RedirectURI,
		ClientID:    a.Client.ID,
		Expiration:  a.Expiration,
	}
	return bson.Marshal(authorization)
}

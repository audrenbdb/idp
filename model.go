package idp

import (
	"go.mongodb.org/mongo-driver/bson"
	"net/mail"
	"time"
)

type AccessTokenForm struct {
	// REQUIRED.
	//
	// GrantType value mus be set to "authorization_code"
	GrantType string
	// REQUIRED.
	//
	// The authorization code received from the
	// authorization server.
	Code string
	// REQUIRED.
	//
	// Redirect URI similar to one passed in authorization
	// code request.
	RedirectURI string
	// REQUIRED.
	//
	// Client identifier
	ClientID string
}

type AuthorizationForm struct {
	// REQUIRED.
	//
	// Value MUST be set to "code".
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
	Access string `json:"access_token,omitempty"`
}

type User struct {
	UID            string `json:"uid,omitempty"`
	Email          string `json:"email,omitempty"`
	HashedPassword []byte `json:"-" bson:"hashedPassword"`
}

type Authorization struct {
	Code        string
	User        User
	RedirectURI string
	Client      Client
	Expiration  time.Time
}

type Access struct {
	ID         string
	User       User
	Expiration time.Time
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
		ID         string    `bson:"id"`
		UserUID    string    `bson:"userUID"`
		Expiration time.Time `bson:"expiration"`
	}{
		ID:         a.ID,
		UserUID:    a.User.UID,
		Expiration: a.Expiration,
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

package idp

type (
	ErrNotFound     struct{ Err }
	ErrUnauthorized struct{ Err }
	ErrBadRequest   struct{ Err }
)

type Err string

func (e Err) Error() string {
	return string(e)
}

var (
	ErrAuthorizationNotFound = ErrNotFound{"authorization not found"}
	ErrAccessNotFound        = ErrNotFound{"access not found"}
	ErrClientNotFound        = ErrNotFound{"client not found"}
	ErrSessionNotFound       = ErrNotFound{"session not found"}
	ErrUserNotFound          = ErrNotFound{"user not found"}

	ErrSessionExpired          = ErrUnauthorized{"session expired"}
	ErrAuthorizationExpired    = ErrUnauthorized{"authorization expired"}
	ErrAccessExpired           = ErrUnauthorized{"access expired"}
	ErrClientUnauthorized      = ErrUnauthorized{"client is not authorized to request an authorization code"}
	ErrEmailOrPasswordMismatch = ErrUnauthorized{"email or password mismatch"}
	ErrInvalidClientID         = ErrUnauthorized{"client_id provided is invalid"}
	ErrMismatchingRedirectURI  = ErrUnauthorized{"mismatching redirect_uri"}
	ErrMissingBearerToken      = ErrUnauthorized{"missing bearer token"}

	ErrMissingAppName         = ErrBadRequest{"request is missing app name"}
	ErrMissingAppRedirectURIs = ErrBadRequest{"request is missing redirect_uris"}
	ErrEmailInvalid           = ErrBadRequest{"email is invalid"}
	ErrEmailMissing           = ErrBadRequest{"email is missing"}
	ErrMissingAuthCode        = ErrBadRequest{"request is missing code parameter"}
	ErrMissingClientID        = ErrBadRequest{"request is missing client_id"}
	ErrMissingGrantType       = ErrBadRequest{"request is missing grant_type=authorization_code"}
	ErrMissingRedirectURI     = ErrBadRequest{"request is missing redirect_uri"}
	ErrPasswordInvalid        = ErrBadRequest{"password is invalid"}
	ErrPasswordMissing        = ErrBadRequest{"password is missing"}
	ErrResponseTypeIsNotCode  = ErrBadRequest{"request should include response_type=code"}
	ErrTemporarilyUnavailable = ErrBadRequest{"authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server"}
)

package idp

type (
	ErrNotFound     struct{ Err }
	ErrUnauthorized struct{ Err }
	ErrBadRequest   struct{ Err }
	ErrInternal     struct{ Err }
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
	ErrPasswordResetNotFound = ErrNotFound{"password reset not found"}

	ErrSessionExpired          = ErrUnauthorized{"session expired"}
	ErrAuthorizationExpired    = ErrUnauthorized{"authorization expired"}
	ErrAccessExpired           = ErrUnauthorized{"access expired"}
	ErrClientUnauthorized      = ErrUnauthorized{"client is not authorized to request an authorization Code"}
	ErrEmailOrPasswordMismatch = ErrUnauthorized{"email or password mismatch"}
	ErrInvalidClientID         = ErrUnauthorized{"client_id provided is invalid"}
	ErrMismatchingRedirectURI  = ErrUnauthorized{"mismatching redirect_uri"}
	ErrMissingBearerToken      = ErrUnauthorized{"missing bearer token"}
	ErrUserAlreadyExists       = ErrUnauthorized{"user already exists"}
	ErrInvalidRefreshToken     = ErrUnauthorized{"refresh token is expired or invalid"}

	ErrMissingAppName            = ErrBadRequest{"request is missing app name"}
	ErrMissingAppRedirectURIs    = ErrBadRequest{"request is missing redirect_uris"}
	ErrMissingResetPasswordToken = ErrBadRequest{"request is missing token to reset password"}
	ErrMissingPassword           = ErrBadRequest{"missing password"}
	ErrEmailInvalid              = ErrBadRequest{"email is invalid"}
	ErrEmailMissing              = ErrBadRequest{"email is missing"}

	ErrUserFirstNameInvalid = ErrBadRequest{"first name is invalid"}
	ErrUserLastNameInvalid  = ErrBadRequest{"last name is invalid"}

	ErrMissingAuthCode        = ErrBadRequest{"request is missing Code parameter"}
	ErrMissingClientID        = ErrBadRequest{"request is missing client_id"}
	ErrMissingClientSecret    = ErrBadRequest{"request is missing client secret"}
	ErrMissingGrantType       = ErrBadRequest{"request is missing accepted grant_type"}
	ErrMissingRedirectURI     = ErrBadRequest{"request is missing redirect_uri"}
	ErrMissingRefreshToken    = ErrBadRequest{"request is missing refresh_token"}
	ErrPasswordInvalid        = ErrBadRequest{"password is invalid"}
	ErrPasswordMissing        = ErrBadRequest{"password is missing"}
	ErrResponseTypeIsNotCode  = ErrBadRequest{"request should include response_type=Code"}
	ErrTemporarilyUnavailable = ErrBadRequest{"authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server"}
)

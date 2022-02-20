// Code generated by MockGen. DO NOT EDIT.
// Source: handler.go

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	idp "idp"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// Authorizer is a mock of Authorizer interface.
type Authorizer struct {
	ctrl     *gomock.Controller
	recorder *AuthorizerMockRecorder
}

// AuthorizerMockRecorder is the mock recorder for Authorizer.
type AuthorizerMockRecorder struct {
	mock *Authorizer
}

// NewAuthorizer creates a new mock instance.
func NewAuthorizer(ctrl *gomock.Controller) *Authorizer {
	mock := &Authorizer{ctrl: ctrl}
	mock.recorder = &AuthorizerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Authorizer) EXPECT() *AuthorizerMockRecorder {
	return m.recorder
}

// AuthorizeClient mocks base method.
func (m *Authorizer) AuthorizeClient(ctx context.Context, form idp.AuthorizationForm) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthorizeClient", ctx, form)
	ret0, _ := ret[0].(error)
	return ret0
}

// AuthorizeClient indicates an expected call of AuthorizeClient.
func (mr *AuthorizerMockRecorder) AuthorizeClient(ctx, form interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthorizeClient", reflect.TypeOf((*Authorizer)(nil).AuthorizeClient), ctx, form)
}

// NewAuthCode mocks base method.
func (m *Authorizer) NewAuthCode(ctx context.Context, session string, form idp.AuthorizationForm) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewAuthCode", ctx, session, form)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewAuthCode indicates an expected call of NewAuthCode.
func (mr *AuthorizerMockRecorder) NewAuthCode(ctx, session, form interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewAuthCode", reflect.TypeOf((*Authorizer)(nil).NewAuthCode), ctx, session, form)
}

// Authenticator is a mock of Authenticator interface.
type Authenticator struct {
	ctrl     *gomock.Controller
	recorder *AuthenticatorMockRecorder
}

// AuthenticatorMockRecorder is the mock recorder for Authenticator.
type AuthenticatorMockRecorder struct {
	mock *Authenticator
}

// NewAuthenticator creates a new mock instance.
func NewAuthenticator(ctrl *gomock.Controller) *Authenticator {
	mock := &Authenticator{ctrl: ctrl}
	mock.recorder = &AuthenticatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Authenticator) EXPECT() *AuthenticatorMockRecorder {
	return m.recorder
}

// AuthenticateUser mocks base method.
func (m *Authenticator) AuthenticateUser(ctx context.Context, cred idp.Credential) (idp.Session, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthenticateUser", ctx, cred)
	ret0, _ := ret[0].(idp.Session)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticateUser indicates an expected call of AuthenticateUser.
func (mr *AuthenticatorMockRecorder) AuthenticateUser(ctx, cred interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticateUser", reflect.TypeOf((*Authenticator)(nil).AuthenticateUser), ctx, cred)
}

// TokenGetter is a mock of TokenGetter interface.
type TokenGetter struct {
	ctrl     *gomock.Controller
	recorder *TokenGetterMockRecorder
}

// TokenGetterMockRecorder is the mock recorder for TokenGetter.
type TokenGetterMockRecorder struct {
	mock *TokenGetter
}

// NewTokenGetter creates a new mock instance.
func NewTokenGetter(ctrl *gomock.Controller) *TokenGetter {
	mock := &TokenGetter{ctrl: ctrl}
	mock.recorder = &TokenGetterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *TokenGetter) EXPECT() *TokenGetterMockRecorder {
	return m.recorder
}

// NewToken mocks base method.
func (m *TokenGetter) NewToken(ctx context.Context, form idp.AccessTokenForm) (idp.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewToken", ctx, form)
	ret0, _ := ret[0].(idp.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewToken indicates an expected call of NewToken.
func (mr *TokenGetterMockRecorder) NewToken(ctx, form interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewToken", reflect.TypeOf((*TokenGetter)(nil).NewToken), ctx, form)
}

// UserAccesser is a mock of UserAccesser interface.
type UserAccesser struct {
	ctrl     *gomock.Controller
	recorder *UserAccesserMockRecorder
}

// UserAccesserMockRecorder is the mock recorder for UserAccesser.
type UserAccesserMockRecorder struct {
	mock *UserAccesser
}

// NewUserAccesser creates a new mock instance.
func NewUserAccesser(ctrl *gomock.Controller) *UserAccesser {
	mock := &UserAccesser{ctrl: ctrl}
	mock.recorder = &UserAccesserMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *UserAccesser) EXPECT() *UserAccesserMockRecorder {
	return m.recorder
}

// AccessUser mocks base method.
func (m *UserAccesser) AccessUser(ctx context.Context, accessToken string) (idp.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AccessUser", ctx, accessToken)
	ret0, _ := ret[0].(idp.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AccessUser indicates an expected call of AccessUser.
func (mr *UserAccesserMockRecorder) AccessUser(ctx, accessToken interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AccessUser", reflect.TypeOf((*UserAccesser)(nil).AccessUser), ctx, accessToken)
}

// ClientMaker is a mock of ClientMaker interface.
type ClientMaker struct {
	ctrl     *gomock.Controller
	recorder *ClientMakerMockRecorder
}

// ClientMakerMockRecorder is the mock recorder for ClientMaker.
type ClientMakerMockRecorder struct {
	mock *ClientMaker
}

// NewClientMaker creates a new mock instance.
func NewClientMaker(ctrl *gomock.Controller) *ClientMaker {
	mock := &ClientMaker{ctrl: ctrl}
	mock.recorder = &ClientMakerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *ClientMaker) EXPECT() *ClientMakerMockRecorder {
	return m.recorder
}

// NewClient mocks base method.
func (m *ClientMaker) NewClient(ctx context.Context, appName string, redirectURIs []string) (idp.Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewClient", ctx, appName, redirectURIs)
	ret0, _ := ret[0].(idp.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewClient indicates an expected call of NewClient.
func (mr *ClientMakerMockRecorder) NewClient(ctx, appName, redirectURIs interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewClient", reflect.TypeOf((*ClientMaker)(nil).NewClient), ctx, appName, redirectURIs)
}
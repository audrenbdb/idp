package inmem

import (
	"context"
	"idp"
)

type sessionRepository struct {
	sessions map[string]idp.Session
}

func NewSessionRepository() *sessionRepository {
	return &sessionRepository{
		sessions: map[string]idp.Session{},
	}
}

func (r *sessionRepository) SaveSession(ctx context.Context, session idp.Session) (idp.Session, error) {
	r.sessions[session.ID] = session
	return session, nil
}

func (r *sessionRepository) GetSessionByID(ctx context.Context, sessionID string) (idp.Session, error) {
	session, ok := r.sessions[sessionID]
	if !ok {
		return idp.Session{}, idp.ErrSessionNotFound
	}
	return session, nil
}

package security

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
)

type SessionStore interface {
	Get(key string, req *http.Request) (*string, error)
	GetAs(key string, v interface{}, req *http.Request) error
	Set(key, value string, rw http.ResponseWriter, req *http.Request) error
	SetValue(key string, value interface{}, rw http.ResponseWriter, req *http.Request) error
	Clear(key string, rw http.ResponseWriter, req *http.Request) error
}

type SecureSessionStore struct {
	SessionName string
	Store       sessions.Store
}

func (s *SecureSessionStore) getSession(req *http.Request) *sessions.Session {
	session, _ := s.Store.Get(req, s.SessionName)
	return session
}

func (s *SecureSessionStore) Get(key string, req *http.Request) (*string, error) {
	val := s.getSession(req).Values[key]
	if val == nil {
		return nil, nil
	}
	strVal, ok := val.(string)
	if !ok {
		return nil, fmt.Errorf("The value is not a string")
	}
	return &strVal, nil
}

func (s *SecureSessionStore) GetAs(key string, v interface{}, req *http.Request) error {
	val, err := s.Get(key, req)
	if err != nil {
		return fmt.Errorf("Cannot deserialize value")
	}
	if val == nil {
		return fmt.Errorf("No value for key")
	}
	err = json.Unmarshal([]byte(*val), v)
	return err
}

func (s *SecureSessionStore) Set(key, value string, rw http.ResponseWriter, req *http.Request) error {
	session := s.getSession(req)
	session.Values[key] = value
	return session.Save(req, rw)
}

func (s *SecureSessionStore) SetValue(key string, value interface{}, rw http.ResponseWriter, req *http.Request) error {
	serialized, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.Set(key, string(serialized), rw, req)
}

func (s *SecureSessionStore) Clear(key string, rw http.ResponseWriter, req *http.Request) error {
	return s.Set(key, "", rw, req)
}

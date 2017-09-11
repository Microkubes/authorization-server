package security

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
)

// SessionStore defines an interface for interacting with the user session.
// This is an abstraction to allow transparent use od cookies-based session or
// session persisted by other mechanisms (database, redis store etc).
type SessionStore interface {
	// Get retrieves a string value from the user session.
	Get(key string, req *http.Request) (*string, error)

	// GetAs retrieves a value from the user session and decodes it to a generic type.
	GetAs(key string, v interface{}, req *http.Request) error

	// Set stores a string value under the provided key in the user session.
	Set(key, value string, rw http.ResponseWriter, req *http.Request) error

	// SetValue stores a user-defined type value in the session. The value is deserialized and then stored.
	SetValue(key string, value interface{}, rw http.ResponseWriter, req *http.Request) error

	// Clear removes the value associated with the key from the user session.
	Clear(key string, rw http.ResponseWriter, req *http.Request) error
}

// SecureSessionStore holds the values for a secure session implementation using
// Go's sessions library.
type SecureSessionStore struct {

	// SessionName is the name of the session store.
	SessionName string

	// Store is the actual sessions.Store.
	Store sessions.Store
}

func (s *SecureSessionStore) getSession(req *http.Request) *sessions.Session {
	session, _ := s.Store.Get(req, s.SessionName)
	return session
}

// Get retrieves a string value from the session.
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

// GetAs retrieves user-defined typed value from the session.
// The value is retireved as JSON string, then deserialized.
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

// Set stores a new value associated with the provided key in the session store.
func (s *SecureSessionStore) Set(key, value string, rw http.ResponseWriter, req *http.Request) error {
	session := s.getSession(req)
	session.Values[key] = value
	return session.Save(req, rw)
}

// SetValue stores a typed value associated with the provided key in the session store.
// The value is serialized to JSON, then stored as string.
func (s *SecureSessionStore) SetValue(key string, value interface{}, rw http.ResponseWriter, req *http.Request) error {
	serialized, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.Set(key, string(serialized), rw, req)
}

// Clear clears the value associated with this key from the session store.
func (s *SecureSessionStore) Clear(key string, rw http.ResponseWriter, req *http.Request) error {
	return s.Set(key, "", rw, req)
}

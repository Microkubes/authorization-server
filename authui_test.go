package main

import (
	"fmt"
	"testing"

	"context"

	"github.com/Microkubes/authorization-server/app/test"
	"github.com/Microkubes/authorization-server/security"
	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-security/oauth2"
	"github.com/keitaroinc/goa"
	"github.com/gorilla/sessions"
)

func TestConfirmAuthorizationAuthUIBadRequest(t *testing.T) {
	service := goa.New("")
	sessionStore := &security.SecureSessionStore{
		SessionName: "TEST-SESSION",
		Store:       sessions.NewCookieStore([]byte("something-very-secret")),
	}
	clientService := &test.DummyClientService{
		Auths:   map[string]*oauth2.ClientAuth{},
		Clients: map[string]*oauth2.Client{},
	}
	authUIController := NewAuthUIController(service, sessionStore, clientService)
	confirmed := true
	_, err := test.ConfirmAuthorizationAuthUIBadRequest(t, context.Background(), service, authUIController, &confirmed)
	if err != nil {
		t.Fatal(err)
	}
}

type ErrDummyClientService struct {
	*test.DummyClientService
}

func (e *ErrDummyClientService) ConfirmClientAuth(a, b string) (*oauth2.ClientAuth, error) {
	return nil, fmt.Errorf("server-error ConfirmClientAuth")
}

func (e *ErrDummyClientService) GetClient(string) (*oauth2.Client, error) {
	return nil, fmt.Errorf("server-error GetClient")
}

func TestConfirmAuthorizationAuthUIInternalServerError(t *testing.T) {
	service := goa.New("")
	sessionStore := test.NewMockSessionStore()

	acd := security.AuthorizeClientData{
		AuthorizeRequest: "/oauth2/authorize?params=params",
		ClientID:         "client-001",
		Confirmed:        true,
	}
	authObj := auth.Auth{
		UserID:   "user-001",
		Username: "testuser",
		Roles:    []string{"user"},
	}

	sessionStore.SetValue("confirmation", acd, nil, nil)

	clientService := &ErrDummyClientService{
		DummyClientService: &test.DummyClientService{
			Auths:   map[string]*oauth2.ClientAuth{},
			Clients: map[string]*oauth2.Client{},
		},
	}
	authUIController := NewAuthUIController(service, sessionStore, clientService)

	confirmed := false
	test.ConfirmAuthorizationAuthUIInternalServerError(t, auth.SetAuth(context.Background(), &authObj), service, authUIController, &confirmed)
}

func TestPromptAuthorizationAuthUIBadRequest(t *testing.T) {
	service := goa.New("")
	sessionStore := test.NewMockSessionStore()

	authUIController := NewAuthUIController(service, sessionStore, &test.DummyClientService{
		Auths:   map[string]*oauth2.ClientAuth{},
		Clients: map[string]*oauth2.Client{},
	})
	test.PromptAuthorizationAuthUIBadRequest(t, context.Background(), service, authUIController)
}

func TestPromptAuthorizationAuthUIInternalServerError(t *testing.T) {
	service := goa.New("")
	sessionStore := test.NewMockSessionStore()

	acd := security.AuthorizeClientData{
		AuthorizeRequest: "/oauth2/authorize?params=params",
		ClientID:         "client-001",
		Confirmed:        true,
	}
	authObj := auth.Auth{
		UserID:   "user-001",
		Username: "testuser",
		Roles:    []string{"user"},
	}

	sessionStore.SetValue("confirmation", acd, nil, nil)
	sessionStore.Set("clientId", "client-001", nil, nil)

	clientService := &ErrDummyClientService{
		DummyClientService: &test.DummyClientService{
			Auths:   map[string]*oauth2.ClientAuth{},
			Clients: map[string]*oauth2.Client{},
		},
	}
	authUIController := NewAuthUIController(service, sessionStore, clientService)

	test.PromptAuthorizationAuthUIInternalServerError(t, auth.SetAuth(context.Background(), &authObj), service, authUIController)

}

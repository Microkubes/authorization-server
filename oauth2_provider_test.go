package main

import (
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/context"

	"github.com/JormungandrK/authorization-server/app"
	"github.com/JormungandrK/authorization-server/app/test"
	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/oauth2"
	"github.com/goadesign/goa"
	oa2 "github.com/goadesign/oauth2"
)

func TestAuthorizeOauth2ProviderBadRequest(t *testing.T) {

	service := goa.New("")
	clientService := &test.DummyClientService{
		Auths:   map[string]*oauth2.ClientAuth{},
		Clients: map[string]*oauth2.Client{},
	}

	tokenService := &test.DummyTokenService{
		Tokens: map[string]*oauth2.AuthToken{},
	}

	sessionStore := test.NewMockSessionStore()

	provider := &oauth2.AuthProvider{}

	clientID := "client-001"
	redirectURI := "http://example.com"
	responseType := "code"
	scope := "api:read"
	state := "xyz"

	controller := NewOauth2ProviderController(service, provider, clientService, tokenService, sessionStore, "/confirm")
	//clientID string, redirectURI *string, responseType string, scope *string, state *string
	test.AuthorizeOauth2ProviderBadRequest(t, context.Background(), service, controller, clientID, &redirectURI, responseType, &scope, &state)
}

func TestAuthorizeOauth2ProviderFound(t *testing.T) {
	service := goa.New("")

	authObj := auth.Auth{
		UserID:   "test-user-001",
		Username: "test-user",
		Roles:    []string{"user"},
	}

	clientService := &test.DummyClientService{
		Auths:   map[string]*oauth2.ClientAuth{},
		Clients: map[string]*oauth2.Client{},
	}

	tokenService := &test.DummyTokenService{
		Tokens: map[string]*oauth2.AuthToken{},
	}

	sessionStore := test.NewMockSessionStore()

	provider := &oauth2.AuthProvider{}

	clientID := "client-001"
	redirectURI := "http://example.com"
	responseType := "code"
	scope := "api:read"
	state := "xyz"

	controller := NewOauth2ProviderController(service, provider, clientService, tokenService, sessionStore, "/confirm")

	test.AuthorizeOauth2ProviderFound(t, auth.SetAuth(context.Background(), &authObj), service, controller, clientID, &redirectURI, responseType, &scope, &state)
}

func TestGetTokenOauth2ProviderBadRequest(t *testing.T) {
	service := goa.New("")

	clientService := &test.DummyClientService{
		Auths:   map[string]*oauth2.ClientAuth{},
		Clients: map[string]*oauth2.Client{},
	}

	tokenService := &test.DummyTokenService{
		Tokens: map[string]*oauth2.AuthToken{},
	}

	sessionStore := test.NewMockSessionStore()

	provider := &oauth2.AuthProvider{}

	controller := NewOauth2ProviderController(service, provider, clientService, tokenService, sessionStore, "/confirm")

	code := "abcde"
	redirectURI := "http://example.com"
	refreshToken := "token-xyz"
	scope := "api:read"

	payload := &app.TokenPayload{
		Code:         &code,
		GrantType:    "authorization_code",
		RedirectURI:  &redirectURI,
		RefreshToken: &refreshToken,
		Scope:        &scope,
	}

	test.GetTokenOauth2ProviderBadRequest(t, context.Background(), service, controller, payload)
}

func TestGetTokenOauth2ProviderOK(t *testing.T) {
	service := goa.New("")

	clientService := &test.DummyClientService{
		Auths: map[string]*oauth2.ClientAuth{
			"client-001-abcde": &oauth2.ClientAuth{
				ClientID:    "client-001",
				Code:        "abcde",
				Confirmed:   true,
				RedirectURI: "http://example.com",
				Scope:       "api:read",
				UserData:    "{\"userId\":\"user-001\"}",
				UserID:      "user-001",
			},
		},
		Clients: map[string]*oauth2.Client{
			"client-001": &oauth2.Client{
				ClientID: "client-001",
				Name:     "client 1",
				Secret:   "password",
				Website:  "http://example.com",
			},
		},
	}

	tokenService := &test.DummyTokenService{
		Tokens: map[string]*oauth2.AuthToken{},
	}

	sessionStore := test.NewMockSessionStore()

	provider := &oauth2.AuthProvider{
		KeyStore:      test.NewDummyKeyStore(),
		ClientService: clientService,
		UserService: &test.DummyUserService{
			Users: map[string]*test.MockUser{},
		},
		SigningMethod:             "RS256",
		AuthCodeLength:            5,
		RefreshTokenLength:        10,
		AccessTokenValidityPeriod: 60000,
		ProviderName:              "UnitTestServer",
		TokenService:              tokenService,
	}

	controller := NewOauth2ProviderController(service, provider, clientService, tokenService, sessionStore, "/confirm")

	code := "abcde"
	redirectURI := "http://example.com"
	scope := "api:read"

	payload := &app.TokenPayload{
		Code:         &code,
		GrantType:    "authorization_code",
		RedirectURI:  &redirectURI,
		RefreshToken: nil,
		Scope:        &scope,
	}

	rr, _ := test.GetTokenOauth2ProviderOK(t, oa2.WithClientID(context.Background(), "client-001"), service, controller, payload)
	data, _ := ioutil.ReadAll(rr.(*httptest.ResponseRecorder).Body)
	fmt.Println("Response: ", string(data))
}

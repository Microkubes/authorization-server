//go:generate goagen bootstrap -d github.com/JormungandrK/authorization-server/design

package main

import (
	"github.com/JormungandrK/authorization-server/app"
	"github.com/JormungandrK/authorization-server/security"
	svc "github.com/JormungandrK/authorization-server/service"
	"github.com/JormungandrK/microservice-security/oauth2"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

func main() {
	// Create service
	service := goa.New("")

	sessionStore := &security.SecureSessionStore{
		SessionName: "OAuth2AuthorizationServer",
		Store:       sessions.NewCookieStore([]byte("super-secret-extra-safe"), securecookie.GenerateRandomKey(32)),
	}

	oauth2Scheme := app.NewOAuth2Security()

	formLoginMiddleware := security.FormLoginMiddleware(&security.FormLoginScheme{
		PostURL:       "/check_credentials",
		LoginURL:      "/login",
		ConfirmURL:    "/auth/authorize-client",
		UsernameField: "username",
		PasswordField: "password",
		CookieSecret:  []byte("secret-key"),
		IgnoreURLs:    []string{"/login", "/oauth/token"},
	}, &svc.DummyUserService{
		Users: map[string]*svc.MockUser{
			"test-user": &svc.MockUser{
				User: oauth2.User{
					ID:            "123456",
					Username:      "test-user",
					Email:         "user@example.com",
					Roles:         []string{"user"},
					Organizations: []string{"org1"},
				},
				Password: "pass",
			},
		},
	}, sessionStore)

	// Mount middleware
	service.Use(middleware.RequestID())
	service.Use(middleware.LogRequest(true))
	service.Use(middleware.ErrorHandler(service, true))
	service.Use(middleware.Recover())
	service.Use(security.NewStoreOAuth2ParamsMiddleware(sessionStore, oauth2Scheme.AuthorizationURL))
	service.Use(formLoginMiddleware)

	// Mount "oauth2_provider" controller
	provider := svc.NewMockOAuth2Provider([]*oauth2.Client{
		&oauth2.Client{
			ClientID:    "test-client-0000000001",
			Name:        "test-client",
			Description: "Test client",
			Website:     "http://localhost:9090",
			Secret:      "super-secret-stuff",
		},
	})
	c := NewOauth2ProviderController(service, provider, provider.ClientService, provider.TokenService, sessionStore)
	app.MountOauth2ProviderController(service, c)

	publicController := NewPublicController(service)
	app.MountPublicController(service, publicController)

	authuiCtrl := NewAuthUIController(service, sessionStore, provider.ClientService)
	app.MountAuthUIController(service, authuiCtrl)

	// Start service
	if err := service.ListenAndServe(":8080"); err != nil {
		service.LogError("startup", "err", err)
	}

}

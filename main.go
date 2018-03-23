//go:generate goagen bootstrap -d github.com/Microkubes/authorization-server/design

package main

import (
	"encoding/base64"
	"net/http"
	"os"

	"github.com/Microkubes/authorization-server/app"
	"github.com/Microkubes/authorization-server/config"
	"github.com/Microkubes/authorization-server/security"
	svc "github.com/Microkubes/authorization-server/service"
	"github.com/Microkubes/microservice-security/oauth2"
	"github.com/Microkubes/microservice-security/tools"
	"github.com/Microkubes/microservice-tools/gateway"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware"
	goaoauth2 "github.com/goadesign/oauth2"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

func main() {
	// Create service
	service := goa.New("")

	serverConfig, err := loadServerConfig()
	if err != nil {
		service.LogError("config", "err", err)
		return
	}

	keyStore, err := tools.NewFileKeyStore(serverConfig.Security.Keys)
	if err != nil {
		panic(err)
	}
	httpClient := &http.Client{}
	// create the access services

	clientService, clientCleanup, err := svc.NewClientService(serverConfig, httpClient, keyStore)
	if err != nil {
		panic(err)
	}
	defer clientCleanup()

	tokenService, tokenCleanup, err := svc.NewTokenService(serverConfig)
	if err != nil {
		panic(err)
	}
	defer tokenCleanup()

	userService, err := svc.NewUserService(serverConfig, httpClient, keyStore)
	if err != nil {
		panic(err)
	}

	authKey, encyptKey, err := loadSessionKeys(&serverConfig.SessionConfig)
	if err != nil {
		panic(err)
	}

	sessionStore := &security.SecureSessionStore{
		SessionName: serverConfig.SessionConfig.SessionName,
		Store:       sessions.NewCookieStore(authKey, encyptKey),
	}

	provider := &oauth2.AuthProvider{
		ClientService:             clientService,
		TokenService:              tokenService,
		UserService:               userService,
		KeyStore:                  keyStore,
		SigningMethod:             serverConfig.AccessTokenSigningMethod,
		AuthCodeLength:            serverConfig.AuthCodeLength,
		RefreshTokenLength:        serverConfig.RefreshTokenLength,
		AccessTokenValidityPeriod: serverConfig.AccessTokenTTL,
		ProviderName:              serverConfig.ServerName,
	}

	gatewayURL := os.Getenv("API_GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://kong:8001"
	}

	registration := gateway.NewKongGateway(gatewayURL, &http.Client{}, &serverConfig.MicroserviceConfig)
	err = registration.SelfRegister()
	if err != nil {
		panic(err)
	}

	defer registration.Unregister()

	oauth2Scheme := app.NewOAuth2Security()

	formLoginMiddleware := security.FormLoginMiddleware(&security.FormLoginScheme{
		PostURL:       "/auth/check_credentials",
		LoginURL:      "/auth/login",
		ConfirmURL:    "/auth/authorize-client",
		EmailField:    "email",
		PasswordField: "password",
		IgnoreURLs:    []string{"/auth/login", "/oauth2/token", "/auth/css/.*", "/auth/js/.*", ".*/favicon.ico"},
	}, userService, sessionStore)

	// Mount middleware
	service.Use(middleware.RequestID())
	service.Use(middleware.LogRequest(true))
	service.Use(middleware.ErrorHandler(service, true))
	service.Use(middleware.Recover())
	service.Use(security.NewStoreOAuth2ParamsMiddleware(sessionStore, oauth2Scheme.AuthorizationURL))
	service.Use(formLoginMiddleware)

	oauth2ClientAuth := goaoauth2.NewOAuth2ClientBasicAuthMiddleware(provider)
	app.UseOauth2ClientBasicAuthMiddleware(service, oauth2ClientAuth)

	c := NewOauth2ProviderController(service, provider, clientService, tokenService, sessionStore, "/auth/authorize-client")
	app.MountOauth2ProviderController(service, c)

	publicController := NewPublicController(service)
	app.MountPublicController(service, publicController)

	authuiCtrl := NewAuthUIController(service, sessionStore, clientService)
	app.MountAuthUIController(service, authuiCtrl)

	loginCtrl := NewLoginController(service, sessionStore)
	app.MountLoginController(service, loginCtrl)

	// Start service
	if err := service.ListenAndServe(":8080"); err != nil {
		service.LogError("startup", "err", err)
	}

}

func loadServerConfig() (*config.ServerConfig, error) {
	confFile := os.Getenv("SERVICE_CONFIG_FILE")
	if confFile == "" {
		confFile = "/run/secrets/microservice_authorization_server_config.json"
	}
	conf, err := config.LoadConfig(confFile)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

func loadSessionKeys(cfg *config.SessionConfig) (authKey []byte, encKey []byte, err error) {
	authKey, err = base64.StdEncoding.DecodeString(cfg.AuthKey)
	if err != nil {
		return nil, nil, err
	}
	if cfg.EncryptKey == "" {
		encKey = securecookie.GenerateRandomKey(32)
	} else {
		encKey, err = base64.StdEncoding.DecodeString(cfg.EncryptKey)
	}
	return authKey, encKey, err
}

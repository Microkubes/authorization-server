package security

import (
	"fmt"
	"net/http"
	"strings"

	"context"

	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/oauth2"
	"github.com/goadesign/goa"
)

type FormLoginScheme struct {
	PostURL       string
	LoginURL      string
	ConfirmURL    string
	UsernameField string
	PasswordField string
	//CookieSecret  []byte
	IgnoreURLs []string
}

type AuthorizeClientData struct {
	AuthorizeRequest string
	ClientID         string
	Confirmed        bool
}

const AUTH_SERVER_SESSION = "OAuth2AuthServer"
const AUTH_USER_DATA = "user"
const AUTH_REDIRECT = "redirect"

var Unauthorized = goa.NewErrorClass("unauthorized", 401)
var Forbidden = goa.NewErrorClass("forbidden", 403)
var ServerError = goa.NewErrorClass("server_error", 500)

func FormLoginMiddleware(scheme *FormLoginScheme, userService oauth2.UserService, sessionStore SessionStore) goa.Middleware {
	fmt.Printf("Session store created")
	return func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			for _, ignoreURL := range scheme.IgnoreURLs {
				if req.URL.Path == ignoreURL {
					fmt.Printf("Ignored URL: %s\n", req.URL.Path)
					return h(ctx, rw, req)
				}
			}
			authObj := getAuth(sessionStore, req)
			if authObj != nil {
				ctx = auth.SetAuth(ctx, authObj)
				if redirect := getRedirectURL(sessionStore, req); redirect != "" {
					clearRedirectURL(sessionStore, req, rw)
					rw.Header().Add("Location", redirect)
					rw.WriteHeader(302)
					return nil
				}
				fmt.Println("Passing through (1)")
				return h(ctx, rw, req)
			}
			// No auth, attempt creating new one
			fmt.Println("Attempting form login")
			sessionStore.Clear("loginError", rw, req)
			ctx, err := attemptFormLogin(ctx, scheme, userService, rw, req)
			if err != nil {
				errorMap := map[string]interface{}{
					"error": err.Error(),
				}
				sessionStore.SetValue("loginError", errorMap, rw, req)
				rw.Header().Add("Location", scheme.LoginURL)
				rw.WriteHeader(302)
				return nil
			}

			if auth.HasAuth(ctx) {
				fmt.Println("Auth created")
				// auth has been successful
				setAuth(auth.GetAuth(ctx), sessionStore, req, rw)
				if redirect := getRedirectURL(sessionStore, req); redirect != "" {
					clearRedirectURL(sessionStore, req, rw)
					rw.Header().Add("Location", redirect)
					rw.WriteHeader(302)
					return nil
				}
				fmt.Println("Passing through (2)")
				return h(ctx, rw, req)
			}
			// auth has not been set, store the Request URL for next redirect and redirect to login
			redirect := fmt.Sprintf("%s?%s", req.URL.Path, req.URL.Query().Encode())
			if err := setRedirectURL(redirect, sessionStore, req, rw); err != nil {
				println("Failed to save session?", err.Error())
			}
			fmt.Printf("Redirect saved: %s\n", redirect)
			rw.Header().Add("Location", scheme.LoginURL)
			rw.WriteHeader(302)
			fmt.Println("Redirecting to login URL:", scheme.LoginURL)
			return nil
		}
	}
}

func getAuth(store SessionStore, req *http.Request) *auth.Auth {
	authObj := auth.Auth{}
	err := store.GetAs(AUTH_USER_DATA, &authObj, req)
	if err != nil {
		return nil
	}
	return &authObj
}

func setAuth(authObj *auth.Auth, store SessionStore, req *http.Request, rw http.ResponseWriter) error {
	return store.SetValue(AUTH_USER_DATA, authObj, rw, req)
}
func clearAuth(store SessionStore, req *http.Request, rw http.ResponseWriter) error {
	return store.Clear(AUTH_USER_DATA, rw, req)
}

func getRedirectURL(store SessionStore, req *http.Request) string {
	redirect, err := store.Get(AUTH_REDIRECT, req)
	if err != nil || redirect == nil {
		return ""
	}
	return *redirect
}

func setRedirectURL(redirect string, store SessionStore, req *http.Request, rw http.ResponseWriter) error {
	return store.Set(AUTH_REDIRECT, redirect, rw, req)
}

func clearRedirectURL(store SessionStore, req *http.Request, rw http.ResponseWriter) error {
	return store.Clear(AUTH_REDIRECT, rw, req)
}

func getUserAuthForCredentials(username, password string, userService oauth2.UserService) (*auth.Auth, error) {
	user, err := userService.VerifyUser(username, password)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	return &auth.Auth{
		UserID:        user.ID,
		Username:      user.Username,
		Roles:         user.Roles,
		Organizations: user.Organizations,
	}, nil
}

func attemptFormLogin(ctx context.Context, scheme *FormLoginScheme, userService oauth2.UserService, rw http.ResponseWriter, req *http.Request) (context.Context, error) {
	if req.Method == "POST" && req.URL.Path == scheme.PostURL {
		// attempt login here
		username := strings.TrimSpace(req.FormValue(scheme.UsernameField))
		password := strings.TrimSpace(req.FormValue(scheme.PasswordField))
		if username == "" || password == "" {
			return ctx, Unauthorized("Credentials required")
		}
		userAuth, err := getUserAuthForCredentials(username, password, userService)
		if err != nil {
			return ctx, ServerError("Server Error", err)
		}
		if userAuth == nil {
			return ctx, Forbidden("Invalid credentials")
		}
		ctx = auth.SetAuth(ctx, userAuth)
		return ctx, nil
	}
	return ctx, nil
}

func NewStoreOAuth2ParamsMiddleware(sessionStore SessionStore, authorizeURL string) goa.Middleware {
	return func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			if req.URL.Path == authorizeURL {
				clientID := req.URL.Query().Get("client_id")
				if clientID != "" {
					sessionStore.Set("clientId", clientID, rw, req)
					println("Client ID set -> ", clientID)
				}
			}
			return h(ctx, rw, req)
		}
	}
}

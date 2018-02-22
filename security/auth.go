package security

import (
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"strings"

	"context"

	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/oauth2"
	"github.com/goadesign/goa"
)

// FormLoginScheme holds the configuration for a Form-based user login and authentication.
// This is used for creating new form-login based authentication Middleware.
type FormLoginScheme struct {
	// PostURL is the URL to which the user credentials are submitted and checked. For example: "/check_credentials".
	PostURL string

	// LoginURL is the URL on which the user is redirected to log in. A login form is displayed. Example: "/login".
	LoginURL string

	ConfirmURL string

	// EmailField is the name of the input field (and POST parameter) for the email user credential.
	EmailField string

	//  PasswordField is the name of the input field (and POST parameter) for the password user credential.
	PasswordField string

	// IgnoreURLs is a list of URLs that are to be ignored by this authentication middleware and are considered public.
	IgnoreURLs []string
}

// AuthorizeClientData holds the data needed for authorization. Usually kept in the session.
// It is used to propery redirect back to the "authorize" OAuth2 action.
type AuthorizeClientData struct {
	// The original authorize request URL (Path+Query params) that the client has made.
	// The client will be redirected here after successful confirmation by the user.
	AuthorizeRequest string

	// ClientID is the client identifier.
	ClientID string

	// Confirmed whether the user confirmed that the client can access the data and can be issued an access token.
	Confirmed bool
}

// SessionUserDataKey session key for the user data
const SessionUserDataKey = "user"

// SessionRedirectKey session key for the redirect URL
const SessionRedirectKey = "redirect"

// Unauthorized is an HTTP error for unauthorized request (an authorization is required).
var Unauthorized = goa.NewErrorClass("unauthorized", 401)

// Forbidden is an HTTP error issued when the authorization does not allow for the client to access the resource.
var Forbidden = goa.NewErrorClass("forbidden", 403)

// ServerError is a generic HTTP server error.
var ServerError = goa.NewErrorClass("server_error", 500)

// BadRequest is a generic bad request error.
var BadRequest = goa.NewErrorClass("bad_request", 400)

// FormLoginMiddleware creates new goa.Middleware for security and form-base authentication.
func FormLoginMiddleware(scheme *FormLoginScheme, userService oauth2.UserService, sessionStore SessionStore) goa.Middleware {
	return func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			for _, ignoreURL := range scheme.IgnoreURLs {
				match, err := regexp.MatchString(ignoreURL, req.URL.Path)
				if err != nil {
					panic(err)
				}
				if match {
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
				return h(ctx, rw, req)
			}
			// No auth, attempt creating new one
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
				// auth has been successful
				setAuth(auth.GetAuth(ctx), sessionStore, req, rw)
				if redirect := getRedirectURL(sessionStore, req); redirect != "" {
					clearRedirectURL(sessionStore, req, rw)
					rw.Header().Add("Location", redirect)
					rw.WriteHeader(302)
					return nil
				}
				return h(ctx, rw, req)
			}
			// auth has not been set, store the Request URL for next redirect and redirect to login
			redirect := fmt.Sprintf("%s?%s", req.URL.Path, req.URL.Query().Encode())
			if err := setRedirectURL(redirect, sessionStore, req, rw); err != nil {
				println("Failed to save session?", err.Error())
			}
			rw.Header().Add("Location", scheme.LoginURL)
			rw.WriteHeader(302)
			return nil
		}
	}
}

func getAuth(store SessionStore, req *http.Request) *auth.Auth {
	authObj := auth.Auth{}
	err := store.GetAs(SessionUserDataKey, &authObj, req)
	if err != nil {
		return nil
	}
	return &authObj
}

func setAuth(authObj *auth.Auth, store SessionStore, req *http.Request, rw http.ResponseWriter) error {
	return store.SetValue(SessionUserDataKey, authObj, rw, req)
}
func clearAuth(store SessionStore, req *http.Request, rw http.ResponseWriter) error {
	return store.Clear(SessionUserDataKey, rw, req)
}

func getRedirectURL(store SessionStore, req *http.Request) string {
	redirect, err := store.Get(SessionRedirectKey, req)
	if err != nil || redirect == nil {
		return ""
	}
	return *redirect
}

func setRedirectURL(redirect string, store SessionStore, req *http.Request, rw http.ResponseWriter) error {
	return store.Set(SessionRedirectKey, redirect, rw, req)
}

func clearRedirectURL(store SessionStore, req *http.Request, rw http.ResponseWriter) error {
	return store.Clear(SessionRedirectKey, rw, req)
}

func getUserAuthForCredentials(email, password string, userService oauth2.UserService) (*auth.Auth, error) {
	user, err := userService.VerifyUser(email, password)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}
	if !user.Active {
		return nil, fmt.Errorf("account-not-activated")
	}

	return &auth.Auth{
		UserID:        user.ID,
		Username:      user.Email,
		Roles:         user.Roles,
		Organizations: user.Organizations,
		Namespaces:    user.Namespaces,
	}, nil
}

func attemptFormLogin(ctx context.Context, scheme *FormLoginScheme, userService oauth2.UserService, rw http.ResponseWriter, req *http.Request) (context.Context, error) {
	if req.Method == "POST" && req.URL.Path == scheme.PostURL {
		// attempt login here
		email := strings.TrimSpace(req.FormValue(scheme.EmailField))
		password := strings.TrimSpace(req.FormValue(scheme.PasswordField))
		if email == "" || password == "" {
			return ctx, Unauthorized("Credentials required")
		}
		if err := validateCredentials(email, password); err != nil {
			return ctx, BadRequest(err)
		}
		userAuth, err := getUserAuthForCredentials(email, password, userService)
		if err != nil {
			if err.Error() == "account-not-activated" {
				return ctx, BadRequest(err)
			}
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

func validateCredentials(email, pass string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("You have entered invalid email")
	}
	if len(pass) < 6 {
		return fmt.Errorf("yuo've entered invalid password")
	}
	return nil
}

// NewStoreOAuth2ParamsMiddleware creates goa.Middleware that stores the clientID in session.
func NewStoreOAuth2ParamsMiddleware(sessionStore SessionStore, authorizeURL string) goa.Middleware {
	return func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			if req.URL.Path == authorizeURL {
				clientID := req.URL.Query().Get("client_id")
				if clientID != "" {
					sessionStore.Set("clientId", clientID, rw, req)
				}
			}
			return h(ctx, rw, req)
		}
	}
}

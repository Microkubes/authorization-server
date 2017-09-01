package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"context"

	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/oauth2"
	"github.com/goadesign/goa"
	"github.com/gorilla/sessions"
)

type FormLoginScheme struct {
	PostURL       string
	LoginURL      string
	UsernameField string
	PasswordField string
	CookieSecret  []byte
	IgnoreURLs    []string
}

const AUTH_SERVER_SESSION = "OAuth2AuthServer"
const AUTH_USER_DATA = "user"
const AUTH_REDIRECT = "redirect"

var Unauthorized = goa.NewErrorClass("unauthorized", 401)
var Forbidden = goa.NewErrorClass("forbidden", 403)
var ServerError = goa.NewErrorClass("server_error", 500)

func FormLoginMiddleware(scheme *FormLoginScheme, userService oauth2.UserService) goa.Middleware {
	sessionStore := sessions.NewCookieStore(scheme.CookieSecret)
	fmt.Printf("Session store created")
	return func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			for _, ignoreURL := range scheme.IgnoreURLs {
				if req.URL.Path == ignoreURL {
					fmt.Printf("Ignored URL: %s", req.URL.Path)
					return h(ctx, rw, req)
				}
			}
			authObj := getAuth(sessionStore, req)
			if authObj != nil {
				fmt.Println("Auth object in session")
				// check redirect
				if redirect := getRedirectURL(sessionStore, req); redirect != "" {
					fmt.Printf("Redirect URL: %s\n", redirect)
					clearRedirectURL(sessionStore, req, rw)
					rw.Header().Add("Location", redirect)
					rw.WriteHeader(302)

					return nil
				}
				fmt.Println("Proceeding with flow")
				// proceed with flow otherwise
				ctx = auth.SetAuth(ctx, authObj)
				return h(ctx, rw, req)
			}
			// No auth, attempt creating new one
			fmt.Println("Attempting form login")
			ctx, err := attemptFormLogin(ctx, scheme, userService, rw, req)
			if err != nil {
				return err
			}
			if auth.HasAuth(ctx) {
				fmt.Println("Auth created")
				// auth has been successful
				setAuth(auth.GetAuth(ctx), sessionStore, req, rw)
				// check redirect
				if redirect := getRedirectURL(sessionStore, req); redirect != "" {
					fmt.Printf("Redirect URL: %s\n", redirect)
					clearRedirectURL(sessionStore, req, rw)
					rw.Header().Add("Location", redirect)
					rw.WriteHeader(302)

					return nil
				}
				fmt.Println("No redirect, proceeding with flow.")
				// if no redirect, proceed with flow
				return h(ctx, rw, req)
			}
			// auth has not been set, store the Request URL for next redirect and redirect to login
			redirect := fmt.Sprintf("%s?%s", req.URL.Path, req.URL.Query().Encode())
			setRedirectURL(redirect, sessionStore, req, rw)
			fmt.Printf("Redirect saved: %s\n", redirect)
			rw.Header().Add("Location", scheme.LoginURL)
			rw.WriteHeader(302)
			fmt.Println("Redirecting to login URL:", scheme.LoginURL)
			return nil
		}
	}
}

func getSession(store sessions.Store, req *http.Request) *sessions.Session {
	session, err := store.Get(req, AUTH_SERVER_SESSION)
	if err != nil {
		fmt.Println("Error while getting session: ", err)
	}
	return session
}

func getAuth(store sessions.Store, req *http.Request) *auth.Auth {
	session := getSession(store, req)
	userData, ok := session.Values[AUTH_USER_DATA]
	println("User data ->", userData, ok)
	fmt.Printf("Session values: %v", session.Values)
	if !ok {
		return nil
	}
	if userData.(string) == "" {
		return nil
	}
	authObj := &auth.Auth{}
	json.Unmarshal([]byte(userData.(string)), authObj)
	return authObj
}

func setAuth(authObj *auth.Auth, store sessions.Store, req *http.Request, rw http.ResponseWriter) error {
	session := getSession(store, req)
	authData, err := json.Marshal(*authObj)
	fmt.Printf("Auth saved -> %s\n", authData)
	if err != nil {
		return err
	}
	session.Values[AUTH_USER_DATA] = string(authData)
	return session.Save(req, rw)
}
func clearAuth(store sessions.Store, req *http.Request, rw http.ResponseWriter) error {
	session := getSession(store, req)
	session.Values[AUTH_USER_DATA] = ""
	return session.Save(req, rw)
}

func getRedirectURL(store sessions.Store, req *http.Request) string {
	session := getSession(store, req)
	redirect, ok := session.Values[AUTH_REDIRECT]
	if !ok {
		return ""
	}
	return redirect.(string)
}

func setRedirectURL(redirect string, store sessions.Store, req *http.Request, rw http.ResponseWriter) error {
	session := getSession(store, req)
	session.Values[AUTH_REDIRECT] = redirect
	return session.Save(req, rw)
}

func clearRedirectURL(store sessions.Store, req *http.Request, rw http.ResponseWriter) error {
	session := getSession(store, req)
	session.Values[AUTH_REDIRECT] = ""
	return session.Save(req, rw)
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

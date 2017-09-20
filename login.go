package main

import (
	"html/template"
	"io/ioutil"

	"github.com/JormungandrK/authorization-server/app"
	"github.com/JormungandrK/authorization-server/security"
	"github.com/goadesign/goa"
)

// LoginController implements the login resource.
type LoginController struct {
	*goa.Controller
	security.SessionStore
}

// NewLoginController creates a login controller.
func NewLoginController(service *goa.Service, sessionStore security.SessionStore) *LoginController {
	return &LoginController{
		Controller:   service.NewController("LoginController"),
		SessionStore: sessionStore,
	}
}

// ShowLogin runs the showLogin action.
func (c *LoginController) ShowLogin(ctx *app.ShowLoginLoginContext) error {
	// LoginController_ShowLogin: start_implement
	loginError := map[string]interface{}{}
	c.SessionStore.GetAs("loginError", &loginError, ctx.Request)

	templateContent, err := ioutil.ReadFile("public/login/login-form.html")
	if err != nil {
		return ctx.InternalServerError(err)
	}

	t, err := template.New("login-form").Parse(string(templateContent))
	if err != nil {
		return ctx.InternalServerError(err)
	}

	responseCode := 200

	if loginErrorCode, ok := loginError["code"]; ok {
		responseCode = loginErrorCode.(int)
	}

	rw := ctx.ResponseWriter

	rw.Header().Set("Content-Type", "text/html")
	err = t.Execute(rw, loginError)
	rw.WriteHeader(responseCode)
	if err != nil {
		println(err.Error())
	}
	// LoginController_ShowLogin: end_implement
	return nil
}

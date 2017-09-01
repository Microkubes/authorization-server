package design

import (
	. "github.com/goadesign/goa/design"
	. "github.com/goadesign/goa/design/apidsl"
	. "github.com/goadesign/oauth2/design"
)

var OAuth2Sec = OAuth2("/oauth2/authorize", "/oauth2/token", func() {
	Scope("api:read")
	Scope("api:write")
})

var _ = Resource("public", func() {
	Origin("*", func() {
		Methods("GET")
	})
	Files("/login", "public/login/login-form.html")
})

// Code generated by goagen v1.3.0, DO NOT EDIT.
//
// unnamed API: oauth2_provider TestHelpers
//
// Command:
// $ goagen
// --design=github.com/JormungandrK/authorization-server/design
// --out=$(GOPATH)/src/github.com/JormungandrK/authorization-server
// --version=v1.2.0-dirty

package test

import (
	"bytes"
	"context"
	"fmt"
	"github.com/JormungandrK/authorization-server/app"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/goatest"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
)

// AuthorizeOauth2ProviderBadRequest runs the method Authorize of the given controller with the given parameters.
// It returns the response writer so it's possible to inspect the response headers and the media type struct written to the response.
// If ctx is nil then context.Background() is used.
// If service is nil then a default service is created.
func AuthorizeOauth2ProviderBadRequest(t goatest.TInterface, ctx context.Context, service *goa.Service, ctrl app.Oauth2ProviderController, clientID string, redirectURI *string, responseType string, scope *string, state *string) (http.ResponseWriter, *app.OAuth2ErrorMedia) {
	// Setup service
	var (
		logBuf bytes.Buffer
		resp   interface{}

		respSetter goatest.ResponseSetterFunc = func(r interface{}) { resp = r }
	)
	if service == nil {
		service = goatest.Service(&logBuf, respSetter)
	} else {
		logger := log.New(&logBuf, "", log.Ltime)
		service.WithLogger(goa.NewLogger(logger))
		newEncoder := func(io.Writer) goa.Encoder { return respSetter }
		service.Encoder = goa.NewHTTPEncoder() // Make sure the code ends up using this decoder
		service.Encoder.Register(newEncoder, "*/*")
	}

	// Setup request context
	rw := httptest.NewRecorder()
	query := url.Values{}
	{
		sliceVal := []string{clientID}
		query["client_id"] = sliceVal
	}
	if redirectURI != nil {
		sliceVal := []string{*redirectURI}
		query["redirect_uri"] = sliceVal
	}
	{
		sliceVal := []string{responseType}
		query["response_type"] = sliceVal
	}
	if scope != nil {
		sliceVal := []string{*scope}
		query["scope"] = sliceVal
	}
	if state != nil {
		sliceVal := []string{*state}
		query["state"] = sliceVal
	}
	u := &url.URL{
		Path:     fmt.Sprintf("/oauth2/authorize"),
		RawQuery: query.Encode(),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}
	prms := url.Values{}
	{
		sliceVal := []string{clientID}
		prms["client_id"] = sliceVal
	}
	if redirectURI != nil {
		sliceVal := []string{*redirectURI}
		prms["redirect_uri"] = sliceVal
	}
	{
		sliceVal := []string{responseType}
		prms["response_type"] = sliceVal
	}
	if scope != nil {
		sliceVal := []string{*scope}
		prms["scope"] = sliceVal
	}
	if state != nil {
		sliceVal := []string{*state}
		prms["state"] = sliceVal
	}
	if ctx == nil {
		ctx = context.Background()
	}
	goaCtx := goa.NewContext(goa.WithAction(ctx, "Oauth2ProviderTest"), rw, req, prms)
	authorizeCtx, _err := app.NewAuthorizeOauth2ProviderContext(goaCtx, req, service)
	if _err != nil {
		panic("invalid test data " + _err.Error()) // bug
	}

	// Perform action
	_err = ctrl.Authorize(authorizeCtx)

	// Validate response
	if _err != nil {
		t.Fatalf("controller returned %+v, logs:\n%s", _err, logBuf.String())
	}
	if rw.Code != 400 {
		t.Errorf("invalid response status code: got %+v, expected 400", rw.Code)
	}
	var mt *app.OAuth2ErrorMedia
	if resp != nil {
		var ok bool
		mt, ok = resp.(*app.OAuth2ErrorMedia)
		if !ok {
			t.Fatalf("invalid response media: got variable of type %T, value %+v, expected instance of app.OAuth2ErrorMedia", resp, resp)
		}
		_err = mt.Validate()
		if _err != nil {
			t.Errorf("invalid response media type: %s", _err)
		}
	}

	// Return results
	return rw, mt
}

// AuthorizeOauth2ProviderFound runs the method Authorize of the given controller with the given parameters.
// It returns the response writer so it's possible to inspect the response headers.
// If ctx is nil then context.Background() is used.
// If service is nil then a default service is created.
func AuthorizeOauth2ProviderFound(t goatest.TInterface, ctx context.Context, service *goa.Service, ctrl app.Oauth2ProviderController, clientID string, redirectURI *string, responseType string, scope *string, state *string) http.ResponseWriter {
	// Setup service
	var (
		logBuf bytes.Buffer
		resp   interface{}

		respSetter goatest.ResponseSetterFunc = func(r interface{}) { resp = r }
	)
	if service == nil {
		service = goatest.Service(&logBuf, respSetter)
	} else {
		logger := log.New(&logBuf, "", log.Ltime)
		service.WithLogger(goa.NewLogger(logger))
		newEncoder := func(io.Writer) goa.Encoder { return respSetter }
		service.Encoder = goa.NewHTTPEncoder() // Make sure the code ends up using this decoder
		service.Encoder.Register(newEncoder, "*/*")
	}

	// Setup request context
	rw := httptest.NewRecorder()
	query := url.Values{}
	{
		sliceVal := []string{clientID}
		query["client_id"] = sliceVal
	}
	if redirectURI != nil {
		sliceVal := []string{*redirectURI}
		query["redirect_uri"] = sliceVal
	}
	{
		sliceVal := []string{responseType}
		query["response_type"] = sliceVal
	}
	if scope != nil {
		sliceVal := []string{*scope}
		query["scope"] = sliceVal
	}
	if state != nil {
		sliceVal := []string{*state}
		query["state"] = sliceVal
	}
	u := &url.URL{
		Path:     fmt.Sprintf("/oauth2/authorize"),
		RawQuery: query.Encode(),
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		panic("invalid test " + err.Error()) // bug
	}
	prms := url.Values{}
	{
		sliceVal := []string{clientID}
		prms["client_id"] = sliceVal
	}
	if redirectURI != nil {
		sliceVal := []string{*redirectURI}
		prms["redirect_uri"] = sliceVal
	}
	{
		sliceVal := []string{responseType}
		prms["response_type"] = sliceVal
	}
	if scope != nil {
		sliceVal := []string{*scope}
		prms["scope"] = sliceVal
	}
	if state != nil {
		sliceVal := []string{*state}
		prms["state"] = sliceVal
	}
	if ctx == nil {
		ctx = context.Background()
	}
	goaCtx := goa.NewContext(goa.WithAction(ctx, "Oauth2ProviderTest"), rw, req, prms)
	authorizeCtx, _err := app.NewAuthorizeOauth2ProviderContext(goaCtx, req, service)
	if _err != nil {
		panic("invalid test data " + _err.Error()) // bug
	}

	// Perform action
	_err = ctrl.Authorize(authorizeCtx)

	// Validate response
	if _err != nil {
		t.Fatalf("controller returned %+v, logs:\n%s", _err, logBuf.String())
	}
	if rw.Code != 302 {
		t.Errorf("invalid response status code: got %+v, expected 302", rw.Code)
	}

	// Return results
	return rw
}

// GetTokenOauth2ProviderBadRequest runs the method GetToken of the given controller with the given parameters and payload.
// It returns the response writer so it's possible to inspect the response headers and the media type struct written to the response.
// If ctx is nil then context.Background() is used.
// If service is nil then a default service is created.
func GetTokenOauth2ProviderBadRequest(t goatest.TInterface, ctx context.Context, service *goa.Service, ctrl app.Oauth2ProviderController, payload *app.TokenPayload) (http.ResponseWriter, *app.OAuth2ErrorMedia) {
	// Setup service
	var (
		logBuf bytes.Buffer
		resp   interface{}

		respSetter goatest.ResponseSetterFunc = func(r interface{}) { resp = r }
	)
	if service == nil {
		service = goatest.Service(&logBuf, respSetter)
	} else {
		logger := log.New(&logBuf, "", log.Ltime)
		service.WithLogger(goa.NewLogger(logger))
		newEncoder := func(io.Writer) goa.Encoder { return respSetter }
		service.Encoder = goa.NewHTTPEncoder() // Make sure the code ends up using this decoder
		service.Encoder.Register(newEncoder, "*/*")
	}

	// Validate payload
	err := payload.Validate()
	if err != nil {
		e, ok := err.(goa.ServiceError)
		if !ok {
			panic(err) // bug
		}
		t.Errorf("unexpected payload validation error: %+v", e)
		return nil, nil
	}

	// Setup request context
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf("/oauth2/token"),
	}
	req, _err := http.NewRequest("POST", u.String(), nil)
	if _err != nil {
		panic("invalid test " + _err.Error()) // bug
	}
	prms := url.Values{}
	if ctx == nil {
		ctx = context.Background()
	}
	goaCtx := goa.NewContext(goa.WithAction(ctx, "Oauth2ProviderTest"), rw, req, prms)
	getTokenCtx, __err := app.NewGetTokenOauth2ProviderContext(goaCtx, req, service)
	if __err != nil {
		panic("invalid test data " + __err.Error()) // bug
	}
	getTokenCtx.Payload = payload

	// Perform action
	__err = ctrl.GetToken(getTokenCtx)

	// Validate response
	if __err != nil {
		t.Fatalf("controller returned %+v, logs:\n%s", __err, logBuf.String())
	}
	if rw.Code != 400 {
		t.Errorf("invalid response status code: got %+v, expected 400", rw.Code)
	}
	var mt *app.OAuth2ErrorMedia
	if resp != nil {
		var _ok bool
		mt, _ok = resp.(*app.OAuth2ErrorMedia)
		if !_ok {
			t.Fatalf("invalid response media: got variable of type %T, value %+v, expected instance of app.OAuth2ErrorMedia", resp, resp)
		}
		__err = mt.Validate()
		if __err != nil {
			t.Errorf("invalid response media type: %s", __err)
		}
	}

	// Return results
	return rw, mt
}

// GetTokenOauth2ProviderOK runs the method GetToken of the given controller with the given parameters and payload.
// It returns the response writer so it's possible to inspect the response headers and the media type struct written to the response.
// If ctx is nil then context.Background() is used.
// If service is nil then a default service is created.
func GetTokenOauth2ProviderOK(t goatest.TInterface, ctx context.Context, service *goa.Service, ctrl app.Oauth2ProviderController, payload *app.TokenPayload) (http.ResponseWriter, *app.TokenMedia) {
	// Setup service
	var (
		logBuf bytes.Buffer
		resp   interface{}

		respSetter goatest.ResponseSetterFunc = func(r interface{}) { resp = r }
	)
	if service == nil {
		service = goatest.Service(&logBuf, respSetter)
	} else {
		logger := log.New(&logBuf, "", log.Ltime)
		service.WithLogger(goa.NewLogger(logger))
		newEncoder := func(io.Writer) goa.Encoder { return respSetter }
		service.Encoder = goa.NewHTTPEncoder() // Make sure the code ends up using this decoder
		service.Encoder.Register(newEncoder, "*/*")
	}

	// Validate payload
	err := payload.Validate()
	if err != nil {
		e, ok := err.(goa.ServiceError)
		if !ok {
			panic(err) // bug
		}
		t.Errorf("unexpected payload validation error: %+v", e)
		return nil, nil
	}

	// Setup request context
	rw := httptest.NewRecorder()
	u := &url.URL{
		Path: fmt.Sprintf("/oauth2/token"),
	}
	req, _err := http.NewRequest("POST", u.String(), nil)
	if _err != nil {
		panic("invalid test " + _err.Error()) // bug
	}
	prms := url.Values{}
	if ctx == nil {
		ctx = context.Background()
	}
	goaCtx := goa.NewContext(goa.WithAction(ctx, "Oauth2ProviderTest"), rw, req, prms)
	getTokenCtx, __err := app.NewGetTokenOauth2ProviderContext(goaCtx, req, service)
	if __err != nil {
		panic("invalid test data " + __err.Error()) // bug
	}
	getTokenCtx.Payload = payload

	// Perform action
	__err = ctrl.GetToken(getTokenCtx)

	// Validate response
	if __err != nil {
		t.Fatalf("controller returned %+v, logs:\n%s", __err, logBuf.String())
	}
	if rw.Code != 200 {
		t.Errorf("invalid response status code: got %+v, expected 200", rw.Code)
	}
	var mt *app.TokenMedia
	if resp != nil {
		var _ok bool
		mt, _ok = resp.(*app.TokenMedia)
		if !_ok {
			t.Fatalf("invalid response media: got variable of type %T, value %+v, expected instance of app.TokenMedia", resp, resp)
		}
		__err = mt.Validate()
		if __err != nil {
			t.Errorf("invalid response media type: %s", __err)
		}
	}

	// Return results
	return rw, mt
}
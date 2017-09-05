package service

import (
	"fmt"
	"io"
	"net/http"

	"github.com/JormungandrK/microservice-security/jwt"
	"github.com/afex/hystrix-go/hystrix"
)

type Signature struct {
	SigningMethod string
	Key           interface{}
	Claims        map[string]interface{}
}

func NewSignedRequest(method string, urlStr string, body io.Reader, signature Signature) (*http.Request, error) {
	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err
	}
	signedString, err := jwt.SignToken(signature.Claims, signature.SigningMethod, signature.Key)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", signedString))
	return req, err
}

func ExecRequest(action string, req *http.Request, client *http.Client) (*http.Response, error) {
	var resp *http.Response
	hystrix.Do(action, func() error {
		r, e := client.Do(req)
		if e != nil {
			return e
		}
		resp = r
		return nil
	}, nil)
	return resp, nil
}

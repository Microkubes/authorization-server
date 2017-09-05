package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/JormungandrK/microservice-security/oauth2"
)

type UserServiceAPI struct {
	ServiceURL string
	*http.Client
	Signature
}

func (u *UserServiceAPI) VerifyUser(username, password string) (*oauth2.User, error) {
	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)
	req, err := NewSignedRequest("POST", "verify", strings.NewReader(form.Encode()), u.Signature)
	if err != nil {
		return nil, err
	}
	resp, err := ExecRequest("user-microservice", req, u.Client)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(resp.Status)
	}
	user := oauth2.User{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

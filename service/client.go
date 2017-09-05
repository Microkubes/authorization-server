package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/JormungandrK/authorization-server/db"
	"github.com/JormungandrK/microservice-security/oauth2"
)

type ClientServiceAPI struct {
	ServiceURL string
	*http.Client
	Signature
	db.ClientAuthRepository
}

func (c *ClientServiceAPI) getURL(path string) string {
	return fmt.Sprintf("%s/%s", c.ServiceURL, path)
}

func (c *ClientServiceAPI) GetClient(clientID string) (*oauth2.Client, error) {
	req, err := NewSignedRequest("GET", c.getURL(fmt.Sprintf("app/%s", clientID)), nil, c.Signature)
	if err != nil {
		return nil, err
	}
	resp, err := ExecRequest("microservice-apps", req, c.Client)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(resp.Status)
	}
	client := oauth2.Client{}
	err = json.NewDecoder(resp.Body).Decode(&client)
	return &client, err
}

func (c *ClientServiceAPI) VerifyClientCredentials(clientID, clientSecret string) (*oauth2.Client, error) {
	form := url.Values{}
	form.Add("client_id", clientID)
	form.Add("client_secret", clientSecret)

	req, err := NewSignedRequest("POST", c.getURL("verify"), strings.NewReader(form.Encode()), c.Signature)
	if err != nil {
		return nil, err
	}

	resp, err := ExecRequest("microservice-apps", req, c.Client)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(resp.Status)
	}
	client := oauth2.Client{}
	err = json.NewDecoder(resp.Body).Decode(&client)
	return &client, err
}
func (c *ClientServiceAPI) SaveClientAuth(clientAuth *oauth2.ClientAuth) error {
	_, err := c.ClientAuthRepository.Save(clientAuth)
	return err
}
func (c *ClientServiceAPI) GetClientAuth(clientID, code string) (*oauth2.ClientAuth, error) {
	return c.ClientAuthRepository.GetWithCode(clientID, code)
}
func (c *ClientServiceAPI) GetClientAuthForUser(userID, clientID string) (*oauth2.ClientAuth, error) {
	return c.ClientAuthRepository.GetWithUserID(clientID, userID)
}
func (c *ClientServiceAPI) ConfirmClientAuth(userID, clientID string) (*oauth2.ClientAuth, error) {
	ca, err := c.ClientAuthRepository.GetWithUserID(clientID, userID)
	if err != nil {
		return nil, err
	}
	if ca == nil {
		return nil, fmt.Errorf("No client auth")
	}
	ca.Confirmed = true
	return c.ClientAuthRepository.Save(ca)
}
func (c *ClientServiceAPI) UpdateUserData(clientID, code, userID, userData string) error {
	ca, err := c.ClientAuthRepository.GetWithUserID(clientID, userID)
	if err != nil {
		return err
	}
	if ca == nil {
		return fmt.Errorf("No client auth")
	}
	ca.UserData = userData
	ca.UserID = userID
	_, err = c.ClientAuthRepository.Save(ca)
	return err
}
func (c *ClientServiceAPI) DeleteClientAuth(clientID, code string) error {
	return c.ClientAuthRepository.Delete(clientID, code)
}

package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JormungandrK/authorization-server/config"
	"github.com/JormungandrK/authorization-server/db"
	"github.com/JormungandrK/jwt-issuer/store"
	"github.com/JormungandrK/microservice-security/oauth2"
	uuid "github.com/satori/go.uuid"
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

func NewClientService(serverConfig *config.ServerConfig, client *http.Client, keyStore store.KeyStore) (*ClientServiceAPI, func(), error) {
	signature, err := NewClientSignature(serverConfig.ServerName, serverConfig.Security, keyStore)
	if err != nil {
		return nil, nil, err
	}

	dbc := serverConfig.DBConfig

	clientRepository, cleanup, err := db.NewDBClientAuthRepository(dbc.Host,
		dbc.DatabaseName,
		dbc.Username,
		dbc.Password,
		time.Duration(serverConfig.ClientAuthorizationTTL)*time.Millisecond)

	if err != nil {
		return nil, nil, err
	}

	clientAPI := ClientServiceAPI{
		ServiceURL:           serverConfig.ServicesEndpoints.AppsServiceURL,
		Signature:            *signature,
		Client:               client,
		ClientAuthRepository: clientRepository,
	}
	return &clientAPI, cleanup, nil
}

func NewClientSignature(serverName string, securityConf config.Security, keyStore store.KeyStore) (*Signature, error) {
	claims := map[string]interface{}{
		"userId":   "system",
		"username": "system",
		"roles":    []string{"system"},
		"iss":      serverName,
		"sub":      "oauth2-auth-server",
		"jti":      uuid.NewV4().String(),
		"nbf":      0,
		"exp":      time.Now().Add(time.Duration(30 * time.Second)).Unix(),
		"iat":      time.Now().Unix(),
	}
	systemKey, err := keyStore.GetPrivateKeyByName("system")
	if err != nil {
		return nil, err
	}
	return &Signature{
		Claims:        claims,
		Key:           systemKey,
		SigningMethod: securityConf.SigningMethod,
	}, nil
}

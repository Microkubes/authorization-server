package service

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/JormungandrK/microservice-security/oauth2"
)

type DummyClientService struct {
	Clients map[string]*oauth2.Client
	Auths   map[string]*oauth2.ClientAuth
}

func (d *DummyClientService) GetClient(clientID string) (*oauth2.Client, error) {
	cl, ok := d.Clients[clientID]
	if !ok {
		return nil, fmt.Errorf("Not found")
	}
	return cl, nil
}

func (d *DummyClientService) VerifyClientCredentials(clientID, clientSecret string) (*oauth2.Client, error) {
	cl, ok := d.Clients[clientID]
	if !ok {
		return nil, fmt.Errorf("Invalid credentials")
	}
	if cl.Secret != clientSecret {
		return nil, nil
	}
	return cl, nil
}

func (d *DummyClientService) SaveClientAuth(clientAuth *oauth2.ClientAuth) error {
	key := fmt.Sprintf("%s-%s", clientAuth.ClientID, clientAuth.Code)
	d.Auths[key] = clientAuth

	return nil
}

func (d *DummyClientService) GetClientAuth(clientID, code string) (*oauth2.ClientAuth, error) {
	key := fmt.Sprintf("%s-%s", clientID, code)
	ca, _ := d.Auths[key]
	return ca, nil
}

func (d *DummyClientService) UpdateUserData(clientID, code, userData string) error {
	key := fmt.Sprintf("%s-%s", clientID, code)
	ca, ok := d.Auths[key]
	if !ok {
		return fmt.Errorf("No such authentication")
	}
	ca.UserData = userData
	return nil
}

func (d *DummyClientService) DeleteClientAuth(clientID, code string) error {
	key := fmt.Sprintf("%s-%s", clientID, code)
	_, ok := d.Auths[key]
	if ok {
		d.Auths[key] = nil
	}
	return nil
}

func NewMockClientService() *DummyClientService {
	return &DummyClientService{
		Clients: map[string]*oauth2.Client{},
		Auths:   map[string]*oauth2.ClientAuth{},
	}
}

type DummyTokenService struct {
	Tokens map[string]*oauth2.OAuth2Token
}

func (d *DummyTokenService) SaveToken(token oauth2.OAuth2Token) error {
	d.Tokens[token.RefreshToken] = &token
	return nil
}

func (d *DummyTokenService) GetToken(refreshToken string) (*oauth2.OAuth2Token, error) {
	if token, ok := d.Tokens[refreshToken]; ok {
		return token, nil
	}
	return nil, nil
}

type DummyKeyStore struct {
	PrivateKey interface{}
}

// GetPrivateKey returns the default private key used for signing.
func (d *DummyKeyStore) GetPrivateKey() (interface{}, error) {
	if d.PrivateKey == nil {
		return nil, fmt.Errorf("No default key")
	}
	return d.PrivateKey, nil
}

// GetPrivateKeyByName gets a private key by name
func (d *DummyKeyStore) GetPrivateKeyByName(keyName string) (interface{}, error) {
	if d.PrivateKey == nil {
		return nil, fmt.Errorf("No default key")
	}
	if keyName != "default" {
		return nil, fmt.Errorf("No key with that name")
	}
	return d.PrivateKey, nil
}

func NewDummyKeyStore() *DummyKeyStore {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &DummyKeyStore{
		PrivateKey: key,
	}
}

func NewMockOAuth2Provider(clients []*oauth2.Client) *oauth2.OAuth2Provider {
	cs := NewMockClientService()
	for _, client := range clients {
		cs.Clients[client.ClientID] = client
	}
	return &oauth2.OAuth2Provider{
		ClientService: cs,
		TokenService: &DummyTokenService{
			Tokens: map[string]*oauth2.OAuth2Token{},
		},
		KeyStore:                  NewDummyKeyStore(),
		SigningMethod:             "RS512",
		AuthCodeLength:            10,
		RefreshTokenLength:        30,
		AccessTokenValidityPeriod: 3600 * 1000,
	}
}

type MockUser struct {
	oauth2.User
	Password string
}

type DummyUserService struct {
	Users map[string]*MockUser
}

func (d *DummyUserService) VerifyUser(username, password string) (*oauth2.User, error) {
	if user, ok := d.Users[username]; ok {
		if user.Password == password {
			return &user.User, nil
		}
	}
	return nil, nil
}

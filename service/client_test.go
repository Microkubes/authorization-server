package service

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	"github.com/JormungandrK/authorization-server/config"
	"github.com/JormungandrK/microservice-security/oauth2"
	gock "gopkg.in/h2non/gock.v1"
)

type DummyClientAuthRepo struct {
	Auths map[string][]*oauth2.ClientAuth
}

func (d *DummyClientAuthRepo) GetWithCode(clientID, code string) (*oauth2.ClientAuth, error) {
	auths := d.getforClientID(clientID)
	for _, auth := range auths {
		if auth.Code == code {
			return auth, nil
		}
	}
	return nil, nil
}

func (d *DummyClientAuthRepo) getforClientID(clientID string) []*oauth2.ClientAuth {
	auths, ok := d.Auths[clientID]
	if !ok {
		auths = []*oauth2.ClientAuth{}
		d.Auths[clientID] = auths
	}
	return auths
}

func (d *DummyClientAuthRepo) GetWithUserID(clientID, userID string) (*oauth2.ClientAuth, error) {
	auths := d.getforClientID(clientID)
	for _, auth := range auths {
		if auth.UserID == userID {
			return auth, nil
		}
	}
	return nil, nil
}

func (d *DummyClientAuthRepo) Save(clientAuth *oauth2.ClientAuth) (*oauth2.ClientAuth, error) {
	auths := d.getforClientID(clientAuth.ClientID)
	for i, auth := range auths {
		if auth.Code == clientAuth.ClientID {
			auths[i] = clientAuth
			return clientAuth, nil
		}
	}
	return clientAuth, nil
}

func (d *DummyClientAuthRepo) Delete(clientID, code string) error {
	auths := d.getforClientID(clientID)
	idx := -1
	for i, auth := range auths {
		if auth.Code == code {
			idx = i
		}
	}
	println("idx=", idx)
	if idx >= 0 {
		if idx == 0 {
			d.Auths[clientID] = auths[1:]
		} else if idx == (len(auths) - 1) {
			d.Auths[clientID] = auths[0 : len(auths)-1]
		} else {
			deleted := []*oauth2.ClientAuth{}
			deleted = append(deleted, auths[0:idx-1]...)
			deleted = append(deleted, auths[idx:]...)
			d.Auths[clientID] = deleted
		}
	}
	return nil
}

func NewFormMatcher(matcher gock.MatchFunc) gock.Matcher {
	return &gock.MockMatcher{
		Matchers: []gock.MatchFunc{matcher},
	}

}

func TestGetClient(t *testing.T) {
	defer gock.Off()

	httpClient := &http.Client{}

	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	gock.New("http://example.com:8080/apps").
		Get("/client-001").
		Reply(200).
		JSON(map[string]interface{}{
			"id":          "client-001",
			"name":        "TestClient",
			"description": "ClientDescription",
			"owner":       "user-0001",
			"website":     "http://client.example.com:9090",
		})

	csAPI := &ClientServiceAPI{
		ServiceURL: "http://example.com:8080/apps",
		Client:     httpClient,
		Signature: Signature{
			Claims: map[string]interface{}{
				"userId": "test",
			},
			Key:           rsaPrivKey,
			SigningMethod: "RS256",
		},
	}

	client, err := csAPI.GetClient("client-001")
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("Expected to get a client")
	}

}

func TestVerifyClientCredentials(t *testing.T) {
	defer gock.Off()

	httpClient := &http.Client{}

	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	gock.New("http://example.com:8080").
		Post("/apps/verify").
		JSON(map[string]interface{}{
			"id":     "client-001",
			"secret": "secret",
		}).
		Reply(200).
		JSON(map[string]interface{}{
			"id":          "client-001",
			"name":        "TestClient",
			"description": "ClientDescription",
			"owner":       "user-0001",
			"website":     "http://client.example.com:9090",
		})

	gock.InterceptClient(httpClient)

	csAPI := &ClientServiceAPI{
		ServiceURL: "http://example.com:8080/apps",
		Client:     httpClient,
		Signature: Signature{
			Claims: map[string]interface{}{
				"userId": "test",
			},
			Key:           rsaPrivKey,
			SigningMethod: "RS256",
		},
	}

	client, err := csAPI.VerifyClientCredentials("client-001", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("Expected to get a client")
	}
}

func TestSaveClientAuth(t *testing.T) {
	csAPI := &ClientServiceAPI{
		ClientAuthRepository: &DummyClientAuthRepo{
			Auths: map[string][]*oauth2.ClientAuth{},
		},
	}

	ca := &oauth2.ClientAuth{
		ClientID:    "client-001",
		Code:        "abcdef",
		Confirmed:   true,
		GeneratedAt: time.Now().Unix(),
		RedirectURI: "http://client.example.com:9090",
		Scope:       "api:read",
		UserData:    "{}",
		UserID:      "11-22-33",
	}
	err := csAPI.SaveClientAuth(ca)
	if err != nil {
		t.Fatal(err)
	}

}

func TestGetClientAuth(t *testing.T) {
	csAPI := &ClientServiceAPI{
		ClientAuthRepository: &DummyClientAuthRepo{
			Auths: map[string][]*oauth2.ClientAuth{
				"client-001": []*oauth2.ClientAuth{
					&oauth2.ClientAuth{
						ClientID:    "client-001",
						Code:        "abcdef",
						Confirmed:   true,
						GeneratedAt: time.Now().Unix(),
						RedirectURI: "http://client.example.com:9090",
						Scope:       "api:read",
						UserData:    "{}",
						UserID:      "11-22-33",
					},
				},
			},
		},
	}
	ca, err := csAPI.GetClientAuth("client-001", "abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if ca == nil {
		t.Fatal("ClientAuth was expected")
	}
}

func TestGetClientAuthForUser(t *testing.T) {
	csAPI := &ClientServiceAPI{
		ClientAuthRepository: &DummyClientAuthRepo{
			Auths: map[string][]*oauth2.ClientAuth{
				"client-001": []*oauth2.ClientAuth{
					&oauth2.ClientAuth{
						ClientID:    "client-001",
						Code:        "abcdef",
						Confirmed:   true,
						GeneratedAt: time.Now().Unix(),
						RedirectURI: "http://client.example.com:9090",
						Scope:       "api:read",
						UserData:    "{}",
						UserID:      "11-22-33",
					},
				},
			},
		},
	}
	ca, err := csAPI.GetClientAuthForUser("11-22-33", "client-001")
	if err != nil {
		t.Fatal(err)
	}
	if ca == nil {
		t.Fatal("ClientAuth was expected")
	}
}

func TestConfirmClientAuth(t *testing.T) {
	cauth := &oauth2.ClientAuth{
		ClientID:    "client-001",
		Code:        "abcdef",
		Confirmed:   false,
		GeneratedAt: time.Now().Unix(),
		RedirectURI: "http://client.example.com:9090",
		Scope:       "api:read",
		UserData:    "{}",
		UserID:      "11-22-33",
	}
	csAPI := &ClientServiceAPI{
		ClientAuthRepository: &DummyClientAuthRepo{
			Auths: map[string][]*oauth2.ClientAuth{
				"client-001": []*oauth2.ClientAuth{cauth},
			},
		},
	}

	ca, err := csAPI.ConfirmClientAuth("11-22-33", "client-001")
	if err != nil {
		t.Fatal(err)
	}
	if ca == nil {
		t.Fatal("Expected an update and confirmed ClientAuth")
	}
	if !ca.Confirmed {
		t.Fatal("ClientAuth should be confirmed")
	}

}

func TestUpdateUserData(t *testing.T) {
	cauth := &oauth2.ClientAuth{
		ClientID:    "client-001",
		Code:        "abcdef",
		Confirmed:   false,
		GeneratedAt: time.Now().Unix(),
		RedirectURI: "http://client.example.com:9090",
		Scope:       "api:read",
		UserData:    "{}",
		UserID:      "11-22-33",
	}
	csAPI := &ClientServiceAPI{
		ClientAuthRepository: &DummyClientAuthRepo{
			Auths: map[string][]*oauth2.ClientAuth{
				"client-001": []*oauth2.ClientAuth{cauth},
			},
		},
	}

	err := csAPI.UpdateUserData("client-001", "abcdef", "11-22-33", "{\"updated\":true}")

	if err != nil {
		t.Fatal(err)
	}

	if cauth.UserData != "{\"updated\":true}" {
		t.Fatal("Expected to update the user data")
	}

}

func TestDeleteAuth(t *testing.T) {
	cauth := &oauth2.ClientAuth{
		ClientID:    "client-001",
		Code:        "abcdef",
		Confirmed:   false,
		GeneratedAt: time.Now().Unix(),
		RedirectURI: "http://client.example.com:9090",
		Scope:       "api:read",
		UserData:    "{}",
		UserID:      "11-22-33",
	}
	csAPI := &ClientServiceAPI{
		ClientAuthRepository: &DummyClientAuthRepo{
			Auths: map[string][]*oauth2.ClientAuth{
				"client-001": []*oauth2.ClientAuth{cauth},
			},
		},
	}

	err := csAPI.DeleteClientAuth("client-001", "abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if len(csAPI.ClientAuthRepository.(*DummyClientAuthRepo).Auths["client-001"]) > 0 {
		t.Fatal("Expected to delete the client auth")
	}
}

type MockKeyStore struct {
	PrivKey interface{}
}

func (m *MockKeyStore) GetPrivateKey() (interface{}, error) {
	return m.PrivKey, nil
}

func (m *MockKeyStore) GetPrivateKeyByName(name string) (interface{}, error) {
	return m.PrivKey, nil
}

func TestNewClientSignature(t *testing.T) {
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := NewClientSignature("unit-test-server", config.Security{
		Issuer:        "unit-test-server",
		SigningMethod: "RS512",
	}, &MockKeyStore{
		PrivKey: rsaPrivKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sig == nil {
		t.Fatal("Signature expected")
	}
}

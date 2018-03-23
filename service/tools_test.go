package service

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"regexp"
	"testing"

	"github.com/Microkubes/authorization-server/config"

	gock "gopkg.in/h2non/gock.v1"
)

func TestNewSignedRequest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signature := Signature{
		Claims:        map[string]interface{}{},
		Key:           key,
		SigningMethod: "RS256",
	}
	req, err := NewSignedRequest("GET", "http://example.com", nil, signature)
	if err != nil {
		t.Fatal(err)
	}
	if req == nil {
		t.Fatal("Expected a non-nil request")
	}
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		t.Fatal("Auth header not populated")
	}
	match, err := regexp.MatchString("^Bearer [^\\.]+\\.[^\\.]+\\.[^\\.]+$", authHeader)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Fatal("Not a JWT bearer authentication")
	}
}

func TestExecRequest_ResponseOK(t *testing.T) {
	defer gock.Off()

	gock.New("http://example.com").Get("/resource").Reply(200).JSON(map[string]string{
		"message": "success",
	})

	client := &http.Client{}

	gock.InterceptClient(client)

	req, err := http.NewRequest("GET", "http://example.com/resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ExecRequest("get-resource", req, client)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Response expected")
	}
	if resp.StatusCode != 200 {
		t.Fatal("Expected 200 OK response status.")
	}

}

type DummyKeyStore struct {
	key interface{}
}

func (d *DummyKeyStore) GetPrivateKey() (interface{}, error) {
	return d.key, nil
}

func (d *DummyKeyStore) GetPrivateKeyByName(name string) (interface{}, error) {
	return d.key, nil
}

func TestNewSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := NewSystemSignature("test-server", config.Security{
		Issuer:        "test-server",
		Keys:          map[string]string{},
		SigningMethod: "RS256",
	}, &DummyKeyStore{
		key: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if signature == nil {
		t.Fatal("Expected full signature.")
	}

}

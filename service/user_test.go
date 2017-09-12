package service

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"

	gock "gopkg.in/h2non/gock.v1"
)

func TestVerifyUser(t *testing.T) {
	defer gock.Off()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	gock.New("http://example.com").Post("/user/find").JSON(map[string]string{
		"username": "testuser",
		"password": "testpass",
	}).Reply(200).JSON(map[string]interface{}{
		"userId":        "user-001",
		"username":      "testuser",
		"email":         "user@mail.com",
		"roles":         []string{"user", "admin"},
		"organizations": []string{"org1", "org2"},
	})

	client := &http.Client{}

	gock.InterceptClient(client)

	userService := &UserServiceAPI{
		ServiceURL: "http://example.com/user",
		Client:     client,
		Signature: Signature{
			Claims:        map[string]interface{}{},
			Key:           rsaKey,
			SigningMethod: "RS256",
		},
	}

	user, err := userService.VerifyUser("testuser", "testpass")
	if err != nil {
		t.Fatal(err)
	}

	if user == nil {
		t.Fatal("Expected user data")
	}
}

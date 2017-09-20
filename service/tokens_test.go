package service

import (
	"testing"
	"time"

	"github.com/JormungandrK/microservice-security/oauth2"
)

type DummyTokenRepository struct {
	Tokens []*oauth2.AuthToken
}

func (d *DummyTokenRepository) GetForClientAndUser(clientID, userID string) (*oauth2.AuthToken, error) {
	for _, token := range d.Tokens {
		if token.ClientID == clientID && token.UserID == userID {
			return token, nil
		}
	}
	return nil, nil
}

func (d *DummyTokenRepository) GetForRefreshToken(refreshToken string) (*oauth2.AuthToken, error) {
	for _, token := range d.Tokens {
		if token.RefreshToken == refreshToken {
			return token, nil
		}
	}
	return nil, nil
}

func (d *DummyTokenRepository) Save(token *oauth2.AuthToken) (*oauth2.AuthToken, error) {
	for i, tkn := range d.Tokens {
		if token.RefreshToken != "" {
			if tkn.RefreshToken == token.RefreshToken {
				d.Tokens[i] = token
				return token, nil
			}
		} else if token.ClientID != "" && token.UserID != "" {
			if token.ClientID == tkn.ClientID && token.UserID == tkn.UserID {
				d.Tokens[i] = token
				return token, nil
			}
		}
	}
	d.Tokens = append(d.Tokens, token)
	return token, nil
}

func TestSaveToken(t *testing.T) {
	tokenRepository := &DummyTokenRepository{
		Tokens: []*oauth2.AuthToken{},
	}
	tokenService := &OAuth2TokenService{
		TokenRepository: tokenRepository,
	}

	err := tokenService.SaveToken(oauth2.AuthToken{
		AccessToken:  "acc-token",
		ClientID:     "client-001",
		IssuedAt:     time.Now().Unix(),
		RefreshToken: "refresh-token",
		Scope:        "api:read",
		UserID:       "user-001",
		ValidFor:     60000,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIsExpired(t *testing.T) {
	expired := isExpired(&oauth2.AuthToken{
		IssuedAt: time.Now().Unix(),
		ValidFor: 10000, // 10 seconds
	})
	if expired {
		t.Fatal("Should be valid for 10 seconds.")
	}

	if !isExpired(&oauth2.AuthToken{
		IssuedAt: time.Now().Add(time.Duration(-30) * time.Second).Unix(),
		ValidFor: 10000, // 10 seconds
	}) {
		t.Fatal("Token should be expired")
	}
}

func TestGetToken(t *testing.T) {
	tokenRepository := &DummyTokenRepository{
		Tokens: []*oauth2.AuthToken{
			&oauth2.AuthToken{
				AccessToken:  "acc-token",
				ClientID:     "client-001",
				IssuedAt:     time.Now().Unix(),
				RefreshToken: "refresh-token",
				Scope:        "api:read",
				UserID:       "user-001",
				ValidFor:     60000,
			},
		},
	}
	tokenService := &OAuth2TokenService{
		TokenRepository: tokenRepository,
	}

	tkn, err := tokenService.GetToken("refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if tkn == nil {
		t.Fatal("Expected to find token")
	}
}

func TestGetTokenForClient(t *testing.T) {
	tokenRepository := &DummyTokenRepository{
		Tokens: []*oauth2.AuthToken{
			&oauth2.AuthToken{
				AccessToken:  "acc-token",
				ClientID:     "client-001",
				IssuedAt:     time.Now().Unix(),
				RefreshToken: "refresh-token",
				Scope:        "api:read",
				UserID:       "user-001",
				ValidFor:     60000,
			},
		},
	}
	tokenService := &OAuth2TokenService{
		TokenRepository: tokenRepository,
	}

	tkn, err := tokenService.GetTokenForClient("user-001", "client-001")
	if err != nil {
		t.Fatal(err)
	}
	if tkn == nil {
		t.Fatal("Expected to find token")
	}
}

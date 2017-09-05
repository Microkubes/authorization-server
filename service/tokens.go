package service

import (
	"github.com/JormungandrK/authorization-server/db"
	"github.com/JormungandrK/microservice-security/oauth2"
)

type OAuth2TokenService struct {
	db.TokenRepository
}

func (t *OAuth2TokenService) SaveToken(token oauth2.OAuth2Token) error {
	_, err := t.TokenRepository.Save(&token)
	return err
}

func (t *OAuth2TokenService) GetToken(refreshToken string) (*oauth2.OAuth2Token, error) {
	return t.TokenRepository.GetForRefreshToken(refreshToken)
}

func (t *OAuth2TokenService) GetTokenForClient(userID, clientID string) (*oauth2.OAuth2Token, error) {
	return t.TokenRepository.GetForClientAndUser(clientID, userID)
}

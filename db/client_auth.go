package db

import (
	"time"

	"github.com/Microkubes/microservice-security/oauth2"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// ClientAuthRepository defines the interface for accessing the ClientAuth in a persistence.
type ClientAuthRepository interface {

	// GetWithCode looks up a ClientAuth by the clientID and the authorization code.
	GetWithCode(clientID, code string) (*oauth2.ClientAuth, error)

	// GetWithUserID looks up a ClientAuth by the clientID and the userID of the user that authorized that client.
	GetWithUserID(clientID, userID string) (*oauth2.ClientAuth, error)

	// Save saves the new or updated ClientAuth.
	Save(clientAuth *oauth2.ClientAuth) (*oauth2.ClientAuth, error)

	// Delete removes a ClientAuth for a client and auth code.
	Delete(clientID, code string) error
}

// MongoDBClientAuthRepository holds the mongo related collection for the ClientAuthRepository implementation.
type MongoDBClientAuthRepository struct {
	collection *mgo.Collection
}

// NewDBClientAuthRepository creates new ClientAuthRepository that is backed by a Mongodb collection.
func NewDBClientAuthRepository(host, dbName, username, password string, clientAuthTTL time.Duration) (*MongoDBClientAuthRepository, func(), error) {
	session, err := mgo.DialWithInfo(&mgo.DialInfo{
		Addrs:    []string{host},
		Username: username,
		Password: password,
		Database: dbName,
		Timeout:  30 * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}

	// SetMode - consistency mode for the session.
	session.SetMode(mgo.Monotonic, true)

	collection := session.DB(dbName).C("client-auth")

	clientAuthRepo := &MongoDBClientAuthRepository{
		collection: collection,
	}

	for _, idx := range []string{"clientId", "userId", "code"} {
		err = collection.EnsureIndex(index(idx))
		if err != nil {
			return nil, nil, err
		}
	}
	genAtIdx := index("generatedAt")
	genAtIdx.ExpireAfter = clientAuthTTL
	if err = collection.EnsureIndex(genAtIdx); err != nil {
		return nil, nil, err
	}
	// setup indexes

	return clientAuthRepo, func() {
		session.Close()
	}, nil
}

func index(ID string) mgo.Index {
	return mgo.Index{
		Key:        []string{ID},
		Background: true,
		Sparse:     true,
	}
}

// GetWithCode retrieves the ClientAuth from mongo db collection.
func (m *MongoDBClientAuthRepository) GetWithCode(clientID, code string) (*oauth2.ClientAuth, error) {
	ca := oauth2.ClientAuth{}
	err := m.collection.Find(bson.M{
		"clientId": clientID,
		"code":     code,
	}).One(&ca)
	if err != nil {
		return nil, err
	}
	return &ca, nil
}

// GetWithUserID retrieves the ClientAuth for a particular user and client from mongo db collection.
func (m *MongoDBClientAuthRepository) GetWithUserID(clientID, userID string) (*oauth2.ClientAuth, error) {
	ca := oauth2.ClientAuth{}
	err := m.collection.Find(bson.M{
		"clientId": clientID,
		"userId":   userID,
	}).One(&ca)
	if err != nil {
		return nil, err
	}
	return &ca, nil
}

// Save saves new or updated ClientAuth in mongo db collection.
// The record in mongo is stored with expiration time (TTL) and will be automatically removed by mongo
// once the expiration time is reached.
func (m *MongoDBClientAuthRepository) Save(clientAuth *oauth2.ClientAuth) (*oauth2.ClientAuth, error) {
	ca := map[string]interface{}{}
	m.collection.Find(bson.M{
		"clientId": clientAuth.ClientID,
		"code":     clientAuth.Code,
	}).One(&ca)

	ca["userId"] = clientAuth.UserID
	ca["scope"] = clientAuth.Scope
	ca["generatedAt"] = clientAuth.GeneratedAt
	ca["userData"] = clientAuth.UserData
	ca["redirectUri"] = clientAuth.RedirectURI
	ca["confirmed"] = clientAuth.Confirmed

	if _, ok := ca["clientId"]; ok {
		err := m.collection.Update(bson.M{
			"clientId": clientAuth.ClientID,
			"code":     clientAuth.Code,
		}, ca)
		if err != nil {
			return nil, err
		}
	} else {
		ca["clientId"] = clientAuth.ClientID
		ca["code"] = clientAuth.Code
		err := m.collection.Insert(ca)
		if err != nil {
			return nil, err
		}
	}
	return clientAuth, nil
}

// Delete removes the ClientAuth for a client and auth code from mongo db collection.
func (m *MongoDBClientAuthRepository) Delete(clientID, code string) error {
	err := m.collection.Remove(bson.M{
		"clientId": clientID,
		"code":     code,
	})
	return err
}

package db

import (
	"time"

	"github.com/JormungandrK/microservice-security/oauth2"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type ClientAuthRepository interface {
	GetWithCode(clientID, code string) (*oauth2.ClientAuth, error)
	GetWithUserID(clientID, userID string) (*oauth2.ClientAuth, error)
	Save(clientAuth *oauth2.ClientAuth) (*oauth2.ClientAuth, error)
	Delete(clientID, code string) error
}

type MongoDBClientAuthRepository struct {
	collection *mgo.Collection
}

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

func (m *MongoDBClientAuthRepository) Save(clientAuth *oauth2.ClientAuth) (*oauth2.ClientAuth, error) {
	ca := map[string]interface{}{}
	m.collection.Find(bson.M{
		"clientId": clientAuth.ClientID,
		"code":     clientAuth.Code,
	}).One(&ca)

	ca["userId"] = clientAuth.UserID
	ca["clientId"] = clientAuth.ClientID
	ca["code"] = clientAuth.Code
	ca["scope"] = clientAuth.Scope
	ca["generatedAt"] = clientAuth.GeneratedAt
	ca["userData"] = clientAuth.UserData
	ca["redirectUri"] = clientAuth.RedirectURI
	ca["confirmed"] = clientAuth.Confirmed

	if ID, ok := ca["_id"]; ok {
		err := m.collection.Update(bson.M{
			"_id": ID,
		}, ca)
		if err != nil {
			return nil, err
		}
	} else {
		err := m.collection.Insert(ca)
		if err != nil {
			return nil, err
		}
	}
	return clientAuth, nil
}

func (m *MongoDBClientAuthRepository) Delete(clientID, code string) error {
	err := m.collection.Remove(bson.M{
		"clientId": clientID,
		"code":     code,
	})
	return err
}

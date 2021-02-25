/*
Copyright Scoir Inc Technologies Inc, SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package mongodb implements a storage interface for Aries (aries-framework-go).
// TODO #69 - This implementation needs to be updated to support the new functionality.
//  Until that happens, this storage provider will not work correctly in aries-framework-go.
package mongodb

import (
	"context"
	"sync"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// data is a wrapper for the stored key/value pair.
type data struct {
	Key   string `bson:"_id" json:"Key"`
	Value []byte `bson:"Value" json:"Value"`
}

// Option configures the mongodb provider.
type Option func(opts *Provider)

// WithDBPrefix option is for adding prefix to db name.
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// Provider mongodb implementation of storage.Provider interface.
type Provider struct {
	dial     string
	dbs      map[string]*mongodbStore
	dbPrefix string
	sync.RWMutex
}

// NewProvider instantiates Provider.
func NewProvider(dial string, opts ...Option) *Provider {
	p := &Provider{dial: dial, dbs: map[string]*mongodbStore{}}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// OpenStore opens and returns a store for given name space.
func (r *Provider) OpenStore(name string) (storage.Store, error) {
	r.Lock()
	defer r.Unlock()

	if r.dbPrefix != "" {
		name = r.dbPrefix + "_" + name
	}

	store, ok := r.dbs[name]
	if ok {
		return store, nil
	}

	client, err := mongo.NewClient(options.Client().ApplyURI(r.dial))
	if err != nil {
		return nil, errors.Wrap(err, "unable to create new mongo client opening store")
	}

	err = client.Connect(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "unable to connect to mongo opening a new store")
	}

	db := client.Database(name)

	store = &mongodbStore{
		db:     db,
		client: client,
		coll:   db.Collection(name),
		name:   name,
	}
	r.dbs[name] = store

	return store, nil
}

// SetStoreConfig is not implemented.
func (r *Provider) SetStoreConfig(string, storage.StoreConfiguration) error {
	return errors.New("not implemented")
}

// GetStoreConfig is not implemented.
func (r *Provider) GetStoreConfig(string) (storage.StoreConfiguration, error) {
	return storage.StoreConfiguration{}, errors.New("not implemented")
}

// GetOpenStores is not implemented and will always panic when called.
func (r *Provider) GetOpenStores() []storage.Store {
	panic("not implemented")
}

// Close closes all stores created under this store provider.
func (r *Provider) Close() error {
	return errors.New("not implemented")
}

// Stores returns the number of stores.
func (r *Provider) Stores() int {
	return len(r.dbs)
}

type mongodbStore struct {
	client *mongo.Client
	db     *mongo.Database
	coll   *mongo.Collection
	name   string
}

// Put stores the key and the record.
func (r *mongodbStore) Put(k string, v []byte, tags ...storage.Tag) error {
	if len(tags) > 0 {
		return errors.New("tag storage not implemented")
	}

	if k == "" || v == nil {
		return errors.New("key and value are mandatory")
	}

	opts := &options.UpdateOptions{}
	_, err := r.coll.UpdateOne(context.Background(), bson.M{"_id": k}, bson.M{"$set": data{Key: k, Value: v}},
		opts.SetUpsert(true))

	return err
}

// Get fetches the record based on key.
func (r *mongodbStore) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	data := &data{}

	result := r.coll.FindOne(context.Background(), bson.M{"_id": k})
	if result.Err() == mongo.ErrNoDocuments {
		return nil, storage.ErrDataNotFound
	} else if result.Err() != nil {
		return nil, errors.Wrap(result.Err(), "unable to query mongo")
	}

	err := result.Decode(data)
	if err != nil {
		return nil, errors.Wrap(err, "invalid data storage, mongo store")
	}

	return data.Value, nil
}

func (r *mongodbStore) GetTags(string) ([]storage.Tag, error) {
	return nil, errors.New("not implemented")
}

func (r *mongodbStore) GetBulk(...string) ([][]byte, error) {
	return nil, errors.New("not implemented")
}

func (r *mongodbStore) Query(string, ...storage.QueryOption) (storage.Iterator, error) {
	return nil, errors.New("not implemented")
}

// Delete will delete record with k key.
func (r *mongodbStore) Delete(k string) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	_, err := r.coll.DeleteOne(context.Background(), bson.M{"_id": k})

	return err
}

func (r *mongodbStore) Batch([]storage.Operation) error {
	return errors.New("not implemented")
}

func (r *mongodbStore) Flush() error {
	return errors.New("not implemented")
}

func (r *mongodbStore) Close() error {
	return errors.New("not implemented")
}

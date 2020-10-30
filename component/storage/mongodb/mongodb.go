/*
Copyright Scoir Inc Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package mongodb implements a storage interface for Aries (aries-framework-go).
//
package mongodb

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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

// Close closes all stores created under this store provider.
func (r *Provider) Close() error {
	r.Lock()
	defer r.Unlock()

	if len(r.dbs) == 0 {
		return nil
	}

	i := 0

	names := make([]string, len(r.dbs))
	for name := range r.dbs {
		names[i] = name
		i++
	}

	for _, name := range names {
		err := r.CloseStore(name)
		if err != nil {
			return errors.Wrap(err, "unable to close provder, error in store")
		}
	}

	r.dbs = make(map[string]*mongodbStore)

	return nil
}

// CloseStore closes level name store of given name.
func (r *Provider) CloseStore(name string) error {
	if r.dbPrefix != "" {
		name = r.dbPrefix + "_" + name
	}

	store, ok := r.dbs[name]
	if ok {
		err := store.client.Disconnect(context.Background())
		if err != nil {
			return errors.Wrap(err, "unable to disconnect from mongo")
		}

		delete(r.dbs, name)
	}

	return nil
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
func (r *mongodbStore) Put(k string, v []byte) error {
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

// Iterator returns iterator for the latest snapshot of the underlying db.
func (r *mongodbStore) Iterator(start, end string) storage.StoreIterator {
	q := bson.M{}

	if strings.Contains(end, storage.EndKeySuffix) {
		newEnd := strings.Replace(end, storage.EndKeySuffix, "", 1)

		if start == newEnd {
			q = bson.M{"_id": bson.M{"$regex": primitive.Regex{
				Pattern: fmt.Sprintf("^%s", start),
				Options: "",
			}}}
		}
	} else {
		q = bson.M{"_id": bson.M{"$gte": start, "$lt": end}}
	}

	opts := options.Find().SetSort(bson.M{"_id": 1})

	cur, err := r.coll.Find(context.Background(), q, opts)
	if err != nil {
		return nil
	}

	return &mongodbIterator{cursor: cur}
}

// Delete will delete record with k key.
func (r *mongodbStore) Delete(k string) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	_, err := r.coll.DeleteOne(context.Background(), bson.M{"_id": k})

	return err
}

type mongodbIterator struct {
	cursor *mongo.Cursor
	err    error
}

func (r *mongodbIterator) Next() bool {
	return r.cursor.Next(context.Background())
}

func (r *mongodbIterator) Release() {
	r.cursor.Current = nil

	err := r.cursor.Close(context.Background())
	if err != nil {
		return
	}

	r.err = errors.New("iterator is closed")
}

func (r *mongodbIterator) Error() error {
	if r.cursor.Err() != nil {
		return r.cursor.Err()
	}

	return r.err
}

func (r *mongodbIterator) Key() []byte {
	d := &data{}

	err := r.cursor.Decode(d)
	if err != nil {
		return nil
	}

	return []byte(d.Key)
}

func (r *mongodbIterator) Value() []byte {
	d := &data{}

	err := r.cursor.Decode(d)
	if err != nil {
		return nil
	}

	return d.Value
}

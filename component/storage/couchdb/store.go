/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package couchdb implements a storage interface for Aries (aries-framework-go).
//
package couchdb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff"

	// The CouchDB driver.
	_ "github.com/go-kivik/couchdb"
	"github.com/go-kivik/kivik"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Provider represents an CouchDB implementation of the storage.Provider interface.
type Provider struct {
	log           logger
	hostURL       string
	couchDBClient *kivik.Client
	dbs           map[string]*StoreCouchDB
	dbPrefix      string
	sync.RWMutex
}

type logger interface {
	Warnf(msg string, args ...interface{})
}

const (
	blankHostErrMsg           = "hostURL for new CouchDB provider can't be blank"
	failToCloseProviderErrMsg = "failed to close provider"
	couchDBNotFoundErr        = "Not Found:"
	couchDBUsersTable         = "_users"
)

// Option configures the couchdb provider.
type Option func(opts *Provider)

// WithDBPrefix option is for adding prefix to db name.
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// WithLogger option is for logging.
func WithLogger(log logger) Option {
	return func(opts *Provider) {
		opts.log = log
	}
}

// PingCouchDB performs a readiness check on the CouchDB url.
func PingCouchDB(url string) error {
	if url == "" {
		return errors.New(blankHostErrMsg)
	}

	client, err := kivik.New("couch", url)
	if err != nil {
		return err
	}

	exists, err := client.DBExists(context.Background(), couchDBUsersTable)
	if err != nil {
		return fmt.Errorf("failed to probe couchdb for '%s' DB at %s: %w", couchDBUsersTable, url, err)
	}

	if !exists {
		return fmt.Errorf(
			"'%s' DB does not yet exist - CouchDB might not be fully initialized", couchDBUsersTable)
	}

	return nil
}

// NewProvider instantiates Provider.
// Certain stores like couchdb cannot accept key IDs with '_' prefix, to avoid getting errors with such values, key ID
// need to be base58 encoded for these stores. In order to do so, the store must be wrapped (using base58 or
// prefix wrapper).
func NewProvider(hostURL string, opts ...Option) (*Provider, error) {
	err := PingCouchDB(hostURL)
	if err != nil {
		return nil, fmt.Errorf("failed to ping couchDB: %w", err)
	}

	client, err := kivik.New("couch", hostURL)
	if err != nil {
		return nil, err
	}

	p := &Provider{hostURL: hostURL, couchDBClient: client, dbs: map[string]*StoreCouchDB{}}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// OpenStore opens an existing store with the given name and returns it.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	p.Lock()
	defer p.Unlock()

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	// Check cache first
	cachedStore, existsInCache := p.dbs[name]
	if existsInCache {
		return cachedStore, nil
	}

	err := p.couchDBClient.CreateDB(context.Background(), name)
	if err != nil {
		if err.Error() != "Precondition Failed: The database could not be created, the file already exists." {
			return nil, fmt.Errorf("failed to create db: %w", err)
		}
	}

	db := p.couchDBClient.DB(context.Background(), name)

	if db.Err() != nil {
		return nil, db.Err()
	}

	store := &StoreCouchDB{log: p.log, db: db}

	p.dbs[name] = store

	return store, nil
}

// CloseStore closes a previously opened store.
func (p *Provider) CloseStore(name string) error {
	p.Lock()
	defer p.Unlock()

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	store, exists := p.dbs[name]
	if !exists {
		return nil
	}

	delete(p.dbs, name)

	return store.db.Close(context.Background())
}

// Close closes the provider.
func (p *Provider) Close() error {
	p.Lock()
	defer p.Unlock()

	for _, store := range p.dbs {
		err := store.db.Close(context.Background())
		if err != nil {
			return fmt.Errorf(failToCloseProviderErrMsg+": %w", err)
		}
	}

	if err := p.couchDBClient.Close(context.Background()); err != nil {
		return err
	}

	p.dbs = make(map[string]*StoreCouchDB)

	return nil
}

// StoreCouchDB represents a CouchDB-backed database.
type StoreCouchDB struct {
	log logger
	db  *kivik.DB
}

// Put stores the given key-value pair in the store.
func (c *StoreCouchDB) Put(k string, v []byte) error {
	if k == "" || v == nil {
		return errors.New("key and value are mandatory")
	}

	var valueToPut []byte
	if isJSON(v) {
		valueToPut = []byte(`{"payload":` + string(v) + `}`)
	} else {
		valueToPut = wrapTextAsCouchDBAttachment(v)
	}

	return c.put(k, valueToPut)
}

func (c *StoreCouchDB) put(k string, value []byte) error {
	const maxRetries = 3

	return backoff.Retry(func() error {
		revID, err := c.getRevID(k)
		if err != nil {
			return err
		}

		valueToPut := value

		if revID != "" {
			valueToPut = []byte(`{"_rev":"` + revID + `",` + string(valueToPut[1:]))
		}

		_, err = c.db.Put(context.Background(), k, valueToPut)
		if err != nil && strings.Contains(err.Error(), "Document update conflict") {
			return err
		}

		// if an error is not `Document update conflict` it will be marked as permanent.
		// It means that retry logic will not be applicable.
		return backoff.Permanent(err)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond), maxRetries))
}

func isJSON(textToCheck []byte) bool {
	var js struct{}
	return json.Unmarshal(textToCheck, &js) == nil
}

// Kivik has a PutAttachment method, but it requires creating a document first and then adding an attachment after.
// We want to do it all in one step, hence this manual stuff below.
func wrapTextAsCouchDBAttachment(textToWrap []byte) []byte {
	encodedTextToWrap := base64.StdEncoding.EncodeToString(textToWrap)
	return []byte(`{"_attachments": {"data": {"data": "` + encodedTextToWrap + `", "content_type": "text/plain"}}}`)
}

// Get retrieves the value in the store associated with the given key.
func (c *StoreCouchDB) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	rawDoc := make(map[string]interface{})

	row := c.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if strings.Contains(err.Error(), couchDBNotFoundErr) {
			return nil, storage.ErrDataNotFound
		}

		return nil, err
	}

	return c.getStoredValueFromRawDoc(rawDoc, k)
}

// get rev ID.
func (c *StoreCouchDB) getRevID(k string) (string, error) {
	rawDoc := make(map[string]interface{})

	row := c.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if strings.Contains(err.Error(), couchDBNotFoundErr) {
			return "", nil
		}

		return "", err
	}

	return rawDoc["_rev"].(string), nil
}

// Delete will delete record with k key.
func (c *StoreCouchDB) Delete(k string) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	revID, err := c.getRevID(k)
	if err != nil {
		return err
	}

	// no error if nothing to delete
	if revID == "" {
		return nil
	}

	_, err = c.db.Delete(context.TODO(), k, revID)
	if err != nil {
		return fmt.Errorf("failed to delete doc: %w", err)
	}

	return nil
}

// Iterator returns iterator for the latest snapshot of the underlying db.
func (c *StoreCouchDB) Iterator(startKey, endKey string) storage.StoreIterator {
	resultRows, err := c.db.AllDocs(context.TODO(), kivik.Options{
		"startkey":      startKey,
		"endkey":        strings.ReplaceAll(endKey, storage.EndKeySuffix, kivik.EndKeySuffix),
		"inclusive_end": "false", // endkey should be exclusive to be consistent with goleveldb
		"include_docs":  "true",
	})
	if err != nil {
		return &couchDBResultsIterator{
			log:   c.log,
			store: c, resultRows: &kivik.Rows{},
			err: fmt.Errorf("failed to query docs: %w", err),
		}
	}

	return &couchDBResultsIterator{log: c.log, store: c, resultRows: resultRows}
}

// Query executes a query using the CouchDB _find endpoint.
func (c *StoreCouchDB) Query(findQuery string) (storage.StoreIterator, error) {
	resultRows, err := c.db.Find(context.Background(), findQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query CouchDB using the find endpoint: %w", err)
	}

	return &couchDBResultsIterator{log: c.log, store: c, resultRows: resultRows}, nil
}

type couchDBResultsIterator struct {
	log        logger
	store      *StoreCouchDB
	resultRows *kivik.Rows
	err        error
}

// Next moves the pointer to the next value in the iterator. It returns false if the iterator is exhausted.
// Note that the Kivik library automatically closes the kivik.Rows iterator if the iterator is exhausted.
func (i *couchDBResultsIterator) Next() bool {
	nextCallResult := i.resultRows.Next()

	if i.log == nil {
		return nextCallResult
	}

	// Kivik only guarantees that this value will be set after all the rows have been iterated through.
	warningMsg := i.resultRows.Warning()
	if warningMsg != "" {
		i.log.Warnf(warningMsg)
	}

	return nextCallResult
}

func (i *couchDBResultsIterator) Release() {
	if err := i.resultRows.Close(); err != nil {
		i.err = err
	}
}

func (i *couchDBResultsIterator) Error() error {
	if i.err != nil {
		return i.err
	}

	return i.resultRows.Err()
}

// Key returns the key of the current key-value pair.
func (i *couchDBResultsIterator) Key() []byte {
	key := i.resultRows.Key()
	if key != "" {
		// The returned key is a raw JSON string. It needs to be unescaped:
		v, err := strconv.Unquote(key)
		if err != nil {
			i.err = err
			return nil
		}

		return []byte(v)
	}

	return nil
}

// Value returns the value of the current key-value pair.
func (i *couchDBResultsIterator) Value() []byte {
	rawDoc := make(map[string]interface{})

	if err := i.resultRows.ScanDoc(&rawDoc); err != nil {
		i.err = err
		return nil
	}

	key := i.Key()

	v, err := i.store.getStoredValueFromRawDoc(rawDoc, string(key))
	if err != nil {
		i.err = err

		return nil
	}

	return v
}

func (c *StoreCouchDB) getStoredValueFromRawDoc(rawDoc map[string]interface{}, k string) ([]byte, error) {
	_, containsAttachment := rawDoc["_attachments"]
	if containsAttachment {
		return c.getDataFromAttachment(k)
	}

	strippedJSON, err := json.Marshal(rawDoc["payload"])
	if err != nil {
		return nil, err
	}

	return strippedJSON, nil
}

func (c *StoreCouchDB) getDataFromAttachment(k string) ([]byte, error) {
	attachment, err := c.db.GetAttachment(context.Background(), k, "data")
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(attachment.Content)
	if err != nil {
		return nil, err
	}

	return data, nil
}

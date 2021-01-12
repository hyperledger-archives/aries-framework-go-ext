/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package couchdb implements a storage interface for Aries (aries-framework-go).
package couchdb

import ( //nolint:gci // False positive, seemingly caused by the CouchDB driver comment.
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	// The CouchDB driver. This import must be here for the Kivik client instantiation with a CouchDB driver to work.
	_ "github.com/go-kivik/couchdb/v3"
	"github.com/go-kivik/kivik/v3"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/newstorage"
)

const (
	couchDBUsersTable = "_users"

	designDocumentName = "AriesStorageDesignDocument"
	payloadFieldKey    = "payload"

	// Hardcoded strings returned from Kivik/CouchDB that we check for.
	docNotFoundErrMsgFromKivik            = "Not Found: missing"
	docDeletedErrMsgFromKivik             = "Not Found: deleted"
	databaseNotFoundErrMsgFromKivik       = "Not Found: Database does not exist."
	documentUpdateConflictErrMsgFromKivik = "Conflict: Document update conflict."

	failGetDatabaseHandle   = "failed to get database handle: %w"
	failGetExistingIndexes  = "failed to get existing indexes: %w"
	failureWhileScanningRow = "failure while scanning row: %w"
	failGetTagsFromRawDoc   = "failed to get tags from raw CouchDB document: %w"
	failGetRevisionID       = "failed to get revision ID: %w"
	failPutValueViaClient   = "failed to put value via client: %w"
)

type marshalFunc func(interface{}) ([]byte, error)

type db interface {
	Get(ctx context.Context, docID string, options ...kivik.Options) *kivik.Row
	Put(ctx context.Context, docID string, doc interface{}, options ...kivik.Options) (rev string, err error)
	Delete(ctx context.Context, docID, rev string, options ...kivik.Options) (newRev string, err error)
	Close(ctx context.Context) error
}

// Provider represents a CouchDB implementation of the newstorage.Provider interface.
type Provider struct {
	logger                        log.Logger
	hostURL                       string
	couchDBClient                 *kivik.Client
	dbPrefix                      string
	maxDocumentConflictRetriesSet bool
	maxDocumentConflictRetries    int
}

// Option represents an option for a CouchDB Provider.
type Option func(opts *Provider)

// WithDBPrefix is an option for adding a prefix to all created DB names.
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// WithMaxDocumentConflictRetries is an option for specifying how many retries are allowed in the case when there's
// a document update conflict (i.e. the document was updated by someone else during a Put operation here).
func WithMaxDocumentConflictRetries(maxRetries int) Option {
	return func(opts *Provider) {
		opts.maxDocumentConflictRetries = maxRetries
		opts.maxDocumentConflictRetriesSet = true
	}
}

// PingCouchDB performs a readiness check on the CouchDB instance located at url.
func PingCouchDB(url string) error {
	if url == "" {
		return errors.New("url can't be blank")
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
			`"%s" database does not yet exist - CouchDB might not be fully initialized`, couchDBUsersTable)
	}

	return nil
}

// NewProvider instantiates a new CouchDB Provider.
func NewProvider(hostURL string, opts ...Option) (*Provider, error) {
	err := PingCouchDB(hostURL)
	if err != nil {
		return nil, fmt.Errorf("failed to ping couchDB: %w", err)
	}

	client, err := kivik.New("couch", hostURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create new CouchDB client: %w", err)
	}

	p := &Provider{hostURL: hostURL, couchDBClient: client, logger: log.New("CouchDBProvider")}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
func (p *Provider) OpenStore(name string) (newstorage.Store, error) {
	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	err := p.couchDBClient.CreateDB(context.Background(), name)
	if err != nil {
		if err.Error() != "Precondition Failed: The database could not be created, the file already exists." {
			return nil, fmt.Errorf("failed to create database in CouchDB: %w", err)
		}
	}

	db := p.couchDBClient.DB(context.Background(), name)

	err = db.Err()
	if err != nil {
		return nil, fmt.Errorf(failGetDatabaseHandle, err)
	}

	maxDocumentConflictRetries := 3

	if p.maxDocumentConflictRetriesSet {
		maxDocumentConflictRetries = p.maxDocumentConflictRetries
	}

	return &Store{
		logger: p.logger, db: db, maxDocumentConflictRetries: maxDocumentConflictRetries,
		marshal: json.Marshal,
	}, nil
}

// SetStoreConfig sets the configuration on a store.
// Indexes are created based on the tag names in config. This allows the Store.Query method to operate faster.
// Existing tag names/indexes in the store that are not in the config passed in here will be removed.
// The store must be created prior to calling this method.
// If duplicate tags are provided, then CouchDB will ignore them.
func (p *Provider) SetStoreConfig(name string, config newstorage.StoreConfiguration) error {
	err := validateTagNames(config)
	if err != nil {
		return fmt.Errorf("invalid tag names: %w", err)
	}

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	db := p.couchDBClient.DB(context.Background(), name)

	err = db.Err()
	if err != nil {
		return fmt.Errorf(failGetDatabaseHandle, err)
	}

	err = p.setIndexes(db, config)
	if err != nil {
		return fmt.Errorf("failure while setting indexes: %w", err)
	}

	return nil
}

// GetStoreConfig gets the current store configuration.
func (p *Provider) GetStoreConfig(name string) (newstorage.StoreConfiguration, error) {
	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	db := p.couchDBClient.DB(context.Background(), name)

	err := db.Err()
	if err != nil {
		return newstorage.StoreConfiguration{}, fmt.Errorf(failGetDatabaseHandle, err)
	}

	indexes, err := db.GetIndexes(context.Background())
	if err != nil {
		if err.Error() == databaseNotFoundErrMsgFromKivik {
			return newstorage.StoreConfiguration{}, fmt.Errorf(failGetExistingIndexes, newstorage.ErrStoreNotFound)
		}

		return newstorage.StoreConfiguration{}, fmt.Errorf(failGetExistingIndexes, err)
	}

	var tags []string

	for _, index := range indexes {
		if index.Name != "_all_docs" { // _all_docs is the CouchDB default index on the document ID
			tags = append(tags, strings.TrimSuffix(index.Name, "_index"))
		}
	}

	return newstorage.StoreConfiguration{TagNames: tags}, nil
}

// Close closes the provider.
func (p *Provider) Close() error {
	err := p.couchDBClient.Close(context.Background())
	if err != nil {
		return fmt.Errorf("failed to close database via client: %w", err)
	}

	return nil
}

func (p *Provider) setIndexes(db *kivik.DB, config newstorage.StoreConfiguration) error {
	existingIndexes, err := db.GetIndexes(context.Background())
	if err != nil {
		if err.Error() == databaseNotFoundErrMsgFromKivik {
			return fmt.Errorf(failGetExistingIndexes, newstorage.ErrStoreNotFound)
		}

		return fmt.Errorf(failGetExistingIndexes, err)
	}

	err = updateIndexes(db, config, existingIndexes)
	if err != nil {
		return fmt.Errorf("failure while creating indexes in CouchDB: %w", err)
	}

	return nil
}

// Store represents a CouchDB-backed database.
type Store struct {
	logger                     log.Logger
	db                         db
	maxDocumentConflictRetries int
	marshal                    marshalFunc
}

// Put stores the key + value pair along with the (optional) tags.
// TODO (#40) Values stored under keys containing special URL characters like `/`
//  are not retrievable due to a bug in the underlying Kivik library.
func (s *Store) Put(k string, v []byte, tags ...newstorage.Tag) error {
	if k == "" {
		return errors.New("key cannot be empty")
	}

	if v == nil {
		return errors.New("value cannot be nil")
	}

	valuesMapToMarshal := make(map[string]string)

	valuesMapToMarshal[payloadFieldKey] = string(v)

	for _, tag := range tags {
		if tag.Name == payloadFieldKey {
			return errors.New(`tag name cannot be "payload" as it is a reserved keyword`)
		}

		valuesMapToMarshal[tag.Name] = tag.Value
	}

	valueToPut, err := s.marshal(valuesMapToMarshal)
	if err != nil {
		return fmt.Errorf("failed to marshal values map: %w", err)
	}

	err = s.put(k, valueToPut)
	if err != nil {
		return fmt.Errorf("failure while putting value into CouchDB: %w", err)
	}

	return nil
}

// Get fetches the value associated with the given key.
func (s *Store) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	rawDoc := make(map[string]interface{})

	row := s.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if strings.Contains(err.Error(), docNotFoundErrMsgFromKivik) ||
			strings.Contains(err.Error(), docDeletedErrMsgFromKivik) {
			return nil, fmt.Errorf(failureWhileScanningRow, newstorage.ErrDataNotFound)
		}

		return nil, fmt.Errorf(failureWhileScanningRow, err)
	}

	storedValue, err := s.getStoredValueFromRawDoc(rawDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to get payload from raw document: %w", err)
	}

	return storedValue, nil
}

// GetTags fetches all tags associated with the given key.
func (s *Store) GetTags(k string) ([]newstorage.Tag, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	rawDoc := make(map[string]interface{})

	row := s.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if strings.Contains(err.Error(), docNotFoundErrMsgFromKivik) {
			return nil, newstorage.ErrDataNotFound
		}

		return nil, err
	}

	tags, err := getTagsFromRawDoc(rawDoc)
	if err != nil {
		return nil, fmt.Errorf(failGetTagsFromRawDoc, err)
	}

	return tags, nil
}

// GetBulk fetches the values associated with the given keys.
// If a key doesn't exist, then a nil []byte is returned for that value. It is not considered an error.
func (s *Store) GetBulk(keys ...string) ([][]byte, error) {
	return nil, errors.New("not implemented")
}

// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
// If TagValue is not provided, then all data associated with the TagName will be returned.
// For now, expression can only be a single tag Name + Value pair.
// If no options are provided, then defaults will be used.
func (s *Store) Query(expression string, options ...newstorage.QueryOption) (newstorage.Iterator, error) {
	return &couchDBResultsIterator{}, errors.New("not implemented")
}

// Delete deletes the key + value pair (and all tags) associated with key.
func (s *Store) Delete(k string) error {
	if k == "" {
		return errors.New("key is mandatory")
	}

	revID, err := s.getRevID(k)
	if err != nil {
		return fmt.Errorf(failGetRevisionID, err)
	}

	// If no revision ID is returned, then this value doesn't exist.
	// This is not considered an error.
	if revID == "" {
		return nil
	}

	_, err = s.db.Delete(context.TODO(), k, revID)
	if err != nil {
		return fmt.Errorf("failed to delete document via client: %w", err)
	}

	return nil
}

// Batch performs multiple Put and/or Delete operations in order.
func (s *Store) Batch(operations []newstorage.Operation) error {
	return errors.New("not implemented")
}

// Close closes this store.
func (s *Store) Close() error {
	err := s.db.Close(context.Background())
	if err != nil {
		return fmt.Errorf("failed to close database client: %w", err)
	}

	return nil
}

func (s *Store) put(k string, value []byte) error {
	err := backoff.Retry(func() error {
		revID, err := s.getRevID(k)
		if err != nil {
			// This is an unexpected error. Return a backoff.Permanent wrapped error to prevent further retries.
			return backoff.Permanent(fmt.Errorf(failGetRevisionID, err))
		}

		if revID != "" {
			value = []byte(`{"_rev":"` + revID + `",` + string(value[1:]))
		}

		_, err = s.db.Put(context.Background(), k, value)
		if err != nil {
			if err.Error() == documentUpdateConflictErrMsgFromKivik {
				// This means that the document was updated since we got the revision ID.
				// Need to get the new revision ID and try again.
				return fmt.Errorf(failPutValueViaClient, err)
			}

			// This is an unexpected error.
			return backoff.Permanent(fmt.Errorf(failPutValueViaClient, err))
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond), uint64(s.maxDocumentConflictRetries)))
	if err != nil {
		if strings.Contains(err.Error(), documentUpdateConflictErrMsgFromKivik) {
			return fmt.Errorf("maximum number of retry attempts (%d) exceeded: %w",
				s.maxDocumentConflictRetries, err)
		}

		return err // No need for more error wrapping here.
	}

	return nil
}

// If the document can't be found, then a blank ID is returned.
func (s *Store) getRevID(k string) (string, error) {
	rawDoc := make(map[string]interface{})

	row := s.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if strings.Contains(err.Error(), docNotFoundErrMsgFromKivik) {
			return "", nil
		}

		return "", err
	}

	revID, ok := rawDoc["_rev"]
	if !ok {
		return "", errors.New("revision ID was missing from the raw document")
	}

	revIDString, ok := revID.(string)
	if !ok {
		return "", errors.New("unable to assert revision ID as a string")
	}

	return revIDString, nil
}

func (s *Store) getStoredValueFromRawDoc(rawDoc map[string]interface{}) ([]byte, error) {
	storedValue, ok := rawDoc[payloadFieldKey]
	if !ok {
		return nil, errors.New("payload was unexpectedly missing from raw document")
	}

	storedValueString, ok := storedValue.(string)
	if !ok {
		return nil, errors.New("stored value could not be asserted as a string")
	}

	return []byte(storedValueString), nil
}

type couchDBResultsIterator struct {
}

// Next moves the pointer to the next value in the iterator. It returns false if the iterator is exhausted.
// Note that the Kivik library automatically closes the kivik.Rows iterator if the iterator is exhausted.
func (i *couchDBResultsIterator) Next() (bool, error) {
	return false, errors.New("not implemented")
}

// Release releases associated resources. Release should always result in success
// and can be called multiple times without causing an error.
func (i *couchDBResultsIterator) Release() error {
	return errors.New("not implemented")
}

// Key returns the key of the current key-value pair.
// A nil error likely means that the key list is exhausted.
func (i *couchDBResultsIterator) Key() (string, error) {
	return "", errors.New("not implemented")
}

// Value returns the value of the current key-value pair.
func (i *couchDBResultsIterator) Value() ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (i *couchDBResultsIterator) Tags() ([]newstorage.Tag, error) {
	return nil, errors.New("not implemented")
}

func validateTagNames(config newstorage.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if tagName == payloadFieldKey {
			return errors.New(`tag name cannot be "payload" as it is a reserved keyword`)
		}
	}

	return nil
}

func updateIndexes(db *kivik.DB, config newstorage.StoreConfiguration, existingIndexes []kivik.Index) error {
	tagNameIndexesAlreadyConfigured := make(map[string]struct{})

	for _, existingIndex := range existingIndexes {
		// Ignore _all_docs, which is the CouchDB default index on the document ID field
		if existingIndex.Name != "_all_docs" {
			existingTagName := strings.TrimSuffix(existingIndex.Name, "_index")

			var existingTagIsInNewConfig bool

			for _, tagName := range config.TagNames {
				if existingTagName == tagName {
					existingTagIsInNewConfig = true
					tagNameIndexesAlreadyConfigured[tagName] = struct{}{}

					break
				}
			}

			// If the new store configuration doesn't have the existing index (tag) defined, then we will delete it
			if !existingTagIsInNewConfig {
				err := db.DeleteIndex(context.Background(), designDocumentName, existingIndex.Name)
				if err != nil {
					return fmt.Errorf("failed to delete index: %w", err)
				}
			}
		}
	}

	var tagNamesNeedIndexCreation []string

	for _, tag := range config.TagNames {
		_, indexAlreadyCreated := tagNameIndexesAlreadyConfigured[tag]
		if !indexAlreadyCreated {
			tagNamesNeedIndexCreation = append(tagNamesNeedIndexCreation, tag)
		}
	}

	err := createIndexes(db, tagNamesNeedIndexCreation)
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}

func createIndexes(db *kivik.DB, tagNamesNeedIndexCreation []string) error {
	for _, tag := range tagNamesNeedIndexCreation {
		err := db.CreateIndex(context.Background(), designDocumentName, tag+"_index",
			`{"fields": ["`+tag+`"]}`)
		if err != nil {
			return fmt.Errorf("failed to create index in CouchDB: %w", err)
		}
	}

	return nil
}

func getTagsFromRawDoc(rawDoc map[string]interface{}) ([]newstorage.Tag, error) {
	var tags []newstorage.Tag

	for key, value := range rawDoc {
		// Any key that isn't one of the reserved keywords below must be a tag.
		if key != "_id" && key != "_rev" && key != payloadFieldKey {
			valueString, ok := value.(string)
			if !ok {
				return nil, errors.New("failed to assert tag value as string")
			}

			tags = append(tags, newstorage.Tag{
				Name:  key,
				Value: valueString,
			})
		}
	}

	return tags, nil
}

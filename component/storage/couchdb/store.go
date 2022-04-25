/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package couchdb implements a storage interface for Aries (aries-framework-go).
package couchdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff" //nolint:gci // False positive, seemingly caused by the CouchDB driver comment.
	// The CouchDB driver. This import must be here for the Kivik client instantiation with a CouchDB driver to work.
	_ "github.com/go-kivik/couchdb/v3"
	"github.com/go-kivik/kivik/v3"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	couchDBUsersTable = "_users"

	// CouchDB won't allow us to put Mango query index-based views in a design document with MapReduce-based views,
	// so we'll need one for each type.
	designDocumentName                  = "AriesStorageDesignDocument"
	mapReduceDesignDocumentName         = "AriesStorageMapReduceDesignDocument"
	mapReduceDesignDocumentNameWithPath = "_design/" + mapReduceDesignDocumentName
	countViewNameTemplate               = "%s_count"

	// Hardcoded strings returned from Kivik/CouchDB that we check for.
	docNotFoundErrMsgFromKivik                            = "Not Found: missing"
	bulkGetDocNotFoundErrMsgFromKivik                     = "not_found: missing"
	docDeletedErrMsgFromKivik                             = "Not Found: deleted"
	databaseNotFoundErrMsgFromKivik                       = "Not Found: Database does not exist."
	documentUpdateConflictErrMsgFromKivik                 = "Conflict: Document update conflict."
	mangoIndexDesignDocumentUpdateConflictErrMsgFromKivik = "Internal Server Error: " +
		"Encountered a conflict while saving the design document."

	failCreateOrUpdateMapReduceDesignDoc = "failed to create/update MapReduce design document: %w"
	invalidTagName                       = `"%s" is an invalid tag name since it contains one or more ':' characters`
	invalidTagValue                      = `"%s" is an invalid tag value since it contains one or more ':' characters`
	failGetDatabaseHandle                = "failed to get database handle: %w"
	failGetExistingIndexes               = "failed to get existing indexes: %w"
	failCreateIndex                      = "failed to create index in CouchDB: %w"
	failCreateIndexDueToConflict         = "failed to create index in CouchDB due to " +
		"design document conflict after %d attempts. This storage provider may need to be started with a higher " +
		"max retry limit. Original error message from CouchDB: %w"
	failUpdateDesignDocumentDueToConflict = "failed to update design document in CouchDB due to " +
		"document conflict after %d attempts. This storage provider may need to be started with a higher " +
		"max retry limit. Original error message from CouchDB: %w"
	failUpdateDocumentDueToConflict = "failed to store document for [Key: %s] in CouchDB due to " +
		"document conflict after %d attempts. This storage provider may need to be started with a higher " +
		"max retry limit. Original error message from CouchDB: %w"
	failureWhileScanningRow       = "failure while scanning row: %w"
	failGetRevisionID             = "failed to get revision ID: %w"
	failPutValueViaClient         = "failed to put value via client: %w"
	failWhileScanResultRows       = "failure while scanning result rows: %w"
	failSendRequestToFindEndpoint = "failure while sending request to CouchDB find endpoint: %w"
	failGetDocs                   = "failure while getting documents: %w"

	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2

	fieldNameExistsSelectorTemplate   = `{"tags.%s":{"$exists":true}}`
	fieldNameAndValueSelectorTemplate = `{"tags.%s":"%s"}`
	sortOptionsTemplate               = `[{"tags.%s": "%s"}]`
)

type findQuery struct {
	Selector json.RawMessage `json:"selector,omitempty"`
	Limit    int             `json:"limit,omitempty"`
	Bookmark string          `json:"bookmark,omitempty"`
	Sort     json.RawMessage `json:"sort,omitempty"`
	Skip     int             `json:"skip,omitempty"`
}

var errInvalidQueryExpressionFormat = errors.New("invalid expression format. " +
	"it must be in the following format: TagName:TagValue")

type marshalFunc func(interface{}) ([]byte, error)

type closer func(storeName string)

type logger interface {
	Infof(msg string, args ...interface{})
	Warnf(msg string, args ...interface{})
}

type defaultLogger struct {
	logger *log.Logger
}

func (d *defaultLogger) Infof(msg string, args ...interface{}) {
	d.logger.Printf(msg, args...)
}

func (d *defaultLogger) Warnf(msg string, args ...interface{}) {
	d.logger.Printf(msg, args...)
}

type designDoc struct {
	RevisionID string                       `json:"_rev,omitempty"`
	Views      map[string]map[string]string `json:"views,omitempty"`
}

type document struct {
	ID         string                 `json:"_id,omitempty"`      // CouchDB-internal field
	RevisionID string                 `json:"_rev,omitempty"`     // CouchDB-internal field
	Deleted    bool                   `json:"_deleted,omitempty"` // CouchDB-internal field
	Value      []byte                 `json:"value,omitempty"`    // Our custom field
	Tags       map[string]interface{} `json:"tags,omitempty"`     // Our custom field
}

type db interface {
	Get(ctx context.Context, docID string, options ...kivik.Options) *kivik.Row
	Put(ctx context.Context, docID string, doc interface{}, options ...kivik.Options) (rev string, err error)
	GetIndexes(ctx context.Context, options ...kivik.Options) ([]kivik.Index, error)
	CreateIndex(ctx context.Context, ddoc, name string, index interface{}, options ...kivik.Options) error
	DeleteIndex(ctx context.Context, ddoc, name string, options ...kivik.Options) error
	Find(ctx context.Context, query interface{}, options ...kivik.Options) (*kivik.Rows, error)
	Query(ctx context.Context, ddoc, view string, options ...kivik.Options) (*kivik.Rows, error)
	Delete(ctx context.Context, docID, rev string, options ...kivik.Options) (newRev string, err error)
	BulkGet(ctx context.Context, docs []kivik.BulkGetReference, options ...kivik.Options) (*kivik.Rows, error)
	Close(ctx context.Context) error
	BulkDocs(ctx context.Context, docs []interface{}, options ...kivik.Options) (*kivik.BulkResults, error)
}

type rows interface {
	Next() bool
	Err() error
	Close() error
	ScanDoc(dest interface{}) error
	Warning() string
	Bookmark() string
}

// Provider represents a CouchDB implementation of the storage.Provider interface.
type Provider struct {
	logger                     logger
	hostURL                    string
	couchDBClient              *kivik.Client
	dbPrefix                   string
	openStores                 map[string]*store
	maxDocumentConflictRetries int
	lock                       sync.RWMutex
}

// Option represents an option for a CouchDB Provider.
type Option func(opts *Provider)

// WithDBPrefix is an option for adding a prefix to all created DB names.
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// WithMaxDocumentConflictRetries is an option for specifying how many retries are allowed when there's a document
// update conflict. This can happen if there are multiple CouchDB providers trying to insert data into a store
// or set store configs are the same time.
// maxRetries must be > 0. If not set (or set to an invalid value), it will default to 3 in the NewProvider function.
func WithMaxDocumentConflictRetries(maxRetries int) Option {
	return func(opts *Provider) {
		opts.maxDocumentConflictRetries = maxRetries
	}
}

// WithLogger is an option for specifying a custom logger.
// The standard Golang logger will be used if this option is not provided.
func WithLogger(logger logger) Option {
	return func(opts *Provider) {
		opts.logger = logger
	}
}

// ReadinessCheck performs a readiness check on the CouchDB instance located at url.
func ReadinessCheck(url string) error {
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
// TODO (#48): Allow context to be passed in.
func NewProvider(hostURL string, opts ...Option) (*Provider, error) {
	err := ReadinessCheck(hostURL)
	if err != nil {
		return nil, fmt.Errorf("failed to ping couchDB: %w", err)
	}

	client, err := kivik.New("couch", hostURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create new CouchDB client: %w", err)
	}

	p := &Provider{
		hostURL:       hostURL,
		couchDBClient: client,
		openStores:    make(map[string]*store),
	}

	for _, opt := range opts {
		opt(p)
	}

	if p.maxDocumentConflictRetries < 1 {
		p.maxDocumentConflictRetries = 3
	}

	if p.logger == nil {
		p.logger = &defaultLogger{
			log.New(os.Stdout, "CouchDB-Provider ", log.Ldate|log.Ltime|log.LUTC),
		}
	}

	return p, nil
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	if name == "" {
		return nil, fmt.Errorf("store name cannot be empty")
	}

	name = strings.ToLower(p.dbPrefix + name)

	p.lock.Lock()
	defer p.lock.Unlock()

	openStore := p.openStores[name]
	if openStore == nil {
		return p.createStore(name)
	}

	return openStore, nil
}

// SetStoreConfig sets the configuration on a store.
// Indexes are created based on the tag names in config. This allows the store.Query method to operate faster with
// large datasets. If you want to do queries with sorts, then you must ensure the tag you're sorting on is indexed,
// otherwise the query will fail.
// Existing tag names/indexes in the store that are not in the config passed in here will be removed.
// The store must be created prior to calling this method.
// If duplicate tags are provided, then CouchDB will ignore them.
func (p *Provider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	name = strings.ToLower(p.dbPrefix + name)

	db := p.couchDBClient.DB(context.Background(), name)

	err := db.Err()
	if err != nil {
		return fmt.Errorf(failGetDatabaseHandle, err)
	}

	err = p.setDesignDocuments(name, config, db)
	if err != nil {
		return err
	}

	return nil
}

// GetStoreConfig gets the current store configuration.
func (p *Provider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	name = strings.ToLower(p.dbPrefix + name)

	db := p.couchDBClient.DB(context.Background(), name)

	err := db.Err()
	if err != nil {
		return storage.StoreConfiguration{}, fmt.Errorf(failGetDatabaseHandle, err)
	}

	indexes, err := db.GetIndexes(context.Background())
	if err != nil {
		if err.Error() == databaseNotFoundErrMsgFromKivik {
			return storage.StoreConfiguration{}, fmt.Errorf(failGetExistingIndexes, storage.ErrStoreNotFound)
		}

		return storage.StoreConfiguration{}, fmt.Errorf(failGetExistingIndexes, err)
	}

	var tags []string

	for _, index := range indexes {
		if index.Name != "_all_docs" { // _all_docs is the CouchDB default index on the document ID
			tags = append(tags, strings.TrimSuffix(index.Name, "_index"))
		}
	}

	return storage.StoreConfiguration{TagNames: tags}, nil
}

// GetOpenStores returns all currently open stores.
func (p *Provider) GetOpenStores() []storage.Store {
	p.lock.RLock()
	defer p.lock.RUnlock()

	openStores := make([]storage.Store, len(p.openStores))

	var counter int

	for _, store := range p.openStores {
		openStores[counter] = store
		counter++
	}

	return openStores
}

// Close closes the provider.
func (p *Provider) Close() error {
	p.lock.RLock()

	openStoresSnapshot := make([]*store, len(p.openStores))

	var counter int

	for _, openStore := range p.openStores {
		openStoresSnapshot[counter] = openStore
		counter++
	}
	p.lock.RUnlock()

	for _, openStore := range openStoresSnapshot {
		err := openStore.Close()
		if err != nil {
			return fmt.Errorf(`failed to close open store with name "%s": %w`, openStore.name, err)
		}
	}

	err := p.couchDBClient.Close(context.Background())
	if err != nil {
		return fmt.Errorf("failed to close database via client: %w", err)
	}

	return nil
}

// Ping verifies whether the CouchDB client can successfully connect to the deployment specified by
// the host URL string used in the NewProvider call.
func (p *Provider) Ping() error {
	_, err := p.couchDBClient.Ping(context.Background())

	return err
}

func (p *Provider) createStore(name string) (storage.Store, error) {
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

	newStore := &store{
		name: name, logger: p.logger, db: db, maxDocumentConflictRetries: p.maxDocumentConflictRetries,
		marshal: json.Marshal, close: p.removeStore,
	}

	p.openStores[name] = newStore

	return newStore, nil
}

func (p *Provider) setDesignDocuments(name string, config storage.StoreConfiguration, db db) error {
	err := p.updateMangoIndexDesignDocument(db, config, name)
	if err != nil {
		return fmt.Errorf("failure while updating Mango index design document: %w", err)
	}

	err = p.updateMapReduceDesignDocument(name, config, db)
	if err != nil {
		return fmt.Errorf("failure while updating the MapReduce design document: %w", err)
	}

	return nil
}

func (p *Provider) updateMangoIndexDesignDocument(db db, config storage.StoreConfiguration, storeName string) error {
	existingIndexes, err := db.GetIndexes(context.Background())
	if err != nil {
		if err.Error() == databaseNotFoundErrMsgFromKivik {
			return fmt.Errorf(failGetExistingIndexes, storage.ErrStoreNotFound)
		}

		return fmt.Errorf(failGetExistingIndexes, err)
	}

	err = p.updateIndexes(db, config, existingIndexes, storeName)
	if err != nil {
		return fmt.Errorf("failure while updating indexes in CouchDB: %w", err)
	}

	return nil
}

func (p *Provider) updateIndexes(db db, config storage.StoreConfiguration,
	existingIndexes []kivik.Index, storeName string) error {
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

					p.logger.Infof("[Store name: %s] Skipping index creation for %s since the "+
						"index already exists.", storeName, tagName)

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

	err := p.createIndexes(db, tagNamesNeedIndexCreation, storeName)
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}

func (p *Provider) createIndexes(db db, tagNamesNeedIndexCreation []string, storeName string) error {
	for _, tagName := range tagNamesNeedIndexCreation {
		var attemptsMade int

		err := backoff.Retry(func() error {
			attemptsMade++

			err := db.CreateIndex(context.Background(), designDocumentName, tagName+"_index",
				`{"fields": ["tags.`+tagName+`"]}`)
			if err != nil {
				// If there are multiple CouchDB Providers trying to set store configurations, it's possible
				// to get a document update conflict. In cases where those multiple CouchDB providers are trying
				// to set the exact same store configuration, retrying here allows them to succeed without failing
				// unnecessarily.
				if err.Error() == mangoIndexDesignDocumentUpdateConflictErrMsgFromKivik {
					p.logger.Infof("[Store name: %s] Attempt %d - design document update conflict while creating "+
						"index for %s. This can happen if multiple CouchDB providers set the store configuration at the "+
						"same time.", storeName, attemptsMade, tagName)

					return fmt.Errorf(failCreateIndexDueToConflict, attemptsMade, err)
				}

				// This is an unexpected error.
				return backoff.Permanent(fmt.Errorf(failCreateIndex, err))
			}

			p.logger.Infof("[Store name: %s] Attempt %d - successfully created index for %s.",
				storeName, attemptsMade, tagName)

			return nil
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond), uint64(p.maxDocumentConflictRetries)))
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Provider) updateMapReduceDesignDocument(name string, config storage.StoreConfiguration, db db) error {
	var attemptsMade int

	err := backoff.Retry(func() error {
		attemptsMade++

		row := db.Get(context.Background(), mapReduceDesignDocumentNameWithPath)

		var existingDesignDocument designDoc

		err := row.ScanDoc(&existingDesignDocument)
		if err != nil {
			if !strings.Contains(err.Error(), docNotFoundErrMsgFromKivik) &&
				!strings.Contains(err.Error(), docDeletedErrMsgFromKivik) {
				return backoff.Permanent(fmt.Errorf("unexpected failure while checking for an "+
					"existing MapReduce design document: %w", err))
			}
		}

		if existingDesignDocHasAllViewsAlready(config, existingDesignDocument) {
			p.logger.Infof("[Store name: %s] Skipping count view creation for %v since they all already exist.",
				name, config.TagNames)
		} else {
			err = p.putMapReduceDesignDocument(config, existingDesignDocument.RevisionID, db, name, attemptsMade)
			if err != nil {
				return err
			}
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond), uint64(p.maxDocumentConflictRetries)))
	if err != nil {
		return err
	}

	return nil
}

func (p *Provider) putMapReduceDesignDocument(config storage.StoreConfiguration, existingRevID string, db db,
	storeName string, attemptsMade int) error {
	mapReduceDesignDocument := createMapReduceDesignDocument(config, existingRevID)

	mapReduceDesignDocumentBytes, err := json.Marshal(mapReduceDesignDocument)
	if err != nil {
		return fmt.Errorf("failed to marshal MapReduce design document: %w", err)
	}

	_, err = db.Put(context.Background(), mapReduceDesignDocumentNameWithPath, string(mapReduceDesignDocumentBytes))
	if err != nil {
		if err.Error() == documentUpdateConflictErrMsgFromKivik {
			// This means that the document was updated since we got the revision ID.
			// Need to get the new revision ID and try again.
			p.logger.Infof("[Store name: %s] Attempt %d - MapReduce design document update conflict. "+
				"This can happen if multiple CouchDB providers set the store configuration at the "+
				"same time.", storeName, attemptsMade)

			return fmt.Errorf(failUpdateDesignDocumentDueToConflict, attemptsMade, err)
		}

		// This is an unexpected error.
		return backoff.Permanent(fmt.Errorf(failCreateOrUpdateMapReduceDesignDoc, err))
	}

	p.logger.Infof("[Store name: %s] Attempt %d - successfully created count views for %v.",
		storeName, attemptsMade, config.TagNames)

	return nil
}

func (p *Provider) removeStore(name string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	_, ok := p.openStores[name]
	if ok {
		delete(p.openStores, name)
	}
}

// store represents a CouchDB-backed database.
type store struct {
	name                       string
	logger                     logger
	db                         db
	maxDocumentConflictRetries int
	marshal                    marshalFunc
	close                      closer
}

// Put stores the key + value pair along with the (optional) tags.
// TODO (#81) If data is binary and large, store as CouchDB attachment instead.
func (s *store) Put(k string, v []byte, tags ...storage.Tag) error {
	errInputValidation := validatePutInput(k, v, tags)
	if errInputValidation != nil {
		return errInputValidation
	}

	var newDocument document

	newDocument.Value = v

	err := setDocumentTags(&newDocument, tags)
	if err != nil {
		return err
	}

	err = s.put(k, newDocument)
	if err != nil {
		return fmt.Errorf("failure while putting document into CouchDB database: %w", err)
	}

	return nil
}

// Get fetches the value associated with the given key.
func (s *store) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	var retrievedDocument document

	row := s.db.Get(context.Background(), k)

	err := row.ScanDoc(&retrievedDocument)
	if err != nil {
		if err.Error() == docNotFoundErrMsgFromKivik || err.Error() == docDeletedErrMsgFromKivik {
			return nil, fmt.Errorf(failureWhileScanningRow, storage.ErrDataNotFound)
		}

		return nil, fmt.Errorf(failureWhileScanningRow, err)
	}

	return retrievedDocument.Value, nil
}

// GetTags fetches all tags associated with the given key.
func (s *store) GetTags(k string) ([]storage.Tag, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	var retrievedDocument document

	row := s.db.Get(context.Background(), k)

	err := row.ScanDoc(&retrievedDocument)
	if err != nil {
		if err.Error() == docNotFoundErrMsgFromKivik || err.Error() == docDeletedErrMsgFromKivik {
			return nil, storage.ErrDataNotFound
		}

		return nil, err
	}

	tags, err := getTagsFromDocument(&retrievedDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags from document: %w", err)
	}

	return tags, nil
}

// GetBulk fetches the values associated with the given keys.
// If a key doesn't exist, then a nil []byte is returned for that value. It is not considered an error.
func (s *store) GetBulk(keys ...string) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("keys slice must contain at least one key")
	}

	documents, err := s.getDocuments(keys)
	if err != nil {
		return nil, fmt.Errorf(failGetDocs, err)
	}

	return getValuesFromDocuments(documents), nil
}

// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
// If TagValue is not provided, then all data associated with the TagName will be returned.
// For now, expression can only be a single tag Name + Value pair.
// If no options are provided, then defaults will be used.
// If sorting is used, then the tag used for sorting must be indexed.
// For improved performance with large datasets, ensure that the tag name you are querying is included in the store
// config, as this will ensure that it's indexed in CouchDB.
func (s *store) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	if expression == "" {
		return &couchDBResultsIterator{}, errInvalidQueryExpressionFormat
	}

	queryOptions := getQueryOptions(options)

	expressionSplit := strings.Split(expression, ":")

	query := findQuery{
		Limit: queryOptions.PageSize,
		Skip:  queryOptions.InitialPageNum * queryOptions.PageSize,
	}

	if queryOptions.SortOptions != nil {
		var sortOrder string
		if queryOptions.SortOptions.Order == storage.SortAscending {
			sortOrder = "asc"
		} else {
			sortOrder = "desc"
		}

		query.Sort = json.RawMessage(fmt.Sprintf(
			sortOptionsTemplate, queryOptions.SortOptions.TagName, sortOrder))
	}

	var resultRows *kivik.Rows

	var queryTagName, queryTagValue string

	switch len(expressionSplit) {
	case expressionTagNameOnlyLength:
		queryTagName = expressionSplit[0]
		query.Selector = json.RawMessage(fmt.Sprintf(fieldNameExistsSelectorTemplate, queryTagName))
	case expressionTagNameAndValueLength:
		queryTagName = expressionSplit[0]
		queryTagValue = expressionSplit[1]
		query.Selector = json.RawMessage(fmt.Sprintf(fieldNameAndValueSelectorTemplate,
			queryTagName, queryTagValue))
	default:
		return &couchDBResultsIterator{}, errInvalidQueryExpressionFormat
	}

	resultRows, err := s.executeFindQuery(&query)
	if err != nil {
		return nil, err
	}

	return &couchDBResultsIterator{
		store:         s,
		resultRows:    resultRows,
		pageSize:      queryOptions.PageSize,
		queryTagName:  queryTagName,
		queryTagValue: queryTagValue,
		findQuery:     query,
		marshal:       json.Marshal,
	}, nil
}

// Delete deletes the key + value pair (and all tags) associated with k.
func (s *store) Delete(k string) error {
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
func (s *store) Batch(operations []storage.Operation) error {
	if len(operations) == 0 {
		return errors.New("batch requires at least one operation")
	}

	// If CouchDB receives the same key multiple times in one batch call, it will just keep the first operation and
	// disregard the rest. We want the opposite behaviour - we need it to only keep the last operation and disregard
	// the earlier ones as if they've been overwritten or deleted.
	// Note that due to this, CouchDB will not have any revision history of those duplicates.
	operations = removeDuplicatesKeepingOnlyLast(operations)

	keys := make([]string, len(operations))

	for i, operation := range operations {
		keys[i] = operation.Key
	}

	existingDocuments, err := s.getDocuments(keys)
	if err != nil {
		return fmt.Errorf(failGetDocs, err)
	}

	documentsToPut := make([]interface{}, len(existingDocuments))

	for i, existingDocument := range existingDocuments {
		var newDocument document
		newDocument.ID = keys[i]

		err = setDocumentTags(&newDocument, operations[i].Tags)
		if err != nil {
			return fmt.Errorf("failed to set document tags on the operation at index %d: %w", i, err)
		}

		if existingDocument != nil {
			// If there was a document that was previously deleted that has the same ID as a new document,
			// then we must omit the revision ID. CouchDB won't create the new document otherwise.
			if !existingDocument.Deleted {
				newDocument.RevisionID = existingDocument.RevisionID
			}
		}

		if operations[i].Value == nil { // This operation is a delete
			newDocument.Deleted = true
		} else {
			newDocument.Value = operations[i].Value
		}

		documentsToPut[i] = newDocument
	}

	// TODO (#50): Examine BulkResults value returned from s.db.BulkDocs and return a storage.MultiError.
	_, err = s.db.BulkDocs(context.Background(), documentsToPut)
	if err != nil {
		return fmt.Errorf("failure while doing CouchDB bulk docs call: %w", err)
	}

	return nil
}

// Close closes this store.
func (s *store) Close() error {
	s.close(s.name)

	err := s.db.Close(context.Background())
	if err != nil {
		return fmt.Errorf("failed to close database client: %w", err)
	}

	return nil
}

// Flush doesn't do anything since this store type doesn't queue values.
func (s *store) Flush() error {
	return nil
}

func (s *store) put(k string, documentToPut document) error {
	var attemptsMade int

	err := backoff.Retry(func() error {
		attemptsMade++

		revID, err := s.getRevID(k)
		if err != nil {
			// This is an unexpected error. Return a backoff.Permanent wrapped error to prevent further retries.
			return backoff.Permanent(fmt.Errorf(failGetRevisionID, err))
		}

		if revID != "" {
			documentToPut.RevisionID = revID
		}

		documentBytes, err := s.marshal(documentToPut)
		if err != nil {
			return fmt.Errorf("failed to marshal document: %w", err)
		}

		_, err = s.db.Put(context.Background(), k, documentBytes)
		if err != nil {
			if err.Error() == documentUpdateConflictErrMsgFromKivik {
				// This means that the document was updated since we got the revision ID.
				// Need to get the new revision ID and try again.

				s.logger.Infof("[Store name: %s] [Key: %s] Attempt %d - document update conflict. "+
					"This can happen if multiple CouchDB providers store data under the same key at the same time.",
					s.name, k, attemptsMade)

				return fmt.Errorf(failUpdateDocumentDueToConflict, k, attemptsMade, err)
			}

			// This is an unexpected error.
			return backoff.Permanent(fmt.Errorf(failPutValueViaClient, err))
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond), uint64(s.maxDocumentConflictRetries)))
	if err != nil {
		return err
	}

	return nil
}

// If the document can't be found, then a blank ID is returned.
func (s *store) getRevID(k string) (string, error) {
	var retrievedDocument document

	row := s.db.Get(context.Background(), k)

	err := row.ScanDoc(&retrievedDocument)
	if err != nil {
		if strings.Contains(err.Error(), docNotFoundErrMsgFromKivik) ||
			strings.Contains(err.Error(), docDeletedErrMsgFromKivik) {
			return "", nil
		}

		return "", err
	}

	return retrievedDocument.RevisionID, nil
}

// getDocuments returns documents from CouchDB using a bulk REST call.
// If a document is not found, then the document will be nil. It is not considered an error.
func (s *store) getDocuments(keys []string) ([]*document, error) {
	bulkGetReferences := make([]kivik.BulkGetReference, len(keys))
	for i, key := range keys {
		bulkGetReferences[i].ID = key
	}

	rows, err := s.db.BulkGet(context.Background(), bulkGetReferences)
	if err != nil {
		return nil, fmt.Errorf("failure while sending request to CouchDB bulk docs endpoint: %w", err)
	}

	documents, err := getDocumentsFromRows(rows)
	if err != nil {
		return nil, fmt.Errorf("failed to get documents from rows: %w", err)
	}

	if len(documents) != len(keys) {
		return nil, fmt.Errorf("received %d documents, but %d were expected", len(documents), len(keys))
	}

	return documents, nil
}

func (s *store) executeFindQuery(query *findQuery) (*kivik.Rows, error) {
	findQueryBytes, err := s.marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal find query to JSON: %w", err)
	}

	resultRows, err := s.db.Find(context.Background(), findQueryBytes)
	if err != nil {
		return nil, fmt.Errorf(failSendRequestToFindEndpoint, err)
	}

	return resultRows, nil
}

type couchDBResultsIterator struct {
	store                          *store
	resultRows                     rows
	pageSize                       int
	queryTagName                   string
	queryTagValue                  string
	findQuery                      findQuery
	numDocumentsReturnedInThisPage int
	marshal                        marshalFunc
}

// Next moves the pointer to the next value in the iterator. It returns false if the iterator is exhausted.
// Note that the Kivik library automatically closes the kivik.Rows iterator if the iterator is exhausted.
func (i *couchDBResultsIterator) Next() (bool, error) {
	nextCallResult := i.resultRows.Next()

	// If no applicable index could be found to speed up the query, then we will receive a warning here.
	// This most likely reasons for no index being found is that either the Provider's StoreConfiguration
	// was never set, or it was set but was missing the queried tag name.
	// This value is only set by Kivik on the final iteration (once all the rows have been iterated through).
	err := i.logAnyWarning()
	if err != nil {
		return false, fmt.Errorf("failed to log a warning: %w", err)
	}

	err = i.resultRows.Err()
	if err != nil {
		return false, fmt.Errorf("failure during iteration of result rows: %w", err)
	}

	if nextCallResult {
		i.numDocumentsReturnedInThisPage++
	} else {
		if i.numDocumentsReturnedInThisPage < i.pageSize {
			// All documents have been returned - no need to attempt fetching any more pages.
			return false, nil
		}

		err := i.resultRows.Close()
		if err != nil {
			return false, fmt.Errorf("failed to close result rows before fetching new page: %w", err)
		}

		// Try fetching another page of documents.
		// Kivik only sets the bookmark value after all result rows have been enumerated via the Next call.
		// Note that the presence of a bookmark doesn't guarantee that there are more results.
		// It's necessary to instead compare the number of returned documents against the page size (done above)
		// See https://docs.couchdb.org/en/stable/api/database/find.html#pagination for more information.
		newPageNextCallResult, err := i.fetchAnotherPage()
		if err != nil {
			return false, fmt.Errorf("failure while fetching new page: %w", err)
		}

		return newPageNextCallResult, nil
	}

	return nextCallResult, nil
}

// Close releases associated resources. Release should always result in success
// and can be called multiple times without causing an error.
func (i *couchDBResultsIterator) Close() error {
	err := i.resultRows.Close()
	if err != nil {
		return fmt.Errorf("failed to close result rows: %w", err)
	}

	return nil
}

// Key returns the key of the current key-value pair.
// A nil error likely means that the key list is exhausted.
func (i *couchDBResultsIterator) Key() (string, error) {
	var retrievedDocument document

	err := i.resultRows.ScanDoc(&retrievedDocument)
	if err != nil {
		return "", fmt.Errorf(failWhileScanResultRows, err)
	}

	return retrievedDocument.ID, nil
}

// Value returns the value of the current key-value pair.
func (i *couchDBResultsIterator) Value() ([]byte, error) {
	var retrievedDocument document

	err := i.resultRows.ScanDoc(&retrievedDocument)
	if err != nil {
		return nil, fmt.Errorf(failWhileScanResultRows, err)
	}

	return retrievedDocument.Value, nil
}

func (i *couchDBResultsIterator) Tags() ([]storage.Tag, error) {
	var retrievedDocument document

	err := i.resultRows.ScanDoc(&retrievedDocument)
	if err != nil {
		return nil, fmt.Errorf(failWhileScanResultRows, err)
	}

	tags, err := getTagsFromDocument(&retrievedDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags from document: %w", err)
	}

	return tags, nil
}

// This runs a separate query on CouchDB, so the total item count returned reflects the current state of the database,
// which may have changed since this iterator was created.
func (i *couchDBResultsIterator) TotalItems() (int, error) {
	var options kivik.Options

	if i.queryTagValue != "" {
		options = kivik.Options{
			"key": i.queryTagValue,
		}
	}

	resultRows, err := i.store.db.Query(context.Background(),
		mapReduceDesignDocumentName,
		fmt.Sprintf(countViewNameTemplate, i.queryTagName),
		options)
	if err != nil {
		if strings.Contains(err.Error(), docNotFoundErrMsgFromKivik) ||
			strings.Contains(err.Error(), "missing-named_view") {
			return -1, fmt.Errorf("failed to query CouchDB. "+
				"The view could not be found for counting the number of query results. "+
				"To resolve this, make sure the store configuration has been set using the "+
				"Store.SetStoreConfig method. "+
				"The store configuration must contain the tag name used in the query. "+
				"Original error from CouchDB client: %w", err)
		}

		return -1, fmt.Errorf("failed to query CouchDB: %w", err)
	}

	if !resultRows.Next() {
		return 0, nil
	}

	var count int

	err = resultRows.ScanValue(&count)
	if err != nil {
		return -1, err
	}

	return count, nil
}

func (i *couchDBResultsIterator) fetchAnotherPage() (bool, error) {
	var err error

	i.findQuery.Bookmark = i.resultRows.Bookmark()
	// If there was an initial page number specified (resulting in Skip being set), this will make sure we don't skip
	// results on subsequent pages.
	i.findQuery.Skip = 0

	findQueryBytes, err := json.Marshal(i.findQuery)
	if err != nil {
		return false, fmt.Errorf("failed to marshal find query to JSON: %w", err)
	}

	i.resultRows, err = i.store.db.Find(context.Background(), findQueryBytes)
	if err != nil {
		return false, fmt.Errorf("failure while sending request to CouchDB find endpoint: %w", err)
	}

	followupNextCallResult := i.resultRows.Next()

	if followupNextCallResult {
		i.numDocumentsReturnedInThisPage = 1
	}

	return followupNextCallResult, nil
}

func validatePutInput(key string, value []byte, tags []storage.Tag) error {
	if key == "" {
		return errors.New("key cannot be empty")
	}

	if value == nil {
		return errors.New("value cannot be nil")
	}

	for _, tag := range tags {
		if strings.Contains(tag.Name, ":") {
			return fmt.Errorf(invalidTagName, tag.Name)
		}

		if strings.Contains(tag.Value, ":") {
			return fmt.Errorf(invalidTagValue, tag.Value)
		}
	}

	return nil
}

func getQueryOptions(options []storage.QueryOption) storage.QueryOptions {
	var queryOptions storage.QueryOptions

	for _, option := range options {
		option(&queryOptions)
	}

	if queryOptions.PageSize < 1 {
		queryOptions.PageSize = 25
	}

	if queryOptions.InitialPageNum < 0 {
		queryOptions.InitialPageNum = 0
	}

	return queryOptions
}

func getValuesFromDocuments(documents []*document) [][]byte {
	storedValues := make([][]byte, len(documents))

	for i, document := range documents {
		// If the document is nil, this means that the value could not be found.
		// It is not considered an error.
		if document == nil {
			storedValues[i] = nil

			continue
		}

		// CouchDB still returns a document if the key has been deleted, so if this is a "deleted" document
		// then we need to return nil to indicate that the value could not be found.
		if document.Deleted {
			storedValues[i] = nil

			continue
		}

		storedValues[i] = document.Value
	}

	return storedValues
}

func getDocumentsFromRows(rows rows) ([]*document, error) {
	moreDocumentsToRead := rows.Next()

	var documents []*document

	for moreDocumentsToRead {
		var retrievedDocument document
		err := rows.ScanDoc(&retrievedDocument)
		// For the regular Get method, Kivik actually returns a different error message if a document was deleted.
		// When doing a bulk get, however, Kivik doesn't return an error message, and we have to check the "_deleted"
		// field in the doc later. This is done in the getValuesFromDocuments method.
		// If the document wasn't found, we allow the nil doc to be appended since we don't consider it to be
		// an error.
		if err != nil && !strings.Contains(err.Error(), bulkGetDocNotFoundErrMsgFromKivik) {
			return nil, fmt.Errorf(failWhileScanResultRows, err)
		}

		documents = append(documents, &retrievedDocument)

		moreDocumentsToRead = rows.Next()
	}

	return documents, nil
}

func getTagsFromDocument(document *document) ([]storage.Tag, error) {
	tags := make([]storage.Tag, len(document.Tags))

	var counter int

	for tagName, tagValue := range document.Tags {
		tagValueAsFloat64, isFloat64 := tagValue.(float64)
		if isFloat64 {
			tags[counter] = storage.Tag{
				Name:  tagName,
				Value: fmt.Sprintf("%.0f", tagValueAsFloat64),
			}
		} else {
			tagValueAsString, isString := tagValue.(string)
			if !isString {
				return nil, errors.New("tag value from document is of unknown type. " +
					"it could not be asserted as a float64 or string")
			}

			tags[counter] = storage.Tag{
				Name:  tagName,
				Value: tagValueAsString,
			}
		}

		counter++
	}

	return tags, nil
}

func (i *couchDBResultsIterator) logAnyWarning() error {
	warningMsg := i.resultRows.Warning()

	if warningMsg != "" {
		findQueryBytes, err := i.marshal(i.findQuery)
		if err != nil {
			return fmt.Errorf("failed to marshal find query for log: %w", err)
		}

		logMessage := fmt.Sprintf(`[Store name: %s] Received warning from CouchDB. `+
			`Message: %s Original query: %s.`, i.store.name, warningMsg, string(findQueryBytes))

		if warningMsg == "No matching index found, create an index to optimize query time." {
			logMessage += " To resolve this, make sure the store configuration has been set using the " +
				"Store.SetStoreConfig method. The store configuration must contain the tag name used in the query."
		}

		i.store.logger.Warnf(logMessage)
	}

	return nil
}

func existingDesignDocHasAllViewsAlready(config storage.StoreConfiguration, existingDesignDocument designDoc) bool {
	allExistAlready := true

	for _, tagName := range config.TagNames {
		_, allExistAlready = existingDesignDocument.Views[fmt.Sprintf(countViewNameTemplate, tagName)]

		if !allExistAlready {
			break
		}
	}

	return allExistAlready
}

func createMapReduceDesignDocument(config storage.StoreConfiguration, existingRevID string) designDoc {
	views := map[string]map[string]string{}

	for _, tagName := range config.TagNames {
		view := map[string]string{}

		view["map"] = fmt.Sprintf("function(doc){if('%s'in doc.tags){emit(doc.tags.%s,doc.value);}}",
			tagName, tagName)
		view["reduce"] = "_count"

		views[fmt.Sprintf(countViewNameTemplate, tagName)] = view
	}

	return designDoc{RevisionID: existingRevID, Views: views}
}

func removeDuplicatesKeepingOnlyLast(operations []storage.Operation) []storage.Operation {
	indexOfOperationToCheck := len(operations) - 1

	for indexOfOperationToCheck > 0 {
		var indicesToRemove []int

		keyToCheck := operations[indexOfOperationToCheck].Key
		for i := indexOfOperationToCheck - 1; i >= 0; i-- {
			if operations[i].Key == keyToCheck {
				indicesToRemove = append(indicesToRemove, i)
			}
		}

		for _, indexToRemove := range indicesToRemove {
			operations = append(operations[:indexToRemove], operations[indexToRemove+1:]...)
		}

		// At this point, we now know that any duplicates of operations[indexOfOperationToCheck] are removed,
		// and only the last instance of it remains.

		// Now we need to check the next key in order to ensure it's unique.
		// If this sets indexOfOperationToCheck to -1, then we're done.
		indexOfOperationToCheck = indexOfOperationToCheck - len(indicesToRemove) - 1
	}

	return operations
}

func setDocumentTags(document *document, tags []storage.Tag) error {
	document.Tags = make(map[string]interface{})

	for _, tag := range tags {
		_, exists := document.Tags[tag.Name]
		if exists {
			return fmt.Errorf("tag name %s appears in more than one tag. A single key-value pair cannot "+
				"have multiple tags that share the same tag name", tag.Name)
		}

		tagValueAsInt, err := strconv.Atoi(tag.Value)
		if err != nil {
			document.Tags[tag.Name] = tag.Value
		} else {
			document.Tags[tag.Name] = tagValueAsInt
		}
	}

	return nil
}

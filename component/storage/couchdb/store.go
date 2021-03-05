/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package couchdb implements a storage interface for Aries (aries-framework-go).
package couchdb

import ( //nolint:gci // False positive, seemingly caused by the CouchDB driver comment.
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	// The CouchDB driver. This import must be here for the Kivik client instantiation with a CouchDB driver to work.
	_ "github.com/go-kivik/couchdb/v3"
	"github.com/go-kivik/kivik/v3"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	couchDBUsersTable = "_users"
	idFieldKey        = "_id"
	revIDFieldKey     = "_rev"
	deletedFieldKey   = "_deleted"

	designDocumentName = "AriesStorageDesignDocument"
	payloadFieldKey    = "payload"

	// Hardcoded strings returned from Kivik/CouchDB that we check for.
	docNotFoundErrMsgFromKivik            = "Not Found: missing"
	bulkGetDocNotFoundErrMsgFromKivik     = "not_found: missing"
	docDeletedErrMsgFromKivik             = "Not Found: deleted"
	databaseNotFoundErrMsgFromKivik       = "Not Found: Database does not exist."
	documentUpdateConflictErrMsgFromKivik = "Conflict: Document update conflict."

	failGetDatabaseHandle         = "failed to get database handle: %w"
	failGetExistingIndexes        = "failed to get existing indexes: %w"
	failureWhileScanningRow       = "failure while scanning row: %w"
	failGetTagsFromRawDoc         = "failed to get tags from raw CouchDB document: %w"
	failGetRevisionID             = "failed to get revision ID: %w"
	failPutValueViaClient         = "failed to put value via client: %w"
	failWhileScanResultRows       = "failure while scanning result rows: %w"
	failSendRequestToFindEndpoint = "failure while sending request to CouchDB find endpoint: %w"
	failGetRawDocs                = "failure while getting raw CouchDB documents: %w"

	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2

	tagNameOnlyQueryTemplate     = `{"selector":{"%s":{"$exists":true}},"limit":%d}`
	tagNameAndValueQueryTemplate = `{"selector":{"%s":"%s"},"limit":%d}`
)

var errInvalidQueryExpressionFormat = errors.New("invalid expression format. " +
	"it must be in the following format: TagName:TagValue")

type marshalFunc func(interface{}) ([]byte, error)

type closer func(storeName string)

type logger interface {
	Warnf(msg string, args ...interface{})
}

type defaultLogger struct {
	logger *log.Logger
}

func (d *defaultLogger) Warnf(msg string, args ...interface{}) {
	d.logger.Printf(msg, args...)
}

type db interface {
	Get(ctx context.Context, docID string, options ...kivik.Options) *kivik.Row
	Put(ctx context.Context, docID string, doc interface{}, options ...kivik.Options) (rev string, err error)
	Find(ctx context.Context, query interface{}, options ...kivik.Options) (*kivik.Rows, error)
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
	logger                        logger
	hostURL                       string
	couchDBClient                 *kivik.Client
	dbPrefix                      string
	openStores                    map[string]*store
	maxDocumentConflictRetriesSet bool
	maxDocumentConflictRetries    int
	lock                          sync.RWMutex
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

// WithLogger is an option for specifying a custom logger.
// The standard Golang logger will be used if this option is not provided.
func WithLogger(logger logger) Option {
	return func(opts *Provider) {
		opts.logger = logger
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
// TODO (#48): Allow context to be passed in.
func NewProvider(hostURL string, opts ...Option) (*Provider, error) {
	err := PingCouchDB(hostURL)
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
// Indexes are created based on the tag names in config. This allows the store.Query method to operate faster.
// Existing tag names/indexes in the store that are not in the config passed in here will be removed.
// The store must be created prior to calling this method.
// If duplicate tags are provided, then CouchDB will ignore them.
func (p *Provider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	err := validateTagNames(config)
	if err != nil {
		return fmt.Errorf("invalid tag names: %w", err)
	}

	name = strings.ToLower(p.dbPrefix + name)

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

	maxDocumentConflictRetries := 3

	if p.maxDocumentConflictRetriesSet {
		maxDocumentConflictRetries = p.maxDocumentConflictRetries
	}

	newStore := &store{
		name: name, logger: p.logger, db: db, maxDocumentConflictRetries: maxDocumentConflictRetries,
		marshal: json.Marshal, close: p.removeStore,
	}

	p.openStores[name] = newStore

	return newStore, nil
}

func (p *Provider) setIndexes(db *kivik.DB, config storage.StoreConfiguration) error {
	existingIndexes, err := db.GetIndexes(context.Background())
	if err != nil {
		if err.Error() == databaseNotFoundErrMsgFromKivik {
			return fmt.Errorf(failGetExistingIndexes, storage.ErrStoreNotFound)
		}

		return fmt.Errorf(failGetExistingIndexes, err)
	}

	err = updateIndexes(db, config, existingIndexes)
	if err != nil {
		return fmt.Errorf("failure while creating indexes in CouchDB: %w", err)
	}

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
// TODO (#44) Tags do not have to be defined in the store config prior to storing data that uses them.
//  Should all store implementations require tags to be defined in store config before allowing them to be used?
// TODO (#81) If data isn't JSON, store as CouchDB attachment instead.
func (s *store) Put(k string, v []byte, tags ...storage.Tag) error {
	if k == "" {
		return errors.New("key cannot be empty")
	}

	if v == nil {
		return errors.New("value cannot be nil")
	}

	rawDoc := make(map[string]interface{})

	rawDoc[payloadFieldKey] = base64.StdEncoding.EncodeToString(v)

	err := addTagsToRawDoc(rawDoc, tags)
	if err != nil {
		return fmt.Errorf("failed to add tags to the raw document: %w", err)
	}

	for _, tag := range tags {
		if tag.Name == payloadFieldKey {
			return errors.New(`tag name cannot be "payload" as it is a reserved keyword`)
		}

		rawDoc[tag.Name] = tag.Value
	}

	valueToPut, err := s.marshal(rawDoc)
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
func (s *store) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	rawDoc := make(map[string]interface{})

	row := s.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if err.Error() == docNotFoundErrMsgFromKivik || err.Error() == docDeletedErrMsgFromKivik {
			return nil, fmt.Errorf(failureWhileScanningRow, storage.ErrDataNotFound)
		}

		return nil, fmt.Errorf(failureWhileScanningRow, err)
	}

	storedValueBase64, err := getStringValueFromRawDoc(rawDoc, payloadFieldKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get payload from raw document: %w", err)
	}

	return base64.StdEncoding.DecodeString(storedValueBase64)
}

// GetTags fetches all tags associated with the given key.
func (s *store) GetTags(k string) ([]storage.Tag, error) {
	if k == "" {
		return nil, errors.New("key is mandatory")
	}

	rawDoc := make(map[string]interface{})

	row := s.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if err.Error() == docNotFoundErrMsgFromKivik || err.Error() == docDeletedErrMsgFromKivik {
			return nil, storage.ErrDataNotFound
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
func (s *store) GetBulk(keys ...string) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("keys slice must contain at least one key")
	}

	rawDocs, err := s.getRawDocs(keys)
	if err != nil {
		return nil, fmt.Errorf(failGetRawDocs, err)
	}

	values, err := getPayloadsFromRawDocs(rawDocs)
	if err != nil {
		return nil, fmt.Errorf("failure while getting stored values from raw docs: %w", err)
	}

	return values, nil
}

// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
// If TagValue is not provided, then all data associated with the TagName will be returned.
// For now, expression can only be a single tag Name + Value pair.
// If no options are provided, then defaults will be used.
// For improved performance, ensure that the tag name you are querying is included in the store config, as this
// will ensure that it's indexed in CouchDB.
// TODO (#44) Should we make the store config mandatory?
func (s *store) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	if expression == "" {
		return &couchDBResultsIterator{}, errInvalidQueryExpressionFormat
	}

	queryOptions := getQueryOptions(options)

	expressionSplit := strings.Split(expression, ":")

	switch len(expressionSplit) {
	case expressionTagNameOnlyLength:
		expressionTagName := expressionSplit[0]

		findQuery := fmt.Sprintf(tagNameOnlyQueryTemplate, expressionTagName, queryOptions.PageSize)

		resultRows, err := s.db.Find(context.Background(), findQuery)
		if err != nil {
			return nil, fmt.Errorf(failSendRequestToFindEndpoint, err)
		}

		queryWithPageSizeAndBookmarkPlaceholders := `{"selector":{"` +
			expressionTagName + `":{"$exists":true}},"limit":%d,"bookmark":"%s"}`

		return &couchDBResultsIterator{
			store:                                    s,
			resultRows:                               resultRows,
			pageSize:                                 queryOptions.PageSize,
			queryWithPageSizeAndBookmarkPlaceholders: queryWithPageSizeAndBookmarkPlaceholders,
		}, nil
	case expressionTagNameAndValueLength:
		expressionTagName := expressionSplit[0]
		expressionTagValue := expressionSplit[1]

		findQuery := fmt.Sprintf(tagNameAndValueQueryTemplate,
			expressionTagName, expressionTagValue, queryOptions.PageSize)

		queryWithPageSizeAndBookmarkPlaceholders := `{"selector":{"` +
			expressionTagName + `":"` + expressionTagValue + `"},"limit":%d,"bookmark":"%s"}`

		resultRows, err := s.db.Find(context.Background(), findQuery)
		if err != nil {
			return nil, fmt.Errorf(failSendRequestToFindEndpoint, err)
		}

		return &couchDBResultsIterator{
			store:                                    s,
			resultRows:                               resultRows,
			pageSize:                                 queryOptions.PageSize,
			queryWithPageSizeAndBookmarkPlaceholders: queryWithPageSizeAndBookmarkPlaceholders,
		}, nil
	default:
		return &couchDBResultsIterator{}, errInvalidQueryExpressionFormat
	}
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
	// If CouchDB receives the same key multiple times in one batch call, it will just keep the first operation and
	// disregard the rest. We want the opposite behaviour - we need it to only keep the last operation and disregard
	// the earlier ones as if they've been overwritten or deleted.
	// Note that due to this, CouchDB will not have any revision history of those duplicates.
	operations = removeDuplicatesKeepingOnlyLast(operations)

	keys := make([]string, len(operations))

	for i, operation := range operations {
		keys[i] = operation.Key
	}

	existingRawDocs, err := s.getRawDocs(keys)
	if err != nil {
		return fmt.Errorf(failGetRawDocs, err)
	}

	rawDocsToPut := make([]interface{}, len(existingRawDocs))

	for i, existingRawDoc := range existingRawDocs {
		rawDocToPut := make(map[string]interface{})
		rawDocToPut[idFieldKey] = keys[i]

		errAddTags := addTagsToRawDoc(rawDocToPut, operations[i].Tags)
		if errAddTags != nil {
			return fmt.Errorf("failed to add tags to raw document: %w", err)
		}

		if existingRawDoc != nil {
			// If there was a document that was previously deleted that has the same ID as a new document,
			// then we must omit the revision ID. CouchDB won't create the new document otherwise.
			_, containsIsDeleted := existingRawDoc[deletedFieldKey]
			if !containsIsDeleted {
				rawDocToPut[revIDFieldKey] = existingRawDoc[revIDFieldKey]
			}
		}

		if operations[i].Value == nil { // This operation is a delete
			rawDocToPut["_deleted"] = true
		} else {
			rawDocToPut[payloadFieldKey] = base64.StdEncoding.EncodeToString(operations[i].Value)
		}

		rawDocsToPut[i] = rawDocToPut
	}

	// TODO (#50): Examine BulkResults value returned from s.db.BulkDocs and return a storage.MultiError.
	_, err = s.db.BulkDocs(context.Background(), rawDocsToPut)
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

// This store type doesn't queue values, so there's never anything to flush.
func (s *store) Flush() error {
	return nil
}

func (s *store) put(k string, value []byte) error {
	err := backoff.Retry(func() error {
		revID, err := s.getRevID(k)
		if err != nil {
			// This is an unexpected error. Return a backoff.Permanent wrapped error to prevent further retries.
			return backoff.Permanent(fmt.Errorf(failGetRevisionID, err))
		}

		if revID != "" {
			value = []byte(`{"` + revIDFieldKey + `":"` + revID + `",` + string(value[1:]))
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
func (s *store) getRevID(k string) (string, error) {
	rawDoc := make(map[string]interface{})

	row := s.db.Get(context.Background(), k)

	err := row.ScanDoc(&rawDoc)
	if err != nil {
		if strings.Contains(err.Error(), docNotFoundErrMsgFromKivik) ||
			strings.Contains(err.Error(), docDeletedErrMsgFromKivik) {
			return "", nil
		}

		return "", err
	}

	revID, err := getStringValueFromRawDoc(rawDoc, revIDFieldKey)
	if err != nil {
		return "", fmt.Errorf("failed to get revision ID from the raw document: %w", err)
	}

	return revID, nil
}

// getRawDocs returns the raw documents from CouchDB using a bulk REST call.
// If a document is not found, then the raw document will be nil. It is not considered an error.
func (s *store) getRawDocs(keys []string) ([]map[string]interface{}, error) {
	bulkGetReferences := make([]kivik.BulkGetReference, len(keys))
	for i, key := range keys {
		bulkGetReferences[i].ID = key
	}

	rows, err := s.db.BulkGet(context.Background(), bulkGetReferences)
	if err != nil {
		return nil, fmt.Errorf("failure while sending request to CouchDB bulk docs endpoint: %w", err)
	}

	rawDocs, err := getRawDocsFromRows(rows)
	if err != nil {
		return nil, fmt.Errorf("failed to get raw documents from rows: %w", err)
	}

	if len(rawDocs) != len(keys) {
		return nil, fmt.Errorf("received %d raw documents, but %d were expected", len(rawDocs), len(keys))
	}

	return rawDocs, nil
}

type couchDBResultsIterator struct {
	store                                    *store
	resultRows                               rows
	pageSize                                 int
	queryWithPageSizeAndBookmarkPlaceholders string
	numDocumentsReturnedInThisPage           int
}

// Next moves the pointer to the next value in the iterator. It returns false if the iterator is exhausted.
// Note that the Kivik library automatically closes the kivik.Rows iterator if the iterator is exhausted.
func (i *couchDBResultsIterator) Next() (bool, error) {
	nextCallResult := i.resultRows.Next()

	// If no applicable index could be found to speed up the query, then we will receive a warning here.
	// This most likely reasons for no index being found is that either the Provider's StoreConfiguration
	// was never set, or it was set but was missing the queried tag name.
	// This value is only set by Kivik on the final iteration (once all the rows have been iterated through).
	logAnyWarning(i)

	err := i.resultRows.Err()
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
	id, err := getValueFromRows(i.resultRows, idFieldKey)
	if err != nil {
		return "", fmt.Errorf(`failed to get %s from rows: %w`, idFieldKey, err)
	}

	return id, nil
}

// Value returns the value of the current key-value pair.
func (i *couchDBResultsIterator) Value() ([]byte, error) {
	valueBase64Encoded, err := getValueFromRows(i.resultRows, payloadFieldKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get payload from rows: %w", err)
	}

	return base64.StdEncoding.DecodeString(valueBase64Encoded)
}

func (i *couchDBResultsIterator) Tags() ([]storage.Tag, error) {
	rawDoc := make(map[string]interface{})

	err := i.resultRows.ScanDoc(&rawDoc)
	if err != nil {
		return nil, fmt.Errorf(failWhileScanResultRows, err)
	}

	tags, err := getTagsFromRawDoc(rawDoc)
	if err != nil {
		return nil, fmt.Errorf(failGetTagsFromRawDoc, err)
	}

	return tags, nil
}

func (i *couchDBResultsIterator) fetchAnotherPage() (bool, error) {
	var err error

	query := fmt.Sprintf(i.queryWithPageSizeAndBookmarkPlaceholders, i.pageSize, i.resultRows.Bookmark())

	i.resultRows, err = i.store.db.Find(context.Background(), query)
	if err != nil {
		return false, fmt.Errorf("failure while sending request to CouchDB find endpoint: %w", err)
	}

	followupNextCallResult := i.resultRows.Next()

	if followupNextCallResult {
		i.numDocumentsReturnedInThisPage = 1
	}

	return followupNextCallResult, nil
}

func validateTagNames(config storage.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if tagName == payloadFieldKey {
			return errors.New(`tag name cannot be "payload" as it is a reserved keyword`)
		}
	}

	return nil
}

func updateIndexes(db *kivik.DB, config storage.StoreConfiguration, existingIndexes []kivik.Index) error {
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

func getQueryOptions(options []storage.QueryOption) storage.QueryOptions {
	var queryOptions storage.QueryOptions
	queryOptions.PageSize = 25

	for _, option := range options {
		option(&queryOptions)
	}

	return queryOptions
}

func getValueFromRows(rows rows, rawDocKey string) (string, error) {
	rawDoc := make(map[string]interface{})

	err := rows.ScanDoc(&rawDoc)
	if err != nil {
		return "", fmt.Errorf(failWhileScanResultRows, err)
	}

	value, err := getStringValueFromRawDoc(rawDoc, rawDocKey)
	if err != nil {
		return "", fmt.Errorf(`failure while getting the value associated with the "%s" key`+
			`from the raw document`, rawDocKey)
	}

	return value, nil
}

func getStringValueFromRawDoc(rawDoc map[string]interface{}, rawDocKey string) (string, error) {
	value, ok := rawDoc[rawDocKey]
	if !ok {
		return "", fmt.Errorf(`"%s" is missing from the raw document`, rawDocKey)
	}

	valueString, ok := value.(string)
	if !ok {
		return "",
			fmt.Errorf(`value associated with the "%s" key in the raw document `+
				`could not be asserted as a string`, rawDocKey)
	}

	return valueString, nil
}

func getPayloadsFromRawDocs(rawDocs []map[string]interface{}) ([][]byte, error) {
	storedValues := make([][]byte, len(rawDocs))

	for i, rawDoc := range rawDocs {
		// If the rawDoc is nil, this means that the value could not be found.
		// It is not considered an error.
		if rawDoc == nil {
			storedValues[i] = nil

			continue
		}

		// CouchDB still returns a raw document if the key has been deleted, so if this is a "deleted" raw document
		// then we need to return nil to indicate that the value could not be found
		isDeleted, containsIsDeleted := rawDoc[deletedFieldKey]
		if containsIsDeleted {
			isDeletedBool, ok := isDeleted.(bool)
			if !ok {
				return nil, errors.New("failed to assert the retrieved deleted field value as a bool")
			}

			if isDeletedBool {
				storedValues[i] = nil

				continue
			}
		}

		storedValueBase64, err := getStringValueFromRawDoc(rawDoc, payloadFieldKey)
		if err != nil {
			return nil, fmt.Errorf(`failed to get the payload from the raw document: %w`, err)
		}

		storeValue, err := base64.StdEncoding.DecodeString(storedValueBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode stored value: %w", err)
		}

		storedValues[i] = storeValue
	}

	return storedValues, nil
}

func getRawDocsFromRows(rows rows) ([]map[string]interface{}, error) {
	moreDocumentsToRead := rows.Next()

	var rawDocs []map[string]interface{}

	for moreDocumentsToRead {
		var rawDoc map[string]interface{}
		err := rows.ScanDoc(&rawDoc)
		// For the regular Get method, Kivik actually returns a different error message if a document was deleted.
		// When doing a bulk get, however,  Kivik doesn't return an error message, and we have to check the "_deleted"
		// field in the raw doc later. This is done in the getPayloadsFromRawDocs method.
		// If the document wasn't found, we allow the nil raw doc to be appended since we don't consider it to be
		// an error.
		if err != nil && !strings.Contains(err.Error(), bulkGetDocNotFoundErrMsgFromKivik) {
			return nil, fmt.Errorf(failWhileScanResultRows, err)
		}

		rawDocs = append(rawDocs, rawDoc)

		moreDocumentsToRead = rows.Next()
	}

	return rawDocs, nil
}

func getTagsFromRawDoc(rawDoc map[string]interface{}) ([]storage.Tag, error) {
	var tags []storage.Tag

	for key, value := range rawDoc {
		// Any key that isn't one of the reserved keywords below must be a tag.
		if key != idFieldKey && key != revIDFieldKey && key != payloadFieldKey {
			valueString, ok := value.(string)
			if !ok {
				return nil, errors.New("failed to assert tag value as string")
			}

			tags = append(tags, storage.Tag{
				Name:  key,
				Value: valueString,
			})
		}
	}

	return tags, nil
}

func logAnyWarning(i *couchDBResultsIterator) {
	warningMsg := i.resultRows.Warning()

	if warningMsg != "" {
		i.store.logger.Warnf(warningMsg)
	}
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

// TODO (#65) Store tags as a nested object so we don't need to do this "payload" name check.
func addTagsToRawDoc(rawDoc map[string]interface{}, tags []storage.Tag) error {
	for _, tag := range tags {
		if tag.Name == payloadFieldKey {
			return errors.New(`tag name cannot be "payload" as it is a reserved keyword`)
		}

		rawDoc[tag.Name] = tag.Value
	}

	return nil
}

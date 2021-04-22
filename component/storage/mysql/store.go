/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package mysql implements a storage interface for Aries (aries-framework-go).
//
package mysql

import ( //nolint:gci // False positive, seemingly caused by the MySQL driver comment.
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	// Add as per the documentation - https://github.com/go-sql-driver/mysql
	_ "github.com/go-sql-driver/mysql"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	createDBQuery  = "CREATE DATABASE IF NOT EXISTS `%s`"
	tagMapKey      = "TagMap"
	storeConfigKey = "StoreConfig"

	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2
	invalidQueryExpressionFormat    = `"%s" is not in a valid expression format. ` +
		"it must be in the following format: TagName:TagValue"
	invalidTagName  = `"%s" is an invalid tag name since it contains one or more ':' characters`
	invalidTagValue = `"%s" is an invalid tag value since it contains one or more ':' characters`
)

// TODO (#67): Fully implement all methods.

// ErrKeyRequired is returned when key is mandatory.
var ErrKeyRequired = errors.New("key is mandatory")

type closer func(storeName string)

type tagMapping map[string]map[string]struct{} // map[TagName](Set of database Keys)

type dbEntry struct {
	Value []byte        `json:"value,omitempty"`
	Tags  []storage.Tag `json:"tags,omitempty"`
}

// Provider represents a MySQL DB implementation of the storage.Provider interface.
type Provider struct {
	dbURL    string
	db       *sql.DB
	dbs      map[string]*store
	dbPrefix string
	lock     sync.RWMutex
}

// Option configures the couchdb provider.
type Option func(opts *Provider)

// WithDBPrefix option is for adding prefix to db name.
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// NewProvider instantiates Provider.
// Example DB Path root:my-secret-pw@tcp(127.0.0.1:3306)/
// This provider's CreateStore(name) implementation creates stores that are backed by a table under a schema
// with the same name as the table. The fully qualified name of the table is thus `name.name`. The fully qualified
// name of the table needs to be used with the store's `Query()` method.
func NewProvider(dbPath string, opts ...Option) (*Provider, error) {
	if dbPath == "" {
		return nil, errBlankDBPath
	}

	db, err := sql.Open("mysql", dbPath)
	if err != nil {
		return nil, fmt.Errorf(failureWhileOpeningMySQLConnectionErrMsg, dbPath, err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf(failureWhilePingingMySQLErrMsg, dbPath, err)
	}

	p := &Provider{
		dbURL: dbPath,
		db:    db,
		dbs:   map[string]*store{},
	}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
// Store names are not case-sensitive. If name is blank, then an error will be returned.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	if name == "" {
		return nil, errBlankStoreName
	}

	name = strings.ToLower(name)

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	// Check cache first
	cachedStore, existsInCache := p.dbs[name]
	if existsInCache {
		return cachedStore, nil
	}

	// creating the database
	_, err := p.db.Exec(fmt.Sprintf(createDBQuery, name))
	if err != nil {
		return nil, fmt.Errorf(failureWhileCreatingDBErrMsg, name, err)
	}

	createTableStmt := fmt.Sprintf(
		"CREATE Table IF NOT EXISTS `%s`.`%s` (`key` varchar(255) NOT NULL ,`value` BLOB, PRIMARY KEY (`key`))",
		name, name)

	// creating key-value table inside the database
	_, err = p.db.Exec(createTableStmt)
	if err != nil {
		return nil, fmt.Errorf(failureWhileCreatingTableErrMsg, name, err)
	}

	// Opening new DB connection
	storeDB, err := sql.Open("mysql", p.dbURL)
	if err != nil {
		return nil, fmt.Errorf(failureWhileOpeningMySQLConnectionErrMsg, p.dbURL, err)
	}

	store := &store{
		db:        storeDB,
		name:      name,
		tableName: fmt.Sprintf("`%s`.`%s`", name, name),
		close:     p.removeStore,
	}

	p.dbs[name] = store

	return store, nil
}

// SetStoreConfig sets the configuration on a store. This must be done before storing any data in order to make use
// of the Query method.
// TODO (#67): Use proper MySQL indexing instead of the "Tag Map".
func (p *Provider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	name = strings.ToLower(name)

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	openStore, ok := p.dbs[name]
	if !ok {
		return storage.ErrStoreNotFound
	}

	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal store configuration: %w", err)
	}

	err = openStore.Put(storeConfigKey, configBytes)
	if err != nil {
		return fmt.Errorf("failed to put store store configuration: %w", err)
	}

	// Create the tag map if it doesn't exist already.
	_, err = openStore.Get(tagMapKey)
	if errors.Is(err, storage.ErrDataNotFound) {
		err = openStore.Put(tagMapKey, []byte("{}"))
		if err != nil {
			return fmt.Errorf(`failed to create tag map for "%s": %w`, name, err)
		}
	} else if err != nil {
		return fmt.Errorf("unexpected failure while getting tag data bytes: %w", err)
	}

	return nil
}

// GetStoreConfig is currently not implemented.
func (p *Provider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	name = strings.ToLower(name)

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	openStore, ok := p.dbs[name]
	if !ok {
		return storage.StoreConfiguration{}, storage.ErrStoreNotFound
	}

	storeConfigBytes, err := openStore.Get(storeConfigKey)
	if err != nil {
		return storage.StoreConfiguration{},
			fmt.Errorf(`failed to get store configuration for "%s": %w`, name, err)
	}

	var storeConfig storage.StoreConfiguration

	err = json.Unmarshal(storeConfigBytes, &storeConfig)
	if err != nil {
		return storage.StoreConfiguration{}, fmt.Errorf("failed to unmarshal store configuration: %w", err)
	}

	return storeConfig, nil
}

// GetOpenStores is currently not implemented.
func (p *Provider) GetOpenStores() []storage.Store {
	panic("not implemented")
}

// Close closes all stores created under this store provider.
func (p *Provider) Close() error {
	p.lock.RLock()

	openStoresSnapshot := make([]*store, len(p.dbs))

	var counter int

	for _, openStore := range p.dbs {
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

	return nil
}

func (p *Provider) removeStore(name string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	_, ok := p.dbs[name]
	if ok {
		delete(p.dbs, name)
	}
}

type store struct {
	db        *sql.DB
	name      string
	tableName string
	close     closer
}

func (s *store) Put(key string, value []byte, tags ...storage.Tag) error {
	errInputValidation := validatePutInput(key, value, tags)
	if errInputValidation != nil {
		return errInputValidation
	}

	var newDBEntry dbEntry
	newDBEntry.Value = value

	if len(tags) > 0 {
		newDBEntry.Tags = tags

		err := s.updateTagMap(key, tags)
		if err != nil {
			return fmt.Errorf("failed to update tag map: %w", err)
		}
	}

	entryBytes, err := json.Marshal(newDBEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal new DB entry: %w", err)
	}

	// create upsert query to insert the record, checking whether the key is already mapped to a value in the store.
	insertStmt := "INSERT INTO " + s.tableName + " VALUES (?, ?) ON DUPLICATE KEY UPDATE value=?"
	// executing the prepared insert statement
	_, err = s.db.Exec(insertStmt, key, entryBytes, entryBytes)
	if err != nil {
		return fmt.Errorf(failureWhileExecutingInsertStatementErrMsg, s.tableName, err)
	}

	return nil
}

func (s *store) Get(k string) ([]byte, error) {
	retrievedDBEntry, err := s.getDBEntry(k)
	if err != nil {
		return nil, fmt.Errorf("failed to get DB entry: %w", err)
	}

	return retrievedDBEntry.Value, nil
}

func (s *store) GetTags(key string) ([]storage.Tag, error) {
	retrievedDBEntry, err := s.getDBEntry(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get DB entry: %w", err)
	}

	return retrievedDBEntry.Tags, nil
}

func (s *store) GetBulk(...string) ([][]byte, error) {
	return nil, errors.New("not implemented")
}

// This provider doesn't currently support any of the current query options.
// spi.WithPageSize will simply be ignored since it only relates to performance and not the actual end result.
// spi.WithInitialPageNum and spi.WithSortOrder will result in an error being returned since those options do
// affect the results that the Iterator returns.
func (s *store) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	err := checkForUnsupportedQueryOptions(options)
	if err != nil {
		return nil, err
	}

	if expression == "" {
		return nil, fmt.Errorf(invalidQueryExpressionFormat, expression)
	}

	tagMap, err := s.getTagMap()
	if err != nil {
		return nil, fmt.Errorf("failed to get tag map: %w", err)
	}

	expressionSplit := strings.Split(expression, ":")
	switch len(expressionSplit) {
	case expressionTagNameOnlyLength:
		expressionTagName := expressionSplit[0]

		matchingDatabaseKeys := getDatabaseKeysMatchingTagName(tagMap, expressionTagName)

		return &iterator{keys: matchingDatabaseKeys, store: s}, nil
	case expressionTagNameAndValueLength:
		expressionTagName := expressionSplit[0]
		expressionTagValue := expressionSplit[1]

		matchingDatabaseKeys, err :=
			s.getDatabaseKeysMatchingTagNameAndValue(tagMap, expressionTagName, expressionTagValue)
		if err != nil {
			return nil, fmt.Errorf("failed to get database keys matching tag name and value: %w", err)
		}

		return &iterator{keys: matchingDatabaseKeys, store: s}, nil
	default:
		return nil, fmt.Errorf(invalidQueryExpressionFormat, expression)
	}
}

// Delete will delete record with k key.
func (s *store) Delete(k string) error {
	if k == "" {
		return ErrKeyRequired
	}

	// delete query to delete the record by key
	_, err := s.db.Exec("DELETE FROM "+s.tableName+" WHERE `key`= ?", k)
	if err != nil {
		return fmt.Errorf(storage.ErrDataNotFound.Error(), err)
	}

	err = s.removeFromTagMap(k)
	if err != nil {
		return fmt.Errorf("failed to remove key from tag map: %w", err)
	}

	return nil
}

func (s *store) Batch([]storage.Operation) error {
	return errors.New("not implemented")
}

// SQL store doesn't queue values, so there's never anything to flush.
func (s *store) Flush() error {
	return nil
}

func (s *store) Close() error {
	s.close(s.name)

	err := s.db.Close()
	if err != nil {
		return fmt.Errorf(failureWhileClosingMySQLConnection, err)
	}

	return nil
}

func (s *store) updateTagMap(key string, tags []storage.Tag) error {
	tagMap, err := s.getTagMap()
	if err != nil {
		return fmt.Errorf("failed to get tag map: %w", err)
	}

	for _, tag := range tags {
		if tagMap[tag.Name] == nil {
			tagMap[tag.Name] = make(map[string]struct{})
		}

		tagMap[tag.Name][key] = struct{}{}
	}

	tagMapBytes, err := json.Marshal(tagMap)
	if err != nil {
		return fmt.Errorf("failed to marshal updated tag map: %w", err)
	}

	err = s.Put(tagMapKey, tagMapBytes)
	if err != nil {
		return fmt.Errorf("failed to put updated tag map back into the store: %w", err)
	}

	return nil
}

func (s *store) getTagMap() (tagMapping, error) {
	tagMapBytes, err := s.Get(tagMapKey)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("tag map not found. Was the store configuration set? error: %w", err)
		}

		return nil, fmt.Errorf("failed to get tag map: %w", err)
	}

	var tagMap tagMapping

	err = json.Unmarshal(tagMapBytes, &tagMap)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tag map bytes: %w", err)
	}

	return tagMap, nil
}

func (s *store) getDBEntry(key string) (dbEntry, error) {
	if key == "" {
		return dbEntry{}, ErrKeyRequired
	}

	var retrievedDBEntryBytes []byte

	// select query to fetch the record by key
	err := s.db.QueryRow("SELECT `value` FROM "+s.tableName+" "+
		" WHERE `key` = ?", key).Scan(&retrievedDBEntryBytes)
	if err != nil {
		if strings.Contains(err.Error(), valueNotFoundErrMsgFromMySQL) {
			return dbEntry{}, storage.ErrDataNotFound
		}

		return dbEntry{}, fmt.Errorf(failureWhileQueryingRowErrMsg, err)
	}

	var retrievedDBEntry dbEntry

	err = json.Unmarshal(retrievedDBEntryBytes, &retrievedDBEntry)
	if err != nil {
		return dbEntry{}, fmt.Errorf("failed to unmarshaled retrieved DB entry: %w", err)
	}

	return retrievedDBEntry, nil
}

func (s *store) removeFromTagMap(keyToRemove string) error {
	tagMap, err := s.getTagMap()
	if err != nil {
		// If there's no tag map, then this means that no store configuration was set.
		// Nothing needs to be done in this case, as it means that this store doesn't use tags.
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil
		}

		return fmt.Errorf("failed to get tag map: %w", err)
	}

	for _, tagNameToKeys := range tagMap {
		delete(tagNameToKeys, keyToRemove)
	}

	tagMapBytes, err := json.Marshal(tagMap)
	if err != nil {
		return fmt.Errorf("failed to marshal updated tag map: %w", err)
	}

	err = s.Put(tagMapKey, tagMapBytes)
	if err != nil {
		return fmt.Errorf("failed to put updated tag map back into the store: %w", err)
	}

	return nil
}

func (s *store) getDatabaseKeysMatchingTagNameAndValue(tagMap tagMapping,
	expressionTagName, expressionTagValue string) ([]string, error) {
	var matchingDatabaseKeys []string

	for tagName, databaseKeysSet := range tagMap {
		if tagName == expressionTagName {
			for databaseKey := range databaseKeysSet {
				tags, err := s.GetTags(databaseKey)
				if err != nil {
					return nil, fmt.Errorf("failed to get tags: %w", err)
				}

				for _, tag := range tags {
					if tag.Name == expressionTagName && tag.Value == expressionTagValue {
						matchingDatabaseKeys = append(matchingDatabaseKeys, databaseKey)

						break
					}
				}
			}

			break
		}
	}

	return matchingDatabaseKeys, nil
}

type iterator struct {
	keys         []string
	currentIndex int
	currentKey   string
	store        *store
}

func (i *iterator) Next() (bool, error) {
	if len(i.keys) == i.currentIndex || len(i.keys) == 0 {
		if len(i.keys) == i.currentIndex || len(i.keys) == 0 {
			return false, nil
		}
	}

	i.currentKey = i.keys[i.currentIndex]

	i.currentIndex++

	return true, nil
}

func (i *iterator) Key() (string, error) {
	return i.currentKey, nil
}

func (i *iterator) Value() ([]byte, error) {
	value, err := i.store.Get(i.currentKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get value from store: %w", err)
	}

	return value, nil
}

func (i *iterator) Tags() ([]storage.Tag, error) {
	tags, err := i.store.GetTags(i.currentKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags from store: %w", err)
	}

	return tags, nil
}

func (i *iterator) Close() error {
	return nil
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

func checkForUnsupportedQueryOptions(options []storage.QueryOption) error {
	querySettings := getQueryOptions(options)

	if querySettings.InitialPageNum != 0 {
		return errors.New("mySQL provider does not currently support " +
			"setting the initial page number of query results")
	}

	if querySettings.SortOptions != nil {
		return errors.New("mySQL provider does not currently support custom sort options for query results")
	}

	return nil
}

func getQueryOptions(options []storage.QueryOption) storage.QueryOptions {
	var queryOptions storage.QueryOptions

	for _, option := range options {
		option(&queryOptions)
	}

	return queryOptions
}

func getDatabaseKeysMatchingTagName(tagMap tagMapping, expressionTagName string) []string {
	var matchingDatabaseKeys []string

	for tagName, databaseKeysSet := range tagMap {
		if tagName == expressionTagName {
			for databaseKey := range databaseKeysSet {
				matchingDatabaseKeys = append(matchingDatabaseKeys, databaseKey)
			}

			break
		}
	}

	return matchingDatabaseKeys
}

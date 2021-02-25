/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package mysql implements a storage interface for Aries (aries-framework-go).
//
package mysql

import ( //nolint:gci // False positive, seemingly caused by the MySQL driver comment.
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	// Add as per the documentation - https://github.com/go-sql-driver/mysql
	_ "github.com/go-sql-driver/mysql"

	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// TODO (#67): Fully implement all methods.

// ErrKeyRequired is returned when key is mandatory.
var ErrKeyRequired = errors.New("key is mandatory")

type closer func(storeName string)

// Provider represents a MySQL DB implementation of the storage.Provider interface.
type Provider struct {
	dbURL    string
	db       *sql.DB
	dbs      map[string]*store
	dbPrefix string
	lock     sync.RWMutex
}

const createDBQuery = "CREATE DATABASE IF NOT EXISTS `%s`"

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
	name = strings.ToLower(name)

	p.lock.Lock()
	defer p.lock.Unlock()

	if name == "" {
		return nil, errBlankStoreName
	}

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

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

// SetStoreConfig is currently not implemented.
func (p *Provider) SetStoreConfig(string, storage.StoreConfiguration) error {
	return errors.New("not implemented")
}

// GetStoreConfig is currently not implemented.
func (p *Provider) GetStoreConfig(string) (storage.StoreConfiguration, error) {
	return storage.StoreConfiguration{}, errors.New("not implemented")
}

// GetOpenStores is currently not implemented.
func (p *Provider) GetOpenStores() []storage.Store {
	return nil
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

func (s *store) Put(key string, value []byte, _ ...storage.Tag) error {
	if key == "" || value == nil {
		return errors.New("key and value are mandatory")
	}

	// create upsert query to insert the record, checking whether the key is already mapped to a value in the store.
	insertStmt := "INSERT INTO " + s.tableName + " VALUES (?, ?) ON DUPLICATE KEY UPDATE value=?"
	// executing the prepared insert statement
	_, err := s.db.Exec(insertStmt, key, value, value)
	if err != nil {
		return fmt.Errorf(failureWhileExecutingInsertStatementErrMsg, s.tableName, err)
	}

	return nil
}

func (s *store) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, ErrKeyRequired
	}

	var value []byte

	// select query to fetch the record by key
	err := s.db.QueryRow("SELECT `value` FROM "+s.tableName+" "+
		" WHERE `key` = ?", k).Scan(&value)
	if err != nil {
		if strings.Contains(err.Error(), valueNotFoundErrMsgFromMySQL) {
			return nil, storage.ErrDataNotFound
		}

		return nil, fmt.Errorf(failureWhileQueryingRowErrMsg, err)
	}

	return value, nil
}

func (s *store) GetTags(string) ([]storage.Tag, error) {
	return nil, errors.New("not implemented")
}

func (s *store) GetBulk(...string) ([][]byte, error) {
	return nil, errors.New("not implemented")
}

func (s *store) Query(string, ...storage.QueryOption) (storage.Iterator, error) {
	return nil, errors.New("not implemented")
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

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package postgresql implements a storage provider conforming to the storage interface in aries-framework-go.
// This implementation is not complete. Check each method's documentation for details on current limitations.
package postgresql

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/valyala/fastjson"
)

const (
	defaultTimeout = time.Second * 10
	invalidTag     = `"%s" is an invalid tag %s since it contains one or more of the ` +
		`following substrings: ":", "<=", "<", ">=", ">"`
)

type closer func(storeName string)

// Provider represents a PostgreSQL implementation of the storage.Provider interface.
// This implementation is not complete. Check each method's documentation for details on current limitations.
// WARNING: Certain inputs could be used for an SQL injection attack. While prepared statements are used whenever
// possible to prevent this, some inputs cannot be used in a prepared statement. Be very careful when using
// user-supplied data as inputs to the methods specified in this file.
// See the documentation above each method for details.
type Provider struct {
	connectionPool   *pgxpool.Pool
	connectionString string
	openStores       map[string]*store
	dbPrefix         string
	timeout          time.Duration
	lock             sync.RWMutex
}

// Option represents an option for a PostgreSQL Provider.
type Option func(opts *Provider)

// WithDBPrefix is an option for adding a prefix to all created database names.
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// WithTimeout is an option for specifying the timeout for all calls to PostgreSQL.
// The timeout is 10 seconds by default.
func WithTimeout(timeout time.Duration) Option {
	return func(opts *Provider) {
		opts.timeout = timeout
	}
}

// NewProvider instantiates a new PostgreSQL provider.
// connectionString can take one of several forms - see the pgxpool.Connect method for details.
// This PostgreSQL provider implementation is not yet complete. Check each method's documentation for details on
// current limitations.
// WARNING: Certain inputs to the various Provider and store functions could be used for an SQL injection attack.
// While prepared statements are used whenever possible to prevent this, some inputs cannot be used in a
// prepared statement. Be very careful when using  user-supplied data as inputs to the methods specified in this file.
// See the documentation above each method for details.
func NewProvider(connectionString string, opts ...Option) (*Provider, error) {
	provider := &Provider{openStores: map[string]*store{}}

	setOptions(opts, provider)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), provider.timeout)
	defer cancel()

	connectionPool, err := pgxpool.Connect(ctxWithTimeout, connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL instance: %w", err)
	}

	provider.connectionPool = connectionPool
	provider.connectionString = connectionString

	return provider, nil
}

// OpenStore opens a Store with the given name and returns a handle.
// If the underlying database and table for the given name has never been created before, then it is created.
// Store names are not case-sensitive. If name is blank, then an error will be returned.
// WARNING: This method will create a database and table based on the given name. Those database calls may be
// vulnerable to an SQL injection attack as prepared statements cannot be used. Be very careful if you use a
// user-provided string in the store name!
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	if name == "" {
		return nil, errors.New("store name cannot be empty")
	}

	name = p.dbPrefix + strings.ToLower(name)

	err := p.createDatabase(name)
	if err != nil {
		return nil, err
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	c, err := pgconn.ParseConfig(p.connectionString)
	if err != nil {
		return nil, err
	}

	connectString := strings.ReplaceAll(p.connectionString, c.Database, name)

	if c.Database == "" {
		split := strings.Split(p.connectionString, "?")

		connectString = fmt.Sprintf("%s/%s", p.connectionString, name)

		if len(split) > 1 {
			connectString = fmt.Sprintf("%s/%s?%s", split[0], name, split[1])
		}
	}

	connectionPoolToDatabase, err := pgxpool.Connect(ctxWithTimeout,
		connectString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	err = p.createTable(name, connectionPoolToDatabase)
	if err != nil {
		return nil, err
	}

	newStore := &store{
		name:                     name,
		connectionPoolToDatabase: connectionPoolToDatabase,
		timeout:                  p.timeout,
		close:                    p.removeStore,
	}

	p.openStores[name] = newStore

	return newStore, nil
}

// SetStoreConfig uses the given tag names in the storage.StoreConfiguration passed in here to create columns
// in the table used by the store referred to by storeName. These columns have indexes created on them. This method
// must be called before attempting to store data using those tag names and also before trying to do a query using
// those tag names.
// WARNING: This method will create columns in the table based on the given tag names. Those database calls may be
// vulnerable to an SQL injection attack as prepared statements cannot be used here. Be very careful if you use any
// user-provided strings in the tag names!
// TODO (#229): Proper conformance to the requirements specified by the interface. This implementation only works as
//            expected if being called either a. the first time or b. on a store with the same config. See the issue
//            for details.
// TODO (#229): In this implementation, tag names are case-insensitive. For other storage provider implementations,
//            they are case-sensitive. Either this implementation should allow them to be case-sensitive or the
//            interface should specify that they should be case-insensitive in order to ensure consistency among
//            implementations.
// TODO (#229): SetStoreConfig is supposed to be optional for querying.
func (p *Provider) SetStoreConfig(storeName string, config storage.StoreConfiguration) error {
	err := validateTagNames(config.TagNames)
	if err != nil {
		return err
	}

	storeName = strings.ToLower(p.dbPrefix + storeName)

	openStore, found := p.openStores[storeName]
	if !found {
		return storage.ErrStoreNotFound
	}

	if len(config.TagNames) == 0 {
		return nil
	}

	alterTableStatement := fmt.Sprintf(`ALTER TABLE %s`, openStore.name)

	for i := 0; i < len(config.TagNames); i++ {
		alterTableStatement += fmt.Sprintf(` ADD COLUMN %s text DEFAULT NULL`, config.TagNames[i])

		if i != len(config.TagNames)-1 {
			alterTableStatement += ","
		}
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	_, err = openStore.connectionPoolToDatabase.Exec(ctxWithTimeout, alterTableStatement)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to alter table: %w", err)
	}

	for i := 0; i < len(config.TagNames); i++ {
		err = p.createIndex(openStore, config.TagNames[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// GetStoreConfig is not implemented.
func (p *Provider) GetStoreConfig(string) (storage.StoreConfiguration, error) {
	return storage.StoreConfiguration{}, errors.New("not implemented")
}

// GetOpenStores is not implemented.
func (p *Provider) GetOpenStores() []storage.Store {
	panic("not implemented")
}

// Close closes all stores created under this store provider.
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

	p.connectionPool.Close()

	return nil
}

// Ping verifies whether the PostgreSQL client can successfully connect to the deployment specified by
// the connection string used in the NewProvider call.
func (p *Provider) Ping() error {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	return p.connectionPool.Ping(ctxWithTimeout)
}

func (p *Provider) removeStore(name string) {
	p.lock.Lock()
	defer p.lock.Unlock()

	_, ok := p.openStores[name]
	if ok {
		delete(p.openStores, name)
	}
}

func (p *Provider) createDatabase(name string) error {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	createDatabaseStatement := fmt.Sprintf(`CREATE DATABASE %s`, name)

	_, err := p.connectionPool.Exec(ctxWithTimeout, createDatabaseStatement)
	if err != nil && !strings.Contains(err.Error(), "already exists (SQLSTATE 42P04)") {
		return fmt.Errorf("failed to create database: %w", err)
	}

	return nil
}

func (p *Provider) createTable(name string, connectionToDatabase *pgxpool.Pool) error {
	createTableStmt :=
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (key text PRIMARY KEY, doc jsonb, bin bytea)`, name)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	_, err := connectionToDatabase.Exec(ctxWithTimeout, createTableStmt)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	return nil
}

func (p *Provider) createIndex(store *store, tagName string) error {
	createIndexStatement := fmt.Sprintf("CREATE INDEX index_%s_%s ON %s(%s)",
		store.name, tagName, store.name, tagName)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	_, err := store.connectionPoolToDatabase.Exec(ctxWithTimeout, createIndexStatement)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create index: %w", err)
	}

	return nil
}

type store struct {
	name                     string
	connectionPoolToDatabase *pgxpool.Pool
	timeout                  time.Duration
	close                    closer
}

// Put stores the key + value pair along with the (optional) tags.
// Any tag names used must have been set in the store config prior to being used here.
// If value is valid JSON, it will be stored using the jsonb type in PostgreSQL. When retrieved, it will be
// equivalent JSON, but may not be byte-for-byte equal due to differences in whitespace or field order.
// You should always unmarshal it first before doing comparisons with other JSON data.
// When overwriting an existing key-value pair, the tags may not also get overwritten.
// WARNING: Prepared statements are used to avoid SQL injection attacks using the key and value inputs, but tag names
// could still be used for an SQL injection attack since prepared statement cannot be used for them as they refer
// to column names. Be very careful if you use any user-provided strings in the tag names!
// TODO (#229): Ensure that overwriting an existing key-value pair also updates the tags.
// TODO (#229): In this implementation, tag names are case-insensitive. For other storage provider implementations,
//            they are case-sensitive. Either this implementation should allow them to be case-sensitive or the
//            interface should specify that they should be case-insensitive in order to ensure consistency among
//            implementations.
func (s *store) Put(key string, value []byte, tags ...storage.Tag) error {
	err := validatePutInput(key, value, tags)
	if err != nil {
		return err
	}

	isJSON := false

	err = fastjson.ValidateBytes(value)
	if err == nil {
		isJSON = true
	}

	columns := "(key,"

	if isJSON {
		columns += "doc"
	} else {
		columns += "bin"
	}

	values := "($1,$2"

	arguments := []interface{}{key, value}

	// This offset ensures that the optional positional arguments start after the first two mandatory ones.
	const argumentPositionOffset = 3

	if len(tags) == 0 {
		columns += ")"
		values += ")"
	} else {
		for i := 0; i < len(tags); i++ {
			columns += fmt.Sprintf(",%s", tags[i].Name)
			values += fmt.Sprintf(",$%d", i+argumentPositionOffset)
			arguments = append(arguments, tags[i].Value)

			if i == len(tags)-1 {
				columns += ")"
				values += ")"
			}
		}
	}

	insertStmt :=
		fmt.Sprintf("INSERT INTO %s %s VALUES %s "+
			"ON CONFLICT (key) DO UPDATE SET doc = excluded.doc, bin = excluded.bin",
			s.name, columns, values)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	_, err = s.connectionPoolToDatabase.Exec(ctxWithTimeout, insertStmt, arguments...)
	if err != nil {
		return fmt.Errorf("failed to insert data into table: %w", err)
	}

	return nil
}

func (s *store) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, errors.New("key cannot be empty")
	}

	var doc []byte

	var bin []byte

	selectStatement := "SELECT doc,bin FROM " + s.name + " WHERE key = $1"

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	err := s.connectionPoolToDatabase.QueryRow(ctxWithTimeout, selectStatement, key).Scan(&doc, &bin)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			return nil, storage.ErrDataNotFound
		}

		return nil, fmt.Errorf("failed to query table: %w", err)
	}

	if doc != nil {
		return doc, nil
	}

	return bin, nil
}

func (s *store) GetTags(string) ([]storage.Tag, error) {
	return nil, errors.New("not implemented")
}

func (s *store) GetBulk(...string) ([][]byte, error) {
	return nil, errors.New("not implemented")
}

// Query returns all data that satisfies the expression. Expression format: TagName. (TagName + TagValue queries
// are not currently implemented.)
// This provider doesn't currently support any of the current query options.
// spi.WithPageSize will simply be ignored since it only relates to performance and not the actual end result.
// spi.WithInitialPageNum and spi.WithSortOrder will result in an error being returned since those options do
// affect the results that the Iterator returns.
// WARNING: The tag name used in the expression could be used to do an SQL injection attack since a prepared statement
// cannot be used here. Be very careful if you use a user-provided string in the tag name!
// TODO (#229): Support TagName + TagValue queries.
// TODO (#229): In this implementation, tag names are case-insensitive. For other storage provider implementations,
//            they are case-sensitive. Either this implementation should allow them to be case-sensitive or the
//            interface should specify that they should be case-insensitive in order to ensure consistency among
//            implementations.
func (s *store) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	err := checkForUnsupportedQueryOptions(options)
	if err != nil {
		return nil, err
	}

	if expression == "" {
		return &iterator{}, errors.New("expression cannot be empty")
	}

	expressionSplit := strings.Split(expression, ":")
	_ = expressionSplit

	if len(expressionSplit) != 1 {
		return nil, errors.New("tag name + value queries not implemented")
	}

	selectStatement := fmt.Sprintf("SELECT * FROM %s WHERE %s IS NOT NULL", s.name, expressionSplit[0])

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	rows, err := s.connectionPoolToDatabase.Query(ctxWithTimeout, selectStatement)
	if err != nil {
		return nil, fmt.Errorf("failed to query table: %w", err)
	}

	return &iterator{rows: rows}, nil
}

func (s *store) Delete(key string) error {
	if key == "" {
		return errors.New("key cannot be empty")
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	_, err := s.connectionPoolToDatabase.Exec(ctxWithTimeout,
		fmt.Sprintf(`DELETE FROM "%s" WHERE key=$1`, s.name), key)
	if err != nil {
		return fmt.Errorf("failed to delete data in table: %w", err)
	}

	return nil
}

func (s *store) Batch([]storage.Operation) error {
	return errors.New("not implemented")
}

// Flush always returns nil, since this store doesn't buffer data.
func (s *store) Flush() error {
	return nil
}

func (s *store) Close() error {
	s.connectionPoolToDatabase.Close()

	s.close(s.name)

	return nil
}

type iterator struct {
	rows pgx.Rows
}

func (i *iterator) Next() (bool, error) {
	return i.rows.Next(), nil
}

func (i *iterator) Key() (string, error) {
	rawValues := i.rows.RawValues()

	return string(rawValues[0]), nil
}

func (i *iterator) Value() ([]byte, error) {
	rawValues := i.rows.RawValues()

	if rawValues[1] != nil {
		return rawValues[1], nil
	}

	return rawValues[2], nil
}

func (i *iterator) Tags() ([]storage.Tag, error) {
	return nil, errors.New("not implemented")
}

func (i *iterator) TotalItems() (int, error) {
	return -1, errors.New("not implemented")
}

func (i *iterator) Close() error {
	i.rows.Close()

	return nil
}

func setOptions(opts []Option, p *Provider) {
	for _, opt := range opts {
		opt(p)
	}

	if p.timeout == 0 {
		p.timeout = defaultTimeout
	}
}

func validateTagNames(tagNames []string) error {
	for _, tagName := range tagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTag, tagName, "name")
		}

		if strings.Contains(tagName, "<") { // This also handles the <= case.
			return fmt.Errorf(invalidTag, tagName, "name")
		}

		if strings.Contains(tagName, ">") { // This also handles the >= case.
			return fmt.Errorf(invalidTag, tagName, "name")
		}
	}

	return nil
}

func validatePutInput(key string, value []byte, tags []storage.Tag) error {
	if key == "" {
		return errors.New("key cannot be empty")
	}

	if value == nil {
		return errors.New("value cannot be nil")
	}

	return validateTags(tags)
}

func validateTags(tags []storage.Tag) error {
	for _, tag := range tags {
		if strings.Contains(tag.Name, ":") {
			return fmt.Errorf(invalidTag, tag.Name, "name")
		}

		if strings.Contains(tag.Value, ":") {
			return fmt.Errorf(invalidTag, tag.Value, "value")
		}

		if strings.Contains(tag.Name, "<") { // This also handles the <= case.
			return fmt.Errorf(invalidTag, tag.Name, "name")
		}

		if strings.Contains(tag.Value, "<") { // This also handles the <= case.
			return fmt.Errorf(invalidTag, tag.Value, "value")
		}

		if strings.Contains(tag.Name, ">") { // This also handles the >= case.
			return fmt.Errorf(invalidTag, tag.Name, "name")
		}

		if strings.Contains(tag.Value, ">") { // This also handles the >= case.
			return fmt.Errorf(invalidTag, tag.Value, "value")
		}
	}

	return nil
}

func checkForUnsupportedQueryOptions(options []storage.QueryOption) error {
	querySettings := getQueryOptions(options)

	if querySettings.InitialPageNum != 0 {
		return errors.New("setting initial page number not implemented")
	}

	if querySettings.SortOptions != nil {
		return errors.New("custom sort options not implemented")
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

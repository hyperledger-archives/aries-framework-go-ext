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
	"time"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/jackc/pgx/v4"
)

const defaultTimeout = time.Second * 10

// Provider represents a PostgreSQL implementation of the storage.Provider interface.
// This implementation is not complete. Check each method's documentation for details on current limitations.
// WARNING: The Provider.OpenStore() method will create a database and table based on the given name. Those database
// calls may be vulnerable to an SQL injection attack. Be very careful if you use a user-provided string in the store
// name!
type Provider struct {
	connection       *pgx.Conn
	connectionString string
	dbPrefix         string
	timeout          time.Duration
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
// connectionString can take one of several forms - see the pgx.Connect method for details.
// This PostgreSQL provider implementation is not yet complete. Check each method's documentation for details on
// current limitations.
// WARNING: The Provider.OpenStore() method will create a database and table based on the given name. Those database
// calls may be vulnerable to an SQL injection attack. Be very careful if you use a user-provided string in the store
// name!
func NewProvider(connectionString string, opts ...Option) (*Provider, error) {
	provider := &Provider{}

	setOptions(opts, provider)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), provider.timeout)
	defer cancel()

	connection, err := pgx.Connect(ctxWithTimeout, connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL instance: %w", err)
	}

	provider.connection = connection
	provider.connectionString = connectionString

	return provider, nil
}

// OpenStore opens a Store with the given name and returns a handle.
// If the underlying database and table for the given name has never been created before, then it is created.
// Store names are not case-sensitive. If name is blank, then an error will be returned.
// WARNING: This method will create a database and table based on the given name. Those database calls may be
// vulnerable to an SQL injection attack. Be very careful if you use a user-provided string in the store name!
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

	connectionToDatabase, err := pgx.Connect(ctxWithTimeout,
		fmt.Sprintf("%s/%s", p.connectionString, name))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	err = p.createTable(name, connectionToDatabase)
	if err != nil {
		return nil, err
	}

	return &store{
		name:       name,
		connection: connectionToDatabase,
		timeout:    p.timeout,
	}, nil
}

func (p *Provider) createDatabase(name string) error {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	createDatabaseStatement := fmt.Sprintf(`CREATE DATABASE "%s"`, name)

	_, err := p.connection.Exec(ctxWithTimeout, createDatabaseStatement)
	if err != nil && !strings.Contains(err.Error(), "already exists (SQLSTATE 42P04)") {
		return fmt.Errorf("failed to create database: %w", err)
	}

	return nil
}

func (p *Provider) createTable(name string, connectionToDatabase *pgx.Conn) error {
	createTableStmt :=
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS "%s" (key VARCHAR PRIMARY KEY, value jsonb)`, name)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	_, err := connectionToDatabase.Exec(ctxWithTimeout, createTableStmt)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	return nil
}

// SetStoreConfig is not implemented.
func (p *Provider) SetStoreConfig(string, storage.StoreConfiguration) error {
	return errors.New("not implemented")
}

// GetStoreConfig is not implemented.
func (p *Provider) GetStoreConfig(string) (storage.StoreConfiguration, error) {
	return storage.StoreConfiguration{}, errors.New("not implemented")
}

// GetOpenStores is not implemented.
func (p *Provider) GetOpenStores() []storage.Store {
	panic("not implemented")
}

// Close is not implemented.
func (p *Provider) Close() error {
	return errors.New("not implemented")
}

type store struct {
	name       string
	connection *pgx.Conn
	timeout    time.Duration
}

// Put stores the given value under the given key.
// value must be JSON. Any other type of data will result in an error. Tags are not currently supported.
func (s *store) Put(key string, value []byte, tags ...storage.Tag) error {
	errInputValidation := validatePutInput(key, value, tags)
	if errInputValidation != nil {
		return errInputValidation
	}

	insertStmt :=
		fmt.Sprintf(`INSERT INTO "%s" VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
			s.name)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	_, err := s.connection.Exec(ctxWithTimeout, insertStmt, key, value)
	if err != nil {
		return fmt.Errorf("failed to insert data into table: %w", err)
	}

	return nil
}

func (s *store) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, errors.New("key cannot be empty")
	}

	var value []byte

	selectStatement := "SELECT value FROM " + s.name + " WHERE key = $1"

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	err := s.connection.QueryRow(ctxWithTimeout, selectStatement, key).Scan(&value)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			return nil, storage.ErrDataNotFound
		}

		return nil, fmt.Errorf("failed to query row: %w", err)
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

func (s *store) Delete(key string) error {
	if key == "" {
		return errors.New("key cannot be empty")
	}

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	_, err := s.connection.Exec(ctxWithTimeout,
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
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	return s.connection.Close(ctxWithTimeout)
}

func setOptions(opts []Option, p *Provider) {
	for _, opt := range opts {
		opt(p)
	}

	if p.timeout == 0 {
		p.timeout = defaultTimeout
	}
}

func validatePutInput(key string, value []byte, tags []storage.Tag) error {
	if key == "" {
		return errors.New("key cannot be empty")
	}

	if value == nil {
		return errors.New("value cannot be nil")
	}

	if tags != nil {
		return errors.New("tags are not currently supported")
	}

	return nil
}

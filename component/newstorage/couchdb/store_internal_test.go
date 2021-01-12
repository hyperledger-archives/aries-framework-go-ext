/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package couchdb

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/go-kivik/kivik/v3"
	"github.com/stretchr/testify/require"
)

type mockDB struct {
	errPut         error
	getRowBodyData string
	errGetRow      error
}

func (m *mockDB) Get(context.Context, string, ...kivik.Options) *kivik.Row {
	return &kivik.Row{
		Err:  m.errGetRow,
		Body: ioutil.NopCloser(strings.NewReader(m.getRowBodyData)),
	}
}

func (m *mockDB) Put(context.Context, string, interface{}, ...kivik.Options) (string, error) {
	return "", m.errPut
}

func (m *mockDB) Delete(context.Context, string, string, ...kivik.Options) (string, error) {
	return "", errors.New("mockDB Delete always fails")
}

func (m *mockDB) Close(context.Context) error {
	return errors.New("mockDB Close always fails")
}

func TestStore_Put_Internal(t *testing.T) {
	t.Run("Fail to marshal values maps", func(t *testing.T) {
		store := &Store{marshal: failingMarshal}

		err := store.Put("key", []byte("value"))
		require.EqualError(t, err, "failed to marshal values map: failingMarshal always fails")
	})
	t.Run("Document update conflict: exceed maximum number of retries", func(t *testing.T) {
		store := &Store{
			db: &mockDB{
				errPut:         errors.New(documentUpdateConflictErrMsgFromKivik),
				getRowBodyData: `{"_rev":"SomeRevID"}`,
			},
			maxDocumentConflictRetries: 3, marshal: json.Marshal,
		}

		err := store.Put("key", []byte("value"))
		require.EqualError(t, err, "failure while putting value into CouchDB: maximum number of "+
			"retry attempts (3) exceeded: failed to put value via client: Conflict: Document update conflict.")
	})
	t.Run("Other error while putting value via client", func(t *testing.T) {
		store := &Store{
			db: &mockDB{
				errPut:         errors.New("other error"),
				getRowBodyData: `{"_rev":"SomeRevID"}`,
			},
			maxDocumentConflictRetries: 3, marshal: json.Marshal,
		}

		err := store.Put("key", []byte("value"))
		require.EqualError(t, err, "failure while putting value into CouchDB: failed to put value via "+
			"client: other error")
	})
	t.Run("Fail to get revision ID", func(t *testing.T) {
		store := &Store{
			db: &mockDB{
				errGetRow: errors.New("get error"),
			},
			maxDocumentConflictRetries: 3, marshal: json.Marshal,
		}

		err := store.Put("key", []byte("value"))
		require.EqualError(t, err, "failure while putting value into CouchDB: "+
			"failed to get revision ID: get error")
	})
	t.Run("Revision ID missing from document", func(t *testing.T) {
		store := &Store{
			db: &mockDB{
				getRowBodyData: `{}`,
			},
			maxDocumentConflictRetries: 3, marshal: json.Marshal,
		}

		err := store.Put("key", []byte("value"))
		require.EqualError(t, err, "failure while putting value into CouchDB: "+
			"failed to get revision ID: revision ID was missing from the raw document")
	})
	t.Run("Unable to assert revision ID as a string", func(t *testing.T) {
		store := &Store{
			db: &mockDB{
				getRowBodyData: `{"_rev":1}`,
			},
			maxDocumentConflictRetries: 3, marshal: json.Marshal,
		}

		err := store.Put("key", []byte("value"))
		require.EqualError(t, err, "failure while putting value into CouchDB: "+
			"failed to get revision ID: unable to assert revision ID as a string")
	})
}

func TestStore_Get_Internal(t *testing.T) {
	t.Run("Other failure while scanning row", func(t *testing.T) {
		store := &Store{db: &mockDB{errGetRow: errors.New("get error")}}

		value, err := store.Get("key")
		require.EqualError(t, err, "failure while scanning row: get error")
		require.Nil(t, value)
	})
	t.Run("Payload field key missing from raw document", func(t *testing.T) {
		store := &Store{db: &mockDB{getRowBodyData: `{}`}}

		value, err := store.Get("key")
		require.EqualError(t, err, "failed to get payload from raw document: "+
			"payload was unexpectedly missing from raw document")
		require.Nil(t, value)
	})
	t.Run("Failed to assert stored value as a string", func(t *testing.T) {
		store := &Store{db: &mockDB{getRowBodyData: `{"payload":1}`}}

		value, err := store.Get("key")
		require.EqualError(t, err, "failed to get payload from raw document: "+
			"stored value could not be asserted as a string")
		require.Nil(t, value)
	})
}

func TestStore_Close_Internal(t *testing.T) {
	t.Run("Failure", func(t *testing.T) {
		store := &Store{db: &mockDB{}}

		err := store.Close()
		require.EqualError(t, err, "failed to close database client: mockDB Close always fails")
	})
}

func TestStore_Delete_Internal(t *testing.T) {
	t.Run("Failed to get revision ID", func(t *testing.T) {
		store := &Store{db: &mockDB{errGetRow: errors.New("get error")}}

		err := store.Delete("key")
		require.EqualError(t, err, "failed to get revision ID: get error")
	})
	t.Run("Failed to delete via client", func(t *testing.T) {
		store := &Store{db: &mockDB{getRowBodyData: `{"_rev":"SomeRevID"}`}}

		err := store.Delete("key")
		require.EqualError(t, err, "failed to delete document via client: mockDB Delete always fails")
	})
}

func failingMarshal(_ interface{}) ([]byte, error) {
	return nil, errors.New("failingMarshal always fails")
}

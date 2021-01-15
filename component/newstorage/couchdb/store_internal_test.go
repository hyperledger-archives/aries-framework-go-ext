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
	errBulkGet     error
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

func (m *mockDB) Find(ctx context.Context, query interface{}, options ...kivik.Options) (*kivik.Rows, error) {
	return nil, errors.New("mockDB Find always fails")
}

func (m *mockDB) Delete(context.Context, string, string, ...kivik.Options) (string, error) {
	return "", errors.New("mockDB Delete always fails")
}

func (m *mockDB) BulkGet(context.Context, []kivik.BulkGetReference, ...kivik.Options) (*kivik.Rows, error) {
	return &kivik.Rows{}, m.errBulkGet
}

func (m *mockDB) Close(context.Context) error {
	return errors.New("mockDB Close always fails")
}

func (m *mockDB) BulkDocs(context.Context, []interface{}, ...kivik.Options) (*kivik.BulkResults, error) {
	panic("implement me")
}

type mockRows struct {
	err      error
	errClose error
	next     bool
}

func (m *mockRows) Next() bool {
	return m.next
}

func (m *mockRows) Err() error {
	return m.err
}

func (m *mockRows) Close() error {
	return m.errClose
}

func (m *mockRows) ScanDoc(dest interface{}) error {
	return errors.New("mockRows ScanDoc always fails")
}

func (m *mockRows) Warning() string {
	return ""
}

func (m *mockRows) Bookmark() string {
	return ""
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
		require.EqualError(t, err, `failure while putting value into CouchDB: `+
			`failed to get revision ID: `+
			`failed to get revision ID from the raw document: "_rev" is missing from the raw document`)
	})
	t.Run("Unable to assert revision ID as a string", func(t *testing.T) {
		store := &Store{
			db: &mockDB{
				getRowBodyData: `{"_rev":1}`,
			},
			maxDocumentConflictRetries: 3, marshal: json.Marshal,
		}

		err := store.Put("key", []byte("value"))
		require.EqualError(t, err, `failure while putting value into CouchDB: `+
			`failed to get revision ID: failed to get revision ID from the raw document: `+
			`value associated with the "_rev" key in the raw document could not be asserted as a string`)
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
		require.EqualError(t, err, `failed to get payload from raw document: `+
			`"payload" is missing from the raw document`)
		require.Nil(t, value)
	})
	t.Run("Failed to assert stored value as a string", func(t *testing.T) {
		store := &Store{db: &mockDB{getRowBodyData: `{"payload":1}`}}

		value, err := store.Get("key")
		require.EqualError(t, err, "failed to get payload from raw document: "+
			`value associated with the "payload" key in the raw document could not be asserted as a string`)
		require.Nil(t, value)
	})
}

func TestStore_GetBulk_Internal(t *testing.T) {
	t.Run("Failure while getting raw CouchDB documents", func(t *testing.T) {
		store := &Store{db: &mockDB{errBulkGet: errors.New("mockDB BulkGet always fails")}}

		values, err := store.GetBulk("key")
		require.EqualError(t, err, "failure while getting raw CouchDB documents: "+
			"failure while sending request to CouchDB bulk docs endpoint: mockDB BulkGet always fails")
		require.Nil(t, values)
	})
}

func TestStore_Query_Internal(t *testing.T) {
	t.Run("Failure sending tag name only query to find endpoint", func(t *testing.T) {
		store := &Store{db: &mockDB{}}

		iterator, err := store.Query("tagName")
		require.EqualError(t, err,
			"failure while sending request to CouchDB find endpoint: mockDB Find always fails")
		require.Empty(t, iterator)
	})
	t.Run("Failure sending tag name and value query to find endpoint", func(t *testing.T) {
		store := &Store{db: &mockDB{}}

		iterator, err := store.Query("tagName:tagValue")
		require.EqualError(t, err,
			"failure while sending request to CouchDB find endpoint: mockDB Find always fails")
		require.Empty(t, iterator)
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

func TestGetRawDocsFromRows(t *testing.T) {
	t.Run("Failure while scanning result rows", func(t *testing.T) {
		rawDocs, err := getRawDocsFromRows(&mockRows{next: true})
		require.EqualError(t, err, "failure while scanning result rows: mockRows ScanDoc always fails")
		require.Nil(t, rawDocs)
	})
}

func TestPayloadsFromRawDocs(t *testing.T) {
	t.Run("Failed to assert deleted field value as a bool", func(t *testing.T) {
		rawDocs := make([]map[string]interface{}, 1)
		rawDocs[0] = make(map[string]interface{})
		rawDocs[0][deletedFieldKey] = "Not a bool"

		payloads, err := getPayloadsFromRawDocs(rawDocs)
		require.EqualError(t, err, "failed to assert the retrieved deleted field value as a bool")
		require.Nil(t, payloads)
	})
	t.Run("Failed to get the payload from the raw document", func(t *testing.T) {
		rawDocs := make([]map[string]interface{}, 1)
		rawDocs[0] = make(map[string]interface{})

		payloads, err := getPayloadsFromRawDocs(rawDocs)
		require.EqualError(t, err,
			`failed to get the payload from the raw document: "payload" is missing from the raw document`)
		require.Nil(t, payloads)
	})
}

func TestCouchDBResultsIterator_Next_Internal(t *testing.T) {
	t.Run("Error returned from result rows", func(t *testing.T) {
		iterator := &couchDBResultsIterator{
			resultRows: &mockRows{err: errors.New("result rows error")},
		}

		nextCallResult, err := iterator.Next()
		require.EqualError(t, err, "failure during iteration of result rows: result rows error")
		require.False(t, nextCallResult)
	})
	t.Run("Fail to close result rows before fetching new page", func(t *testing.T) {
		iterator := &couchDBResultsIterator{
			resultRows: &mockRows{errClose: errors.New("close error")},
		}

		nextCallResult, err := iterator.Next()
		require.EqualError(t, err, "failed to close result rows before fetching new page: close error")
		require.False(t, nextCallResult)
	})
	t.Run("Failure while fetching another page", func(t *testing.T) {
		iterator := &couchDBResultsIterator{
			store:                                    &Store{db: &mockDB{}},
			resultRows:                               &mockRows{},
			queryWithPageSizeAndBookmarkPlaceholders: "%d,%s",
		}

		nextCallResult, err := iterator.Next()
		require.EqualError(t, err, "failure while fetching new page: "+
			"failure while sending request to CouchDB find endpoint: mockDB Find always fails")
		require.False(t, nextCallResult)
	})
}

func TestCouchDBResultsIterator_Release_Internal(t *testing.T) {
	t.Run("Fail to close result rows", func(t *testing.T) {
		iterator := &couchDBResultsIterator{
			resultRows: &mockRows{errClose: errors.New("close error")},
		}

		err := iterator.Release()
		require.EqualError(t, err, "failed to close result rows: close error")
	})
}

func TestCouchDBResultsIterator_Key_Internal(t *testing.T) {
	t.Run("Fail to get id from rows", func(t *testing.T) {
		iterator := &couchDBResultsIterator{
			resultRows: &mockRows{},
		}

		key, err := iterator.Key()
		require.EqualError(t, err, "failed to get _id from rows: failure while scanning result rows: "+
			"mockRows ScanDoc always fails")
		require.Empty(t, key)
	})
}

func TestCouchDBResultsIterator_Value_Internal(t *testing.T) {
	t.Run("Fail to get value from rows", func(t *testing.T) {
		iterator := &couchDBResultsIterator{
			resultRows: &mockRows{},
		}

		value, err := iterator.Value()
		require.EqualError(t, err, `failed to get payload from rows: failure while scanning result rows: `+
			`mockRows ScanDoc always fails`)
		require.Nil(t, value)
	})
}

func TestCouchDBResultsIterator_Tags_Internal(t *testing.T) {
	t.Run("Fail to scan result rows", func(t *testing.T) {
		iterator := &couchDBResultsIterator{
			resultRows: &mockRows{},
		}

		tags, err := iterator.Tags()
		require.EqualError(t, err, "failure while scanning result rows: mockRows ScanDoc always fails")
		require.Empty(t, tags)
	})
}

func failingMarshal(_ interface{}) ([]byte, error) {
	return nil, errors.New("failingMarshal always fails")
}

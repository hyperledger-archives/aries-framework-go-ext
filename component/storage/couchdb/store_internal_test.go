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
	"log"
	"os"
	"strings"
	"testing"

	"github.com/go-kivik/kivik/v3"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
)

type mockDB struct {
	errPut         error
	errGetIndexes  error
	errCreateIndex error
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

func (m *mockDB) GetIndexes(context.Context, ...kivik.Options) ([]kivik.Index, error) {
	return nil, m.errGetIndexes
}

func (m *mockDB) CreateIndex(context.Context, string, string, interface{}, ...kivik.Options) error {
	return m.errCreateIndex
}

func (m *mockDB) DeleteIndex(context.Context, string, string, ...kivik.Options) error {
	panic("implement me")
}

func (m *mockDB) Find(context.Context, interface{}, ...kivik.Options) (*kivik.Rows, error) {
	return nil, errors.New("mockDB Find always fails")
}

func (m *mockDB) Query(context.Context, string, string, ...kivik.Options) (*kivik.Rows, error) {
	panic("implement me")
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
	warning  string
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
	return m.warning
}

func (m *mockRows) Bookmark() string {
	return ""
}

func failingMarshal(interface{}) ([]byte, error) {
	return nil, errors.New("marshal failure")
}

func TestStore_Put_Internal(t *testing.T) {
	t.Run("Document update conflict: exceed maximum number of retries", func(t *testing.T) {
		store := &store{
			name: "TestStore",
			logger: &defaultLogger{
				log.New(os.Stdout, "CouchDB-Provider ", log.Ldate|log.Ltime|log.LUTC),
			},
			db: &mockDB{
				errPut:         errors.New(documentUpdateConflictErrMsgFromKivik),
				getRowBodyData: `{"_rev":"SomeRevID"}`,
			},
			maxDocumentConflictRetries: 3, marshal: json.Marshal,
		}

		err := store.Put("key", []byte("value"))
		require.EqualError(t, err, "failure while putting document into CouchDB database: "+
			"failed to store document for [Key: key] in CouchDB due to document conflict after 4 attempts. "+
			"This storage provider may need to be started with a higher max retry limit. "+
			"Original error message from CouchDB: Conflict: Document update conflict.")
	})
	t.Run("Other error while putting value via client", func(t *testing.T) {
		store := &store{
			db: &mockDB{
				errPut:         errors.New("other error"),
				getRowBodyData: `{"_rev":"SomeRevID"}`,
			},
			maxDocumentConflictRetries: 3, marshal: json.Marshal,
		}

		err := store.Put("key", []byte("value"))
		require.EqualError(t, err, "failure while putting document into CouchDB database: failed to put value via "+
			"client: other error")
	})
	t.Run("Fail to get revision ID", func(t *testing.T) {
		store := &store{
			db: &mockDB{
				errGetRow: errors.New("get error"),
			},
			maxDocumentConflictRetries: 3, marshal: json.Marshal,
		}

		err := store.Put("key", []byte("value"))
		require.EqualError(t, err, "failure while putting document into CouchDB database: "+
			"failed to get revision ID: get error")
	})
}

func TestStore_Get_Internal(t *testing.T) {
	t.Run("Other failure while scanning row", func(t *testing.T) {
		store := &store{db: &mockDB{errGetRow: errors.New("get error")}}

		value, err := store.Get("key")
		require.EqualError(t, err, "failure while scanning row: get error")
		require.Nil(t, value)
	})
}

func TestStore_GetBulk_Internal(t *testing.T) {
	t.Run("Failure while getting raw CouchDB documents", func(t *testing.T) {
		store := &store{db: &mockDB{errBulkGet: errors.New("mockDB BulkGet always fails")}}

		values, err := store.GetBulk("key")
		require.EqualError(t, err, "failure while getting documents: "+
			"failure while sending request to CouchDB bulk docs endpoint: mockDB BulkGet always fails")
		require.Nil(t, values)
	})
}

func TestStore_Query_Internal(t *testing.T) {
	t.Run("Failure sending query to find endpoint", func(t *testing.T) {
		store := &store{db: &mockDB{}, marshal: json.Marshal}

		iterator, err := store.Query("tagName")
		require.EqualError(t, err,
			"failure while sending request to CouchDB find endpoint: mockDB Find always fails")
		require.Empty(t, iterator)
	})
	t.Run("Fail to marshal find query", func(t *testing.T) {
		store := &store{marshal: failingMarshal}

		iterator, err := store.Query("tagName")
		require.EqualError(t, err,
			"failed to marshal find query to JSON: marshal failure")
		require.Empty(t, iterator)
	})
}

func TestStore_Close_Internal(t *testing.T) {
	t.Run("Failure", func(t *testing.T) {
		store := &store{db: &mockDB{}, close: func(string) {}}

		err := store.Close()
		require.EqualError(t, err, "failed to close database client: mockDB Close always fails")
	})
}

func TestStore_Delete_Internal(t *testing.T) {
	t.Run("Failed to get revision ID", func(t *testing.T) {
		store := &store{db: &mockDB{errGetRow: errors.New("get error")}}

		err := store.Delete("key")
		require.EqualError(t, err, "failed to get revision ID: get error")
	})
	t.Run("Failed to delete via client", func(t *testing.T) {
		store := &store{db: &mockDB{getRowBodyData: `{"_rev":"SomeRevID"}`}}

		err := store.Delete("key")
		require.EqualError(t, err, "failed to delete document via client: mockDB Delete always fails")
	})
}

func TestGetRawDocsFromRows(t *testing.T) {
	t.Run("Failure while scanning result rows", func(t *testing.T) {
		rawDocs, err := getDocumentsFromRows(&mockRows{next: true})
		require.EqualError(t, err, "failure while scanning result rows: mockRows ScanDoc always fails")
		require.Nil(t, rawDocs)
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
			store:      &store{db: &mockDB{}},
			resultRows: &mockRows{},
		}

		nextCallResult, err := iterator.Next()
		require.EqualError(t, err, "failure while fetching new page: "+
			"failure while sending request to CouchDB find endpoint: mockDB Find always fails")
		require.False(t, nextCallResult)
	})
	t.Run("Failure while logging a warning", func(t *testing.T) {
		iterator := &couchDBResultsIterator{
			resultRows: &mockRows{warning: "Some warning"},
			marshal:    failingMarshal,
		}

		nextCallResult, err := iterator.Next()
		require.EqualError(t, err, "failed to log a warning: "+
			"failed to marshal find query for log: marshal failure")
		require.False(t, nextCallResult)
	})
}

func TestCouchDBResultsIterator_Release_Internal(t *testing.T) {
	t.Run("Fail to close result rows", func(t *testing.T) {
		iterator := &couchDBResultsIterator{
			resultRows: &mockRows{errClose: errors.New("close error")},
		}

		err := iterator.Close()
		require.EqualError(t, err, "failed to close result rows: close error")
	})
}

func TestCouchDBResultsIterator_Key_Internal(t *testing.T) {
	t.Run("Fail to get id from rows", func(t *testing.T) {
		iterator := &couchDBResultsIterator{
			resultRows: &mockRows{},
		}

		key, err := iterator.Key()
		require.EqualError(t, err, "failure while scanning result rows: mockRows ScanDoc always fails")
		require.Empty(t, key)
	})
}

func TestCouchDBResultsIterator_Value_Internal(t *testing.T) {
	t.Run("Fail to get value from rows", func(t *testing.T) {
		iterator := &couchDBResultsIterator{
			resultRows: &mockRows{},
		}

		value, err := iterator.Value()
		require.EqualError(t, err, `failure while scanning result rows: mockRows ScanDoc always fails`)
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

func TestGetQueryOptions_InvalidInitialPageIsChangedToDefault(t *testing.T) {
	queryOptions := getQueryOptions([]spi.QueryOption{spi.WithInitialPageNum(-1)})
	require.Equal(t, 0, queryOptions.InitialPageNum)
}

func TestProvider_SetDesignDocuments(t *testing.T) {
	t.Run("Fail to update Mango index design document", func(t *testing.T) {
		t.Run("Fail to get existing indexes", func(t *testing.T) {
			provider := Provider{}

			err := provider.setDesignDocuments("StoreName",
				spi.StoreConfiguration{TagNames: []string{"TagName1"}},
				&mockDB{errGetIndexes: errors.New("get indexes error")})
			require.EqualError(t, err, "failure while updating Mango index design document: "+
				"failed to get existing indexes: get indexes error")
		})
		t.Run("Fail to create index", func(t *testing.T) {
			t.Run("Unexpected error", func(t *testing.T) {
				provider := Provider{}

				err := provider.setDesignDocuments("StoreName",
					spi.StoreConfiguration{TagNames: []string{"TagName1"}},
					&mockDB{errCreateIndex: errors.New("create index error")})
				require.EqualError(t, err, "failure while updating Mango index design document: "+
					"failure while updating indexes in CouchDB: failed to create indexes: "+
					"failed to create index in CouchDB: create index error")
			})
			t.Run("Too many document update conflicts - max retry attempts exceeded", func(t *testing.T) {
				provider := Provider{
					logger: &defaultLogger{
						log.New(os.Stdout, "CouchDB-Provider ", log.Ldate|log.Ltime|log.LUTC),
					},
					maxDocumentConflictRetries: 1,
				}

				err := provider.setDesignDocuments("StoreName",
					spi.StoreConfiguration{TagNames: []string{"TagName1"}},
					&mockDB{errCreateIndex: errors.New(mangoIndexDesignDocumentUpdateConflictErrMsgFromKivik)})
				require.EqualError(t, err, "failure while updating Mango index design document: "+
					"failure while updating indexes in CouchDB: failed to create indexes: "+
					"failed to create index in CouchDB due to design document conflict after 2 attempts. "+
					"This storage provider may need to be started with a higher max retry limit. "+
					"Original error message from CouchDB: Internal Server Error: Encountered a conflict while "+
					"saving the design document.")
			})
		})
	})

	t.Run("Fail to update MapReduce design document", func(t *testing.T) {
		t.Run("Unexpected failure while getting existing design document", func(t *testing.T) {
			provider := Provider{logger: &defaultLogger{
				log.New(os.Stdout, "CouchDB-Provider ", log.Ldate|log.Ltime|log.LUTC),
			}}

			err := provider.setDesignDocuments("StoreName",
				spi.StoreConfiguration{TagNames: []string{"TagName1"}},
				&mockDB{})
			require.EqualError(t, err, "failure while updating the MapReduce design document: "+
				"unexpected failure while checking for an existing MapReduce design document: EOF")
		})
		t.Run("Fail to store updated design document", func(t *testing.T) {
			t.Run("Unexpected failure", func(t *testing.T) {
				provider := Provider{
					logger: &defaultLogger{
						log.New(os.Stdout, "CouchDB-Provider ", log.Ldate|log.Ltime|log.LUTC),
					},
					maxDocumentConflictRetries: 1,
				}

				err := provider.setDesignDocuments("StoreName",
					spi.StoreConfiguration{TagNames: []string{"TagName1"}},
					&mockDB{getRowBodyData: "{}", errPut: errors.New("put error")})
				require.EqualError(t, err, "failure while updating the MapReduce design document: "+
					"failed to create/update MapReduce design document: put error")
			})
			t.Run("Too many document update conflicts - max retry attempts exceeded", func(t *testing.T) {
				provider := Provider{
					logger: &defaultLogger{
						log.New(os.Stdout, "CouchDB-Provider ", log.Ldate|log.Ltime|log.LUTC),
					},
					maxDocumentConflictRetries: 1,
				}

				err := provider.setDesignDocuments("StoreName",
					spi.StoreConfiguration{TagNames: []string{"TagName1"}},
					&mockDB{getRowBodyData: "{}", errPut: errors.New(documentUpdateConflictErrMsgFromKivik)})
				require.EqualError(t, err, "failure while updating the MapReduce design document: "+
					"failed to update design document in CouchDB due to document conflict after 2 attempts. "+
					"This storage provider may need to be started with a higher max retry limit. "+
					"Original error message from CouchDB: Conflict: Document update conflict.")
			})
		})
	})
}

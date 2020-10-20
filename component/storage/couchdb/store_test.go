/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package couchdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/go-kivik/kivik"
	"github.com/google/uuid"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	common "github.com/hyperledger/aries-framework-go-ext/test/component/storage"
)

const (
	couchDBURL          = "admin:password@localhost:5982"
	dockerCouchdbImage  = "couchdb"
	dockerCouchdbTag    = "3.1.0"
	dockerCouchdbVolume = "%s/testdata/single-node.ini:/opt/couchdb/etc/local.d/single-node.ini"
)

type mockLoggerFn func(msg string, args ...interface{})

func (fn mockLoggerFn) Warnf(msg string, args ...interface{}) {
	fn(msg, args)
}

func TestMain(m *testing.M) {
	code := 1

	defer func() { os.Exit(code) }()

	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("pool: %v", err))
	}

	path, err := filepath.Abs("./")
	if err != nil {
		panic(fmt.Sprintf("filepath: %v", err))
	}

	couchdbResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerCouchdbImage,
		Tag:        dockerCouchdbTag,
		Env:        []string{"COUCHDB_USER=admin", "COUCHDB_PASSWORD=password"},
		Mounts:     []string{fmt.Sprintf(dockerCouchdbVolume, path)},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"5984/tcp": {{HostIP: "", HostPort: "5982"}},
		},
	})
	if err != nil {
		panic(fmt.Sprintf("run with options: %v", err))
	}

	defer func() {
		if err := pool.Purge(couchdbResource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

	if err := checkCouchDB(); err != nil {
		panic(fmt.Sprintf("check CouchDB: %v", err))
	}

	code = m.Run()
}

const retries = 30

func checkCouchDB() error {
	return backoff.Retry(func() error {
		return PingCouchDB(couchDBURL)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), retries))
}

func TestCouchDBStore(t *testing.T) {
	t.Run("Couchdb connection refused", func(t *testing.T) {
		const (
			driverName     = "couch"
			dataSourceName = "admin:password@localhost:1111"
			dbName         = "db_name"
		)

		client, err := kivik.New(driverName, dataSourceName)
		require.NoError(t, err)

		db := &StoreCouchDB{db: client.DB(context.Background(), dbName)}
		require.Error(t, db.Put("key", []byte("val")))
	})

	t.Run("Test couchdb store failures", func(t *testing.T) {
		prov, err := NewProvider("")
		require.Error(t, err)
		require.Contains(t, err.Error(), blankHostErrMsg)
		require.Nil(t, prov)

		_, err = NewProvider("wrongURL")
		require.Error(t, err)
	})

	t.Run("Test couchdb multi store close by name", func(t *testing.T) {
		prov, err := NewProvider(couchDBURL, WithDBPrefix("dbprefix"))
		require.NoError(t, err)

		const commonKey = "did:example:1"
		data := []byte("value1")

		storeNames := []string{randomKey(), randomKey(), randomKey(), randomKey(), randomKey()}
		storesToClose := []string{storeNames[0], storeNames[2], storeNames[4]}

		for _, name := range storeNames {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)

			e = store.Put(commonKey, data)
			require.NoError(t, e)
		}

		for _, name := range storeNames {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)
			require.NotNil(t, store)

			dataRead, e := store.Get(commonKey)
			require.NoError(t, e)
			require.Equal(t, data, dataRead)
		}

		// verify store length
		require.Len(t, prov.dbs, 5)

		for _, name := range storesToClose {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)
			require.NotNil(t, store)

			e = prov.CloseStore(name)
			require.NoError(t, e)
		}

		// verify store length
		require.Len(t, prov.dbs, 2)

		// try to close non existing db
		err = prov.CloseStore("store_x")
		require.NoError(t, err)

		// verify store length
		require.Len(t, prov.dbs, 2)

		err = prov.Close()
		require.NoError(t, err)

		// verify store length
		require.Empty(t, prov.dbs)

		// try close all again
		err = prov.Close()
		require.NoError(t, err)
	})

	t.Run("Test CouchDB store query", func(t *testing.T) {
		t.Run("Successfully query using index", func(t *testing.T) {
			queryTest(t, "payload.employeeID")
		})
		t.Run("Successful query, but the specified index isn't valid for the query", func(t *testing.T) {
			done := make(chan struct{})
			// Despite the selected index ("name") not being applicable to our query ("payload.employeeID"),
			// CouchDB doesn't throw an error. Instead, it just ignores the chosen index and still does the search,
			// albeit slowly. When this happens, we log the warning message returned from CouchDB.
			queryTest(t, "name", WithLogger(mockLoggerFn(func(msg string, args ...interface{}) {
				defer close(done)

				require.Contains(t, msg,
					`_design/TestDesignDoc, TestIndex was not used because it is not a valid index for this query.
No matching index found, create an index to optimize query time.`)
			})))

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("timeout")
			}
		})
		t.Run("Fail to query - invalid query JSON", func(t *testing.T) {
			prov, err := NewProvider(couchDBURL)
			require.NoError(t, err)
			store, err := prov.OpenStore(randomKey())
			require.NoError(t, err)

			itr, err := store.Query(``)
			require.EqualError(t,
				err, "failed to query CouchDB using the find endpoint: Bad Request: invalid UTF-8 JSON")
			require.Nil(t, itr)
		})
	})
}

func queryTest(t *testing.T, fieldToIndex string, opts ...Option) {
	prov, err := NewProvider(couchDBURL, opts...)
	require.NoError(t, err)
	store, err := prov.OpenStore(randomKey())
	require.NoError(t, err)

	couchDBStore, ok := store.(*StoreCouchDB)
	require.True(t, ok, "failed to assert store as a StoreCouchDB")

	testJSONPayload := []byte(`{"employeeID":1234,"name":"Mr. Aries"}`)

	err = store.Put("sampleDBKey", testJSONPayload)
	require.NoError(t, err)

	const designDocName = "TestDesignDoc"

	const indexName = "TestIndex"

	err = couchDBStore.db.CreateIndex(context.Background(), designDocName, indexName,
		`{"fields": ["`+fieldToIndex+`"]}`)
	require.NoError(t, err)

	itr, err := store.Query(`{
		   "selector": {
		       "payload.employeeID": 1234
		   },
			"use_index": ["` + designDocName + `", "` + indexName + `"]
		}`)
	require.NoError(t, err)

	ok = itr.Next()
	require.True(t, ok)
	require.NoError(t, itr.Error())

	value := itr.Value()
	require.Equal(t, testJSONPayload, value)
	require.NoError(t, itr.Error())

	ok = itr.Next()
	require.False(t, ok)
	require.NoError(t, itr.Error())

	itr.Release()
	require.NoError(t, itr.Error())
}

func TestCouchDBStore_Common(t *testing.T) {
	prov, err := NewProvider(couchDBURL)
	require.NoError(t, err)

	common.TestAll(t, prov)
}

func randomKey() string {
	// prefix `key` is needed for couchdb due to error e.g Name: '7c80bdcd-b0e3-405a-bb82-fae75f9f2470'.
	// Only lowercase characters (a-z), digits (0-9), and any of the characters _, $, (, ), +, -, and / are allowed.
	// Must begin with a letter.
	return "key" + uuid.New().String()
}

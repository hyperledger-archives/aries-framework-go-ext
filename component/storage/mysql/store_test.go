/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mysql_test

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	commontest "github.com/hyperledger/aries-framework-go/test/component/storage"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
)

type mysqlLogger struct{}

// Print ignores MySQL logs.
func (*mysqlLogger) Print(...interface{}) {}

const (
	dockerMySQLImage = "mysql"
	dockerMySQLTag   = "8.0.20"
	sqlStoreDBURL    = "root:my-secret-pw@tcp(127.0.0.1:3301)/?interpolateParams=true&multiStatements=true"
)

func TestMain(m *testing.M) {
	code := 1

	defer func() { os.Exit(code) }()

	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("pool: %v", err))
	}

	mysqlResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMySQLImage, Tag: dockerMySQLTag, Env: []string{"MYSQL_ROOT_PASSWORD=my-secret-pw"},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"3306/tcp": {{HostIP: "", HostPort: "3301"}},
		},
	})
	if err != nil {
		log.Println(`Failed to start MySQL Docker image.` +
			` This can happen if there is a MySQL container still running from a previous unit test run.` +
			` Try "docker ps" from the command line and kill the old container if it's still running.`)
		panic(fmt.Sprintf("run with options: %v", err))
	}

	defer func() {
		if err = pool.Purge(mysqlResource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

	if err := checkMySQL(); err != nil {
		panic(fmt.Sprintf("check MySQL: %v", err))
	}

	code = m.Run()
}

func checkMySQL() error {
	const retries = 60

	if err := mysql.SetLogger((*mysqlLogger)(nil)); err != nil {
		return fmt.Errorf("set logger: %w", err)
	}

	return backoff.Retry(func() error {
		db, err := sql.Open("mysql", sqlStoreDBURL)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}

		return db.Ping()
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), retries))
}

func TestSQLDBStore(t *testing.T) {
	t.Run("Test SQL open store", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL, WithDBPrefix("prefixdb"))
		require.NoError(t, err)

		_, err = prov.OpenStore("")
		require.Error(t, err)
		require.Equal(t, err.Error(), "store name is required")
	})
	t.Run("Test wrong url", func(t *testing.T) {
		_, err := NewProvider("root:@tcp(127.0.0.1:45454)/")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failure while pinging MySQL")
	})
	t.Run("Test sql db store failures", func(t *testing.T) {
		prov, err := NewProvider("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "DB URL for new mySQL DB provider can't be blank")
		require.Nil(t, prov)

		// Invalid db path
		_, err = NewProvider("root:@tcp(127.0.0.1:45454)")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failure while opening MySQL connection")

		_, err = NewProvider("root:@tcp(127.0.0.1:45454)/")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failure while pinging MySQL")
	})
	t.Run("Test sqlDB multi store close by name", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL, WithDBPrefix("prefixdb"))
		require.NoError(t, err)

		const commonKey = "did:example:1"
		data := []byte("value1")

		storeNames := []string{"store_1", "store_2", "store_3", "store_4", "store_5"}
		storesToClose := []string{"store_1", "store_3", "store_5"}

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

		for _, name := range storesToClose {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)
			require.NotNil(t, store)

			err = store.Close()
			require.NoError(t, err)
		}

		err = prov.Close()
		require.NoError(t, err)

		// try close all again
		err = prov.Close()
		require.NoError(t, err)
	})
	t.Run("Flush", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		store, err := prov.OpenStore("storename")
		require.NoError(t, err)

		err = store.Flush()
		require.NoError(t, err)
	})
}

func TestNotImplementedMethods(t *testing.T) {
	t.Run("Not implemented methods", func(t *testing.T) {
		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		require.Panics(t, func() {
			prov.GetOpenStores()
		})

		store, err := prov.OpenStore("storename")
		require.NoError(t, err)

		_, err = store.GetBulk()
		require.EqualError(t, err, "not implemented")
	})
}

func TestSqlDBProvider_GetStoreConfig(t *testing.T) {
	t.Run("Fail to get store configuration", func(t *testing.T) {
		provider, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		storeName := randomStoreName()

		_, err = provider.OpenStore(storeName)
		require.NoError(t, err)

		config, err := provider.GetStoreConfig(storeName)
		require.EqualError(t, err,
			fmt.Sprintf(`failed to get store configuration for "%s": `+
				`failed to get DB entry: data not found`, storeName))
		require.Empty(t, config)
	})
}

func TestSqlDBStore_Put(t *testing.T) {
	t.Run("Fail to update tag map since the DB connection was closed", func(t *testing.T) {
		provider, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		testStore, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		err = testStore.Close()
		require.NoError(t, err)

		err = testStore.Put("key", []byte("value"), storage.Tag{})
		require.EqualError(t, err, "failed to update tag map: failed to get tag map: failed to get data: "+
			"failed to get DB entry: failure while querying row: sql: database is closed")
	})
	t.Run("Fail to unmarshal tag map bytes", func(t *testing.T) {
		provider, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		testStore, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		err = testStore.Put("TagMap", []byte("Not a proper tag map"))
		require.NoError(t, err)

		err = testStore.Put("key", []byte("value"), storage.Tag{})
		require.EqualError(t, err, "failed to update tag map: failed to get tag map: "+
			"failed to unmarshal tag map bytes: invalid character 'N' looking for beginning of value")
	})
}

func TestSqlDBStore_Query(t *testing.T) {
	t.Run("Fail to get tag map since the DB connection was closed", func(t *testing.T) {
		provider, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		testStore, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		err = testStore.Close()
		require.NoError(t, err)

		itr, err := testStore.Query("expression")
		require.EqualError(t, err, "failed to get database keys matching query: failed to get tag map: "+
			"failed to get data: failed to get DB entry: failure while querying row: sql: database is closed")
		require.Nil(t, itr)
	})
	t.Run("Not supported options", func(t *testing.T) {
		provider, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		store, err := provider.OpenStore("TestStore")
		require.NoError(t, err)

		iterator, err := store.Query("TagName:TagValue", storage.WithInitialPageNum(1))
		require.EqualError(t, err, "mySQL provider does not currently support "+
			"setting the initial page number of query results")
		require.Nil(t, iterator)

		iterator, err = store.Query("TagName:TagValue", storage.WithSortOrder(&storage.SortOptions{}))
		require.EqualError(t, err, "mySQL provider does not currently support custom sort options for "+
			"query results")
		require.Nil(t, iterator)
	})
}

func TestSqlDBIterator(t *testing.T) {
	provider, err := NewProvider(sqlStoreDBURL)
	require.NoError(t, err)

	testStoreName := randomStoreName()

	testStore, err := provider.OpenStore(testStoreName)
	require.NoError(t, err)

	err = provider.SetStoreConfig(testStoreName, storage.StoreConfiguration{})
	require.NoError(t, err)

	itr, err := testStore.Query("expression")
	require.NoError(t, err)

	t.Run("Fail to get value from store", func(t *testing.T) {
		value, errValue := itr.Value()
		require.EqualError(t, errValue, "failed to get value from store: failed to get DB entry: key is mandatory")
		require.Nil(t, value)
	})
	t.Run("Fail to get tags from store", func(t *testing.T) {
		tags, errGetTags := itr.Tags()
		require.EqualError(t, errGetTags, "failed to get tags from store: failed to get DB entry: key is mandatory")
		require.Nil(t, tags)
	})
}

func TestSqlDBStore_Common(t *testing.T) {
	t.Run("Without prefix", func(t *testing.T) {
		provider, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		commontest.TestProviderOpenStoreSetGetConfig(t, provider)
		commontest.TestPutGet(t, provider)
		commontest.TestStoreGetTags(t, provider)
		commontest.TestStoreQuery(t, provider)
		commontest.TestStoreDelete(t, provider)
		commontest.TestStoreClose(t, provider)
		commontest.TestProviderClose(t, provider)
		commontest.TestStoreBatch(t, provider)
	})
	t.Run("With prefix", func(t *testing.T) {
		provider, err := NewProvider(sqlStoreDBURL, WithDBPrefix("db-prefix-"))
		require.NoError(t, err)

		commontest.TestProviderOpenStoreSetGetConfig(t, provider)
		commontest.TestPutGet(t, provider)
		commontest.TestStoreGetTags(t, provider)
		commontest.TestStoreQuery(t, provider)
		commontest.TestStoreDelete(t, provider)
		commontest.TestStoreClose(t, provider)
		commontest.TestProviderClose(t, provider)
		commontest.TestStoreBatch(t, provider)
	})
}

func TestSqlDBStore_Batch(t *testing.T) {
	t.Run("error on empty key", func(t *testing.T) {
		s := newStore(t, randomStoreName())
		err := s.Batch([]storage.Operation{{}})
		require.Error(t, err)
		require.Equal(t, err.Error(), "key cannot be empty")
	})

	t.Run("error removing key from tagMap", func(t *testing.T) {
		storeName := randomStoreName()
		s := newStore(t, storeName)

		db, err := sql.Open("mysql", sqlStoreDBURL)
		require.NoError(t, err)

		_, err = db.Exec(
			fmt.Sprintf("INSERT INTO `%s`.`%s` VALUES (?,?)", storeName, storeName),
			"TagMap", []byte("{"),
		)
		require.NoError(t, err)

		err = s.Batch([]storage.Operation{{
			Key:   "test",
			Value: nil,
			Tags: []storage.Tag{{
				Name:  "test",
				Value: "value",
			}},
		}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to remove key from tag map")
	})

	t.Run("error removing key from tagMap", func(t *testing.T) {
		storeName := randomStoreName()
		s := newStore(t, storeName)

		db, err := sql.Open("mysql", sqlStoreDBURL)
		require.NoError(t, err)

		_, err = db.Exec(
			fmt.Sprintf("INSERT INTO `%s`.`%s` VALUES (?,?)", storeName, storeName),
			"TagMap", []byte("{"),
		)
		require.NoError(t, err)

		err = s.Batch([]storage.Operation{{
			Key:   "test",
			Value: []byte("value"),
			Tags: []storage.Tag{{
				Name:  "test",
				Value: "value",
			}},
		}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to update tag map")
	})
}

func TestEnsureTagMapIsOnlyCreatedWhenNeeded(t *testing.T) {
	provider, err := NewProvider(sqlStoreDBURL)
	require.NoError(t, err)

	// We defer creating the tag map entry until we actually have to. This saves on space if a client does not need
	// to use tags + querying. The only thing that should cause the tag map entry to be created is if a Put is done
	// with tags.

	testStore, err := provider.OpenStore("TestStore")
	require.NoError(t, err)

	err = provider.SetStoreConfig("TestStore", storage.StoreConfiguration{TagNames: []string{"TagName1"}})
	require.NoError(t, err)

	value, err := testStore.Get("TagMap")
	require.True(t, errors.Is(err, storage.ErrDataNotFound), "unexpected error or no error")
	require.Nil(t, value)

	err = testStore.Put("Key", []byte("value"))
	require.NoError(t, err)

	value, err = testStore.Get("TagMap")
	require.True(t, errors.Is(err, storage.ErrDataNotFound))
	require.Nil(t, value)

	err = testStore.Delete("Key")
	require.NoError(t, err)

	value, err = testStore.Get("TagMap")
	require.True(t, errors.Is(err, storage.ErrDataNotFound), "unexpected error or no error")
	require.Nil(t, value)

	err = testStore.Put("Key", []byte("value"), storage.Tag{Name: "TagName1"})
	require.NoError(t, err)

	value, err = testStore.Get("TagMap")
	require.NoError(t, err)
	require.Equal(t, `{"TagName1":{"Key":{}}}`, string(value))
}

func TestStoreLargeData(t *testing.T) {
	provider, err := NewProvider(sqlStoreDBURL)
	require.NoError(t, err)

	testStore, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	// Store 1 MiB worth of data.
	err = testStore.Put("key", make([]byte, 1000000))
	require.NoError(t, err)
}

func randomStoreName() string {
	return "store-" + uuid.New().String()
}

func newStore(t *testing.T, name string) storage.Store {
	t.Helper()

	p, err := NewProvider(sqlStoreDBURL)
	require.NoError(t, err)

	s, err := p.OpenStore(name)
	require.NoError(t, err)

	return s
}

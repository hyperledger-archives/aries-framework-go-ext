/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mysql_test

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-sql-driver/mysql"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	common "github.com/hyperledger/aries-framework-go-ext/test/component/storage"
)

type mysqlLogger struct{}

// Print ignores MySQL logs.
func (*mysqlLogger) Print(_ ...interface{}) {}

const (
	dockerMySQLImage = "mysql"
	dockerMySQLTag   = "8.0.20"
	sqlStoreDBURL    = "root:my-secret-pw@tcp(127.0.0.1:3301)/"
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

func TestSqlDBStore(t *testing.T) {
	t.Run("Test sql multi store put and get", func(t *testing.T) {
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

			e = prov.CloseStore(name)
			require.NoError(t, e)

			// try to get after provider is closed
			_, err = store.Get(commonKey)
			require.Error(t, err)
		}

		// try to close non existing db
		err = prov.CloseStore("store_x")
		require.EqualError(t, err, storage.ErrStoreNotFound.Error())

		err = prov.Close()
		require.NoError(t, err)

		// try close all again
		err = prov.Close()
		require.NoError(t, err)
	})
}

func TestSqlDBStore_Common(t *testing.T) {
	prov, err := NewProvider(sqlStoreDBURL)
	require.NoError(t, err)

	common.TestAll(t, prov)
}

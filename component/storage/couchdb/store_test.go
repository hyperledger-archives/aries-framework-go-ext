/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package couchdb_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	commontest "github.com/hyperledger/aries-framework-go/test/component/storage"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
)

const (
	couchDBURL          = "admin:password@localhost:5984"
	dockerCouchdbImage  = "couchdb"
	dockerCouchdbTag    = "3.1.0"
	dockerCouchdbVolume = "%s/testdata/single-node.ini:/opt/couchdb/etc/local.d/single-node.ini"
)

type mockLogger struct{}

func (*mockLogger) Warnf(string, ...interface{}) {
	log.Printf("mock logger output")
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
			"5984/tcp": {{HostIP: "", HostPort: "5984"}},
		},
	})
	if err != nil {
		log.Println(`Failed to start CouchDB Docker image.` +
			` This can happen if there is a CouchDB container still running from a previous unit test run.` +
			` Try "docker ps" from the command line and kill the old container if it's still running.`)
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

func TestCommon(t *testing.T) {
	t.Run("Without prefix option", func(t *testing.T) {
		t.Run("Without max document conflict retries option", func(t *testing.T) {
			t.Run("Without custom logger option", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL)
				require.NoError(t, err)

				commontest.TestAll(t, prov)
			})
			t.Run("With custom logger option", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithLogger(&mockLogger{}))
				require.NoError(t, err)

				commontest.TestAll(t, prov)
			})
		})
		t.Run("With Max Document Conflict Retries option set to 2", func(t *testing.T) {
			t.Run("Without custom logger", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithMaxDocumentConflictRetries(2))
				require.NoError(t, err)

				commontest.TestAll(t, prov)
			})
			t.Run("With custom logger", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithMaxDocumentConflictRetries(2),
					WithLogger(&mockLogger{}))
				require.NoError(t, err)

				commontest.TestAll(t, prov)
			})
		})
	})
	t.Run("With prefix option", func(t *testing.T) {
		t.Run("Without max document conflict retries option", func(t *testing.T) {
			t.Run("Without custom logger option", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithDBPrefix("test-prefix"))
				require.NoError(t, err)

				commontest.TestAll(t, prov)
			})
			t.Run("With custom logger", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithDBPrefix("test-prefix"), WithLogger(&mockLogger{}))
				require.NoError(t, err)

				commontest.TestAll(t, prov)
			})
		})
		t.Run("With max document conflict retries option set to 2", func(t *testing.T) {
			t.Run("Without custom logger", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithDBPrefix("test-prefix"),
					WithMaxDocumentConflictRetries(2))
				require.NoError(t, err)

				commontest.TestAll(t, prov)
			})
			t.Run("With custom logger", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithDBPrefix("test-prefix"),
					WithMaxDocumentConflictRetries(2), WithLogger(&mockLogger{}))
				require.NoError(t, err)

				commontest.TestAll(t, prov)
			})
		})
	})
}

func TestNewProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)
	})
	t.Run("Fail to ping CouchDB: blank URL", func(t *testing.T) {
		provider, err := NewProvider("")
		require.EqualError(t, err, "failed to ping couchDB: url can't be blank")
		require.Nil(t, provider)
	})
}

func TestProvider_OpenStore(t *testing.T) {
	t.Run("Failure: store name cannot start with a number", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL)
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("3StoreNameStartingWithANumber")
		require.EqualError(t, err, "failed to create database in CouchDB: Bad Request: Name: "+
			"'3storenamestartingwithanumber'. Only lowercase characters (a-z), digits (0-9), "+
			"and any of the characters _, $, (, ), +, -, and / are allowed. Must begin with a letter.")
		require.Nil(t, store)
	})
}

func TestProvider_SetStoreConfig(t *testing.T) {
	t.Run("Failure: invalid tag name", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		storeName := randomStoreName()

		err = provider.SetStoreConfig(storeName,
			storage.StoreConfiguration{TagNames: []string{"payload"}})
		require.EqualError(t, err,
			`invalid tag names: tag name cannot be "payload" as it is a reserved keyword`)
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("Failure: tag name is a reserved keyword", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("value"),
			[]storage.Tag{
				{Name: "payload"},
			}...)
		require.EqualError(t, err, `failed to add tags to the raw document: `+
			`tag name cannot be "payload" as it is a reserved keyword`)
	})
}

func randomStoreName() string {
	return "store-" + uuid.New().String()
}

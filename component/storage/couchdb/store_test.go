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
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
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

func (l *mockLogger) Infof(msg string, args ...interface{}) {
	log.Printf("mock logger output")
}

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
		return ReadinessCheck(couchDBURL)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), retries))
}

type stringLogger struct {
	log string
}

func (s *stringLogger) Infof(msg string, args ...interface{}) {
	s.log += fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Warnf(msg string, args ...interface{}) {
	s.log += fmt.Sprintf(msg, args...)
}

func TestCommon(t *testing.T) {
	t.Run("Without prefix option", func(t *testing.T) {
		t.Run("Without max document conflict retries option", func(t *testing.T) {
			t.Run("Without custom logger option", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL)
				require.NoError(t, err)

				runCommonTests(t, prov)
			})
			t.Run("With custom logger option", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithLogger(&mockLogger{}))
				require.NoError(t, err)

				runCommonTests(t, prov)
			})
		})
		t.Run("With Max Document Conflict Retries option set to 2", func(t *testing.T) {
			t.Run("Without custom logger", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithMaxDocumentConflictRetries(2))
				require.NoError(t, err)

				runCommonTests(t, prov)
			})
			t.Run("With custom logger", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithMaxDocumentConflictRetries(2),
					WithLogger(&mockLogger{}))
				require.NoError(t, err)

				runCommonTests(t, prov)
			})
		})
	})
	t.Run("With prefix option", func(t *testing.T) {
		t.Run("Without max document conflict retries option", func(t *testing.T) {
			t.Run("Without custom logger option", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithDBPrefix("test-prefix"))
				require.NoError(t, err)

				runCommonTests(t, prov)
			})
			t.Run("With custom logger", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithDBPrefix("test-prefix"), WithLogger(&mockLogger{}))
				require.NoError(t, err)

				runCommonTests(t, prov)
			})
		})
		t.Run("With max document conflict retries option set to 2", func(t *testing.T) {
			t.Run("Without custom logger", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithDBPrefix("test-prefix"),
					WithMaxDocumentConflictRetries(2))
				require.NoError(t, err)

				runCommonTests(t, prov)
			})
			t.Run("With custom logger", func(t *testing.T) {
				prov, err := NewProvider(couchDBURL, WithDBPrefix("test-prefix"),
					WithMaxDocumentConflictRetries(2), WithLogger(&mockLogger{}))
				require.NoError(t, err)

				runCommonTests(t, prov)
			})
		})
	})
}

func runCommonTests(t *testing.T, prov *Provider) {
	t.Helper()

	commontest.TestAll(t, prov, commontest.SkipSortTests(true),
		commontest.SkipIteratorTotalItemTests(true))
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

func TestStore_Put_DuplicateTagName(t *testing.T) {
	provider, err := NewProvider(couchDBURL)
	require.NoError(t, err)
	require.NotNil(t, provider)

	store, err := provider.OpenStore("TestStore")
	require.NoError(t, err)

	err = store.Put("key", []byte("value"), spi.Tag{Name: "SomeName"}, spi.Tag{Name: "SomeName"})
	require.EqualError(t, err, "tag name SomeName appears in more than one tag. "+
		"A single key-value pair cannot have multiple tags that share the same tag name")
}

func TestStore_Batch_DuplicateTagName(t *testing.T) {
	provider, err := NewProvider(couchDBURL)
	require.NoError(t, err)
	require.NotNil(t, provider)

	store, err := provider.OpenStore("TestStore")
	require.NoError(t, err)

	err = store.Batch(
		[]spi.Operation{{
			Key: "key", Value: []byte("value"),
			Tags: []spi.Tag{{Name: "SomeName"}, {Name: "SomeName"}},
		}})
	require.EqualError(t, err, "failed to set document tags on the operation at index 0: tag name SomeName "+
		"appears in more than one tag. A single key-value pair cannot have multiple tags that share the same tag name")
}

func TestNoIndexSetWarning(t *testing.T) {
	stringLogger := &stringLogger{}
	prov, err := NewProvider(couchDBURL, WithLogger(stringLogger))
	require.NoError(t, err)

	store, err := prov.OpenStore("noindexteststore")
	require.NoError(t, err)

	iterator, err := store.Query("TagNameThatWasNeverSetInStoreConfig")
	require.NoError(t, err)

	anotherEntry, err := iterator.Next()
	require.False(t, anotherEntry)
	require.NoError(t, err)

	require.Equal(t, `[Store name: noindexteststore] Received warning from CouchDB. Message: `+
		`No matching index found, create an index to optimize query time. Original query: `+
		`{"selector":{"tags.TagNameThatWasNeverSetInStoreConfig":{"$exists":true}},"limit":25}. `+
		`To resolve this, make sure the store configuration has been set using the Store.SetStoreConfig method. `+
		`The store configuration must contain the tag name used in the query.`, stringLogger.log)
}

func TestMultipleProvidersSettingSameStoreConfigurationAtTheSameTime(t *testing.T) {
	providers := make([]*Provider, 10)

	for i := 0; i < 10; i++ {
		provider, err := NewProvider(couchDBURL, WithMaxDocumentConflictRetries(1))
		require.NoError(t, err)

		providers[i] = provider
	}

	// Since all the providers share the same CouchDB instance and database prefix, we only need to open the store once
	// (and it doesn't matter which provider we use)
	_, err := providers[0].OpenStore("MultipleProviderTest")
	require.NoError(t, err)

	var waitGroup sync.WaitGroup

	for i := 0; i < 10; i++ {
		i := i

		waitGroup.Add(1)

		setStoreConfig := func() {
			defer waitGroup.Done()

			err := providers[i].SetStoreConfig("MultipleProviderTest",
				spi.StoreConfiguration{TagNames: []string{
					"TagName1", "TagName2", "TagName3", "TagName4",
					"TagName5", "TagName6", "TagName7", "TagName8",
				}})
			require.NoError(t, err)
		}
		go setStoreConfig()
	}

	waitGroup.Wait()
}

func TestIteratorTotalItemsCountWithTagsWithBlankTagValues(t *testing.T) {
	prov, err := NewProvider(couchDBURL)
	require.NoError(t, err)

	store, err := prov.OpenStore("TotalItemBlankTagValueTest")
	require.NoError(t, err)

	tagName := "tagName1"

	err = prov.SetStoreConfig("TotalItemBlankTagValueTest",
		spi.StoreConfiguration{TagNames: []string{tagName}})
	require.NoError(t, err)

	iterator, err := store.Query(tagName)
	require.NoError(t, err)

	totalCount, err := iterator.TotalItems()
	require.NoError(t, err)
	require.Equal(t, 0, totalCount)

	err = store.Put("key1", []byte("value1"), spi.Tag{Name: tagName})
	require.NoError(t, err)

	// Since the iterator makes an explicit query to CouchDB every time we call TotalItems,
	// there's no need to re-run store.Query. TotalItems() will always reflect the current state of the database.
	totalCount, err = iterator.TotalItems()
	require.NoError(t, err)
	require.Equal(t, 1, totalCount)

	err = store.Put("key2", []byte("value2"), spi.Tag{Name: tagName, Value: "tagValue1"})
	require.NoError(t, err)

	totalCount, err = iterator.TotalItems()
	require.NoError(t, err)
	require.Equal(t, 2, totalCount)
}

func TestProvider_Ping(t *testing.T) {
	provider, err := NewProvider(couchDBURL)
	require.NoError(t, err)
	require.NotNil(t, provider)

	err = provider.Ping()
	require.NoError(t, err)
}

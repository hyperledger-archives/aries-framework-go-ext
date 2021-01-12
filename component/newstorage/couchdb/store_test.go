/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package couchdb_test

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/newstorage"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go-ext/component/newstorage/couchdb"
	common "github.com/hyperledger/aries-framework-go-ext/test/component/newstorage"
)

const (
	couchDBURL          = "admin:password@localhost:5984"
	dockerCouchdbImage  = "couchdb"
	dockerCouchdbTag    = "3.1.0"
	dockerCouchdbVolume = "%s/testdata/single-node.ini:/opt/couchdb/etc/local.d/single-node.ini"
)

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
	t.Run("Success", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"), WithMaxDocumentConflictRetries(0))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Failure: store name cannot contain capital letters", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore("StoreNameWithCapitalLetters")
		require.EqualError(t, err, "failed to create database in CouchDB: Bad Request: Name: "+
			"'prefix_StoreNameWithCapitalLetters'. Only lowercase characters (a-z), digits (0-9), "+
			"and any of the characters _, $, (, ), +, -, and / are allowed. Must begin with a letter.")
		require.Nil(t, store)
	})
}

func TestProvider_SetStoreConfig(t *testing.T) {
	t.Run("Success: all new tags", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		err = provider.SetStoreConfig(storeName,
			newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2"}})
		require.NoError(t, err)

		// Verify that the config is set
		config, err := provider.GetStoreConfig(storeName)
		require.NoError(t, err)
		require.Equal(t, "tagName1", config.TagNames[0])
		require.Equal(t, "tagName2", config.TagNames[1])
	})
	t.Run("Success: merge a new tag in with existing tags", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		// Set initial tags.
		err = provider.SetStoreConfig(storeName,
			newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2"}})
		require.NoError(t, err)

		// Now we want another tag to be indexed, so we set the store config again, but include the new tag as well
		// as the old ones.
		err = provider.SetStoreConfig(storeName,
			newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3"}})
		require.NoError(t, err)

		// Verify that the new config is set.
		config, err := provider.GetStoreConfig(storeName)
		require.NoError(t, err)
		require.Equal(t, "tagName1", config.TagNames[0])
		require.Equal(t, "tagName2", config.TagNames[1])
		require.Equal(t, "tagName3", config.TagNames[2])
	})
	t.Run("Success: delete all existing tags", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		// Set initial tags.
		err = provider.SetStoreConfig(storeName,
			newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2"}})
		require.NoError(t, err)

		// Delete all existing indices by passing in an empty newstorage.StoreConfiguration.
		err = provider.SetStoreConfig(storeName, newstorage.StoreConfiguration{})
		require.NoError(t, err)

		// Verify that the new config is set, resulting in no indexes existing anymore.
		config, err := provider.GetStoreConfig(storeName)
		require.NoError(t, err)
		require.Empty(t, config)
	})
	t.Run("Success: merge a new tag in with existing tags while deleting some too", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		// Set initial tags.
		err = provider.SetStoreConfig(storeName,
			newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2"}})
		require.NoError(t, err)

		// Now we want tagName1 to be kept, tagName2 to be removed, and tagName3 to be indexed.
		err = provider.SetStoreConfig(storeName,
			newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName3"}})
		require.NoError(t, err)

		// Verify that the new config is set.
		config, err := provider.GetStoreConfig(storeName)
		require.NoError(t, err)
		require.Equal(t, "tagName1", config.TagNames[0])
		require.Equal(t, "tagName3", config.TagNames[1])
	})
	t.Run("Failure: database does not exist", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		storeName := randomStoreName()

		err = provider.SetStoreConfig(storeName,
			newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2"}})
		require.EqualError(t, err,
			"failure while setting indexes: failed to get existing indexes: "+
				newstorage.ErrStoreNotFound.Error())
	})
	t.Run("Failure: invalid tag name", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		storeName := randomStoreName()

		err = provider.SetStoreConfig(storeName,
			newstorage.StoreConfiguration{TagNames: []string{"payload"}})
		require.EqualError(t, err,
			`invalid tag names: tag name cannot be "payload" as it is a reserved keyword`)
	})
}

func TestProvider_GetStoreConfig(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		err = provider.SetStoreConfig(storeName,
			newstorage.StoreConfiguration{TagNames: []string{"tagName1", "tagName2"}})
		require.NoError(t, err)

		config, err := provider.GetStoreConfig(storeName)
		require.NoError(t, err)
		require.Len(t, config.TagNames, 2)
		require.Equal(t, "tagName1", config.TagNames[0])
		require.Equal(t, "tagName2", config.TagNames[1])
	})
	t.Run("Failure: database does not exist", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		storeName := randomStoreName()

		config, err := provider.GetStoreConfig(storeName)
		require.EqualError(t, err, "failed to get existing indexes: "+newstorage.ErrStoreNotFound.Error())
		require.Empty(t, config)
	})
}

func TestProvider_Close(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		err = provider.Close()
		require.NoError(t, err)
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
			[]newstorage.Tag{
				{Name: "payload"},
			}...)
		require.EqualError(t, err, `tag name cannot be "payload" as it is a reserved keyword`)
	})
}

func TestStore_GetTags(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Put("key", []byte("value"),
			[]newstorage.Tag{
				{Name: "tagName1", Value: "tagValue1"},
				{Name: "tagName2", Value: "tagValue2"},
			}...)
		require.NoError(t, err)

		tags, err := store.GetTags("key")
		require.NoError(t, err)

		// CouchDB can return the tags in either order, so we need to check for either order
		var gotExpectedTags bool
		if tags[0].Name == "tagName1" && tags[0].Value == "tagValue1" &&
			tags[1].Name == "tagName2" && tags[1].Value == "tagValue2" {
			gotExpectedTags = true
		} else if tags[0].Name == "tagName2" && tags[0].Value == "tagValue2" &&
			tags[1].Name == "tagName1" && tags[1].Value == "tagValue1" {
			gotExpectedTags = true
		}
		require.Truef(t, gotExpectedTags, "got unexpected tag contents")
	})
	t.Run("Failure: blank key", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		tags, err := store.GetTags("")
		require.EqualError(t, err, "key is mandatory")
		require.Nil(t, tags)
	})
	t.Run("Failure: data not found", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		tags, err := store.GetTags("key")
		require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
		require.Nil(t, tags)
	})
}

func TestStore_GetBulk(t *testing.T) {
	t.Run("Failure - not implemented", func(t *testing.T) {
		store := &Store{}
		_, err := store.GetBulk()
		require.EqualError(t, err, "not implemented")
	})
}

func TestStore_Query(t *testing.T) {
	t.Run("Failure - not implemented", func(t *testing.T) {
		store := &Store{}
		iterator, err := store.Query("")
		require.EqualError(t, err, "not implemented")

		_, err = iterator.Next()
		require.EqualError(t, err, "not implemented")

		err = iterator.Release()
		require.EqualError(t, err, "not implemented")

		_, err = iterator.Key()
		require.EqualError(t, err, "not implemented")

		_, err = iterator.Value()
		require.EqualError(t, err, "not implemented")

		_, err = iterator.Tags()
		require.EqualError(t, err, "not implemented")
	})
}

func TestStore_Batch(t *testing.T) {
	t.Run("Failure - not implemented", func(t *testing.T) {
		store := &Store{}
		err := store.Batch(nil)
		require.EqualError(t, err, "not implemented")
	})
}

func TestStore_Close(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := NewProvider(couchDBURL, WithDBPrefix("prefix"))
		require.NoError(t, err)
		require.NotNil(t, provider)

		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)
		require.NotNil(t, store)

		err = store.Close()
		require.NoError(t, err)
	})
}

func TestCouchDBStore_Common(t *testing.T) {
	t.Run("Without prefix", func(t *testing.T) {
		prov, err := NewProvider(couchDBURL)
		require.NoError(t, err)

		common.TestAll(t, prov)
	})
	t.Run("With prefix", func(t *testing.T) {
		prov, err := NewProvider(couchDBURL, WithDBPrefix("test-prefix"))
		require.NoError(t, err)

		common.TestAll(t, prov)
	})
}

func randomStoreName() string {
	return "store-" + uuid.New().String()
}

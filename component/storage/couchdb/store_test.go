/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package couchdb_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/uuid"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	common "github.com/hyperledger/aries-framework-go-ext/test/component/storage"
)

const (
	couchDBURL          = "admin:password@localhost:5982"
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
	t.Run("Test couchdb store failures", func(t *testing.T) {
		prov, err := NewProvider("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "hostURL for new CouchDB provider can't be blank")
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

		for _, name := range storesToClose {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)
			require.NotNil(t, store)

			e = prov.CloseStore(name)
			require.NoError(t, e)
		}

		// try to close non existing db
		err = prov.CloseStore("store_x")
		require.NoError(t, err)

		err = prov.Close()
		require.NoError(t, err)

		// try close all again
		err = prov.Close()
		require.NoError(t, err)
	})
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

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package newstorage contains common tests for newstorage implementation.
//
package newstorage

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/newstorage"
	"github.com/stretchr/testify/require"
)

// TestAll tests common storage functionality.
func TestAll(t *testing.T, provider newstorage.Provider) {
	t.Helper()

	t.Run("Store Put and Get", func(t *testing.T) {
		TestPutGet(t, provider)
	})
	t.Run("Delete", func(t *testing.T) {
		TestDelete(t, provider)
	})
}

// TestPutGet tests common Put and Get functionality.
func TestPutGet(t *testing.T, provider newstorage.Provider) {
	t.Helper()

	const commonKey = "did:example:1"

	data := []byte("value1")

	// Create two different stores for testing.
	store1name := randomStoreName()
	store1, err := provider.OpenStore(store1name)
	require.NoError(t, err)

	store2, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	// Put in store 1.
	err = store1.Put(commonKey, data)
	require.NoError(t, err)

	// Try getting from store 1 - should be found.
	doc, err := store1.Get(commonKey)
	require.NoError(t, err)
	require.NotEmpty(t, doc)
	require.Equal(t, data, doc)

	// Try getting from store 2 - should not be found
	doc, err = store2.Get(commonKey)
	require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
	require.Nil(t, doc)

	// Put in store 2.
	err = store2.Put(commonKey, data)
	require.NoError(t, err)

	// Now we should be able to get that value from store 2.
	doc, err = store2.Get(commonKey)
	require.NoError(t, err)
	require.NotEmpty(t, doc)
	require.Equal(t, data, doc)

	// Create store 3 with the same name as store 1.
	store3, err := provider.OpenStore(store1name)
	require.NoError(t, err)
	require.NotNil(t, store3)

	// Since store 3 points to the same underlying database as store 1, the data should be found.
	doc, err = store3.Get(commonKey)
	require.NoError(t, err)
	require.NotEmpty(t, doc)
	require.Equal(t, data, doc)

	tryNilOrBlankValues(t, store1, data, commonKey)
}

// TestDelete tests common Delete functionality.
func TestDelete(t *testing.T, provider newstorage.Provider) {
	t.Helper()

	const commonKey = "did:example:1234"

	data := []byte("value1")

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	// Put in store 1
	err = store.Put(commonKey, data)
	require.NoError(t, err)

	// Try getting from store 1 - should be found.
	doc, err := store.Get(commonKey)
	require.NoError(t, err)
	require.NotEmpty(t, doc)
	require.Equal(t, data, doc)

	// Delete an existing key - should succeed.
	err = store.Delete(commonKey)
	require.NoError(t, err)

	// Delete a key which never existed. Should not throw any error.
	err = store.Delete("k1")
	require.NoError(t, err)

	// Try to get the value stored under the deleted key - should fail.
	doc, err = store.Get(commonKey)
	require.True(t, errors.Is(err, newstorage.ErrDataNotFound), "got unexpected error or no error")
	require.Empty(t, doc)

	// Try Delete with an blank key - should fail.
	err = store.Delete("")
	require.Error(t, err)
}

func tryNilOrBlankValues(t *testing.T, store newstorage.Store, data []byte, commonKey string) {
	// Try getting blank key
	_, err := store.Get("")
	require.Error(t, err)

	// Try putting with empty key
	err = store.Put("", data)
	require.Error(t, err)

	// Try putting nil value
	err = store.Put(commonKey, nil)
	require.Error(t, err)
}

func randomStoreName() string {
	return "store-" + uuid.New().String()
}

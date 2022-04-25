/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package postgresql_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
	commontest "github.com/hyperledger/aries-framework-go/test/component/storage"
	"github.com/jackc/pgx/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/postgresql"
)

const (
	postgreSQLDockerImage      = "postgres"
	postgreSQLDockerTag        = "14.2"
	postgreSQLConnectionString = "postgres://postgres:mysecretpassword@localhost:5432?sslmode=disable"
)

func TestCommon(t *testing.T) {
	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("pool: %v", err))
	}

	postgreSQLResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: postgreSQLDockerImage, Tag: postgreSQLDockerTag, Env: []string{"POSTGRES_PASSWORD=mysecretpassword"},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"5432/tcp": {{HostIP: "", HostPort: "5432"}},
		},
	})
	if err != nil {
		log.Println(`Failed to start PostgreSQL Docker image.` +
			` This can happen if there is a PostgreSQL container still running from a previous unit test run.` +
			` Try "docker ps" from the command line and kill the old container if it's still running.`)
		panic(fmt.Sprintf("run with options: %v", err))
	}

	defer func() {
		if err = pool.Purge(postgreSQLResource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

	err = ensurePostgreSQLIsUp()
	if err != nil {
		panic(fmt.Sprintf("PostgreSQL did not start successfully or is not reachable: %s", err.Error()))
	}

	t.Run("Default options", func(t *testing.T) {
		provider, err := postgresql.NewProvider(postgreSQLConnectionString)
		require.NoError(t, err)

		runCommonTests(t, provider)
	})
	t.Run("With prefix and timeout options", func(t *testing.T) {
		provider, err := postgresql.NewProvider(postgreSQLConnectionString,
			postgresql.WithDBPrefix("testprefix_"),
			postgresql.WithTimeout(time.Second*5))
		require.NoError(t, err)

		runCommonTests(t, provider)
	})
}

func TestNewProvider(t *testing.T) {
	t.Run("Fail to connect to PostgreSQL instance", func(t *testing.T) {
		provider, err := postgresql.NewProvider("BadConnectionString")
		require.EqualError(t, err, "failed to connect to PostgreSQL instance: cannot parse "+
			"`BadConnectionString`: failed to parse as DSN (invalid dsn)")
		require.Nil(t, provider)
	})
}

func runCommonTests(t *testing.T, provider *postgresql.Provider) {
	t.Helper()

	testProviderOpenStore(t, provider)
	testProviderSetStoreConfig(t, provider)
	testStorePutGet(t, provider)
	testStoreQuery(t, provider)
	testStoreFlush(t, provider)
	testStoreClose(t, provider)
	testProviderPing(t, provider)
	testProviderAndStoreNotImplemented(t, provider)
	commontest.TestProviderClose(t, provider)
}

func testProviderOpenStore(t *testing.T, provider spi.Provider) {
	t.Helper()

	t.Run("Success", func(t *testing.T) {
		testStoreName := randomStoreName()

		store, err := provider.OpenStore(testStoreName)
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Attempt to open a store with a blank name", func(t *testing.T) {
		store, err := provider.OpenStore("")
		require.EqualError(t, err, "store name cannot be empty")
		require.Nil(t, store)
	})
	t.Run("Demonstrate that store names are not case-sensitive", func(t *testing.T) {
		// Per the interface, store names are not supposed to be case-sensitive in order to ensure consistency across
		// storage implementations - some of which don't support case sensitivity in their database names.

		storeWithCapitalLetter, err := provider.OpenStore("Some_store_name")
		require.NoError(t, err)

		type exampleStruct struct {
			SomeString  string  `json:"some_string,omitempty"`
			SomeInt     int     `json:"some_int,omitempty"`
			SomeFloat64 float64 `json:"some_float64,omitempty"`
		}

		dataToStore := exampleStruct{
			SomeString:  "Hello",
			SomeInt:     6,
			SomeFloat64: 1.341569,
		}

		dataToStoreBytes, err := json.Marshal(dataToStore)
		require.NoError(t, err)

		err = storeWithCapitalLetter.Put("key", dataToStoreBytes)
		require.NoError(t, err)

		// If the store names are properly case-insensitive, then it's expected that the store below
		// contains the same data as the one above.
		storeWithLowercaseLetter, err := provider.OpenStore("some_store_name")
		require.NoError(t, err)

		valueBytes, err := storeWithLowercaseLetter.Get("key")
		require.NoError(t, err)

		var value exampleStruct

		err = json.Unmarshal(valueBytes, &value)
		require.NoError(t, err)

		require.True(t, reflect.DeepEqual(dataToStore, value), "stored data differs from retrieved data")
	})
	t.Run("Failed to create database", func(t *testing.T) {
		store, err := provider.OpenStore(`"`)
		require.Contains(t, err.Error(), "failed to create database: ERROR: "+
			"unterminated quoted identifier at or near")
		require.Contains(t, err.Error(), "(SQLSTATE 42601)")
		require.Nil(t, store)
	})
}

func testProviderSetStoreConfig(t *testing.T, provider spi.Provider) {
	t.Helper()

	t.Run("Set store config with all new tags", func(t *testing.T) {
		testStoreName := randomStoreName()

		store, err := provider.OpenStore(testStoreName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		config := spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3"}}

		err = provider.SetStoreConfig(testStoreName, config)
		require.NoError(t, err)
	})
	t.Run("Attempt to set config without opening store first", func(t *testing.T) {
		err := provider.SetStoreConfig("NonExistentStore", spi.StoreConfiguration{})
		require.True(t, errors.Is(err, spi.ErrStoreNotFound), "Got unexpected error or no error")
	})
	t.Run("Invalid tag names", func(t *testing.T) {
		testStoreName := randomStoreName()

		store, err := provider.OpenStore(testStoreName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		config := spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagNameWith:Character"}}

		err = provider.SetStoreConfig(testStoreName, config)
		require.EqualError(t, err, `"tagNameWith:Character" is an invalid tag name since it contains `+
			`one or more of the following substrings: ":", "<=", "<", ">=", ">"`)

		config = spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagNameWith<Character"}}

		err = provider.SetStoreConfig(testStoreName, config)
		require.EqualError(t, err, `"tagNameWith<Character" is an invalid tag name since it contains `+
			`one or more of the following substrings: ":", "<=", "<", ">=", ">"`)

		config = spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagNameWith>Character"}}

		err = provider.SetStoreConfig(testStoreName, config)
		require.EqualError(t, err, `"tagNameWith>Character" is an invalid tag name since it contains `+
			`one or more of the following substrings: ":", "<=", "<", ">=", ">"`)
	})
}

type testStruct struct {
	String string `json:"string"`

	Test1Bool bool `json:"test1Bool"`
	Test2Bool bool `json:"test2Bool"`

	BigNegativeInt32   int32 `json:"bigNegativeInt32"`
	SmallNegativeInt32 int32 `json:"smallNegativeInt32"`
	ZeroInt32          int32 `json:"zeroInt32"`
	SmallPositiveInt32 int32 `json:"smallPositiveInt32"`
	BigPositiveInt32   int32 `json:"bigPositiveInt32"`

	BigNegativeInt64   int64 `json:"bigNegativeInt64"`
	SmallNegativeInt64 int64 `json:"smallNegativeInt64"`
	ZeroInt64          int64 `json:"zeroInt64"`
	SmallPositiveInt64 int64 `json:"smallPositiveInt64"`
	BigPositiveInt64   int64 `json:"bigPositiveInt64"`

	Test1Float32 float32 `json:"test1Float32"`
	Test2Float32 float32 `json:"test2Float32"`
	Test3Float32 float32 `json:"test3Float32"`
	Test4Float32 float32 `json:"test4Float32"`
	Test5Float32 float32 `json:"test5Float32"`
	ZeroFloat32  float32 `json:"zeroFloat32"`

	Test1Float64 float64 `json:"test1Float64"`
	Test2Float64 float64 `json:"test2Float64"`
	Test3Float64 float64 `json:"test3Float64"`
	Test4Float64 float64 `json:"test4Float64"`
	Test5Float64 float32 `json:"test5Float64"`
	ZeroFloat64  float64 `json:"zeroFloat64"`
}

func testStorePutGet(t *testing.T, provider spi.Provider) {
	t.Helper()

	testKeyNonURL := "TestKey"
	testKeyURL := "https://example.com"

	testValueSimpleString := "TestValue"
	testValueSimpleString2 := "TestValue2"
	testBinaryData := []byte{0x5f, 0xcb, 0x5c, 0xe9, 0x7f, 0xe3, 0x81}
	testBinaryData2 := []byte{0x5f, 0xcb, 0x5c, 0xe9, 0x7f}
	testValueJSONString := `"TestValue"`

	t.Run("Put and get a value", func(t *testing.T) {
		t.Run("Key is not a URL", func(t *testing.T) {
			t.Run("Value is simple text", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyNonURL, []byte(testValueSimpleString))
			})
			t.Run("Value is JSON-formatted object", func(t *testing.T) {
				doPutThenGetTestWithJSONFormattedObject(t, provider, testKeyNonURL)
			})
			t.Run("Value is JSON-formatted string", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyNonURL, []byte(testValueJSONString))
			})
			t.Run("Value is binary data", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyNonURL, testBinaryData)
			})
		})
		t.Run("Key is a URL", func(t *testing.T) {
			t.Run("Value is simple text", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyURL, []byte(testValueSimpleString))
			})
			t.Run("Value is JSON-formatted object", func(t *testing.T) {
				doPutThenGetTestWithJSONFormattedObject(t, provider, testKeyURL)
			})
			t.Run("Value is JSON-formatted string", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyURL, []byte(testValueJSONString))
			})
			t.Run("Value is binary data", func(t *testing.T) {
				doPutThenGetTest(t, provider, testKeyURL, testBinaryData)
			})
		})
	})
	t.Run("Put a value, update it, and get the updated value", func(t *testing.T) {
		t.Run("Key is not a URL", func(t *testing.T) {
			t.Run("Value is simple text", func(t *testing.T) {
				doPutThenUpdateThenGetTest(t, provider, testKeyNonURL,
					[]byte(testValueSimpleString), []byte(testValueSimpleString2))
			})
			t.Run("Value is JSON-formatted object", func(t *testing.T) {
				doPutThenUpdateThenGetTestWithJSONFormattedObject(t, provider, testKeyNonURL)
			})
			t.Run("Value is binary data", func(t *testing.T) {
				doPutThenUpdateThenGetTest(t, provider, testKeyNonURL, testBinaryData, testBinaryData2)
			})
		})
		t.Run("Key is a URL", func(t *testing.T) {
			t.Run("Value is simple text", func(t *testing.T) {
				doPutThenUpdateThenGetTest(t, provider, testKeyURL, []byte(testValueSimpleString),
					[]byte(testValueSimpleString2))
			})
			t.Run("Value is JSON-formatted object", func(t *testing.T) {
				doPutThenUpdateThenGetTestWithJSONFormattedObject(t, provider, testKeyURL)
			})
			t.Run("Value is binary data", func(t *testing.T) {
				doPutThenUpdateThenGetTest(t, provider, testKeyURL, testBinaryData, testBinaryData2)
			})
		})
	})
	t.Run("Put a value, then delete it, then put again using the same key", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		storedTestData := storeTestJSONData(t, store, testKeyNonURL)

		err = store.Delete(testKeyNonURL)
		require.NoError(t, err)

		modifiedTestData := storedTestData
		modifiedTestData.String = "Some updated string here"

		modifiedTestDataBytes, err := json.Marshal(modifiedTestData)
		require.NoError(t, err)

		err = store.Put(testKeyNonURL, modifiedTestDataBytes)
		require.NoError(t, err)

		value, err := store.Get(testKeyNonURL)
		require.NoError(t, err)

		checkIfTestStructsMatch(t, value, &modifiedTestData)
	})
	t.Run("Tests demonstrating proper store namespacing", func(t *testing.T) {
		t.Run("Put key + value in one store, "+
			"then check that it can't be found in a second store with a different name", func(t *testing.T) {
			store1, err := provider.OpenStore(randomStoreName())
			require.NoError(t, err)

			defer func() {
				require.NoError(t, store1.Close())
			}()

			storeTestJSONData(t, store1, testKeyNonURL)

			store2, err := provider.OpenStore(randomStoreName())
			require.NoError(t, err)

			defer func() {
				require.NoError(t, store2.Close())
			}()

			// Store 2 should be disjoint from store 1. It should not contain the key + value pair from store 1.
			value, err := store2.Get(testKeyNonURL)
			require.True(t, errors.Is(err, spi.ErrDataNotFound), "Got unexpected error or no error")
			require.Nil(t, value)
		})
		t.Run("Put same key + value in two stores with different names, then update value in one store, "+
			"then check that the other store was not changed",
			func(t *testing.T) {
				store1, err := provider.OpenStore(randomStoreName())
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store1.Close())
				}()

				storeTestJSONData(t, store1, testKeyNonURL)

				store2, err := provider.OpenStore(randomStoreName())
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store2.Close())
				}()

				storedData := storeTestJSONData(t, store2, testKeyNonURL)

				// Now both store 1 and 2 contain the same key + value pair.

				modifiedStoredData := storedData

				modifiedStoredData.String = "Some new string here"

				modifiedStoredDataBytes, err := json.Marshal(modifiedStoredData)
				require.NoError(t, err)

				// Now update the value in only store 1.
				err = store1.Put(testKeyNonURL, modifiedStoredDataBytes)
				require.NoError(t, err)

				// Store 1 should have the new value.
				value, err := store1.Get(testKeyNonURL)
				require.NoError(t, err)
				checkIfTestStructsMatch(t, value, &modifiedStoredData)

				// Store 2 should still have the old value.
				value, err = store2.Get(testKeyNonURL)
				require.NoError(t, err)
				checkIfTestStructsMatch(t, value, &storedData)
			})
		t.Run("Put same key + value in two stores with the same name (so they should point to the same "+
			"underlying databases), then update value in one store, then check that the other store also reflects this",
			func(t *testing.T) {
				storeName := randomStoreName()

				store1, err := provider.OpenStore(storeName)
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store1.Close())
				}()

				storeTestJSONData(t, store1, testKeyNonURL)

				// Store 2 should contain the same data as store 1 since they were opened with the same name.
				store2, err := provider.OpenStore(storeName)
				require.NoError(t, err)

				defer func() {
					require.NoError(t, store2.Close())
				}()

				// Store 2 should find the same data that was put in store 1

				valueFromStore1, err := store1.Get(testKeyNonURL)
				require.NoError(t, err)

				valueFromStore2, err := store2.Get(testKeyNonURL)
				require.NoError(t, err)

				var retrievedTestData1 testStruct

				err = json.Unmarshal(valueFromStore1, &retrievedTestData1)
				require.NoError(t, err)

				checkIfTestStructsMatch(t, valueFromStore2, &retrievedTestData1)
			})
	})
	t.Run("Get using empty key", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		_, err = store.Get("")
		require.EqualError(t, err, "key cannot be empty")
	})
	t.Run("Put with empty key", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put("", []byte(`{"name":"value"}`))
		require.EqualError(t, err, "key cannot be empty")
	})
	t.Run("Put with vil value", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put(testKeyNonURL, nil)
		require.EqualError(t, err, "value cannot be nil")
	})
	t.Run("Put with invalid tag", func(t *testing.T) {
		store, err := provider.OpenStore(randomStoreName())
		require.NoError(t, err)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = store.Put("key", []byte("value"), spi.Tag{Name: ":"})
		require.EqualError(t, err, `":" is an invalid tag name since it contains one or more of the`+
			` following substrings: ":", "<=", "<", ">=", ">"`)

		err = store.Put("key", []byte("value"), spi.Tag{Value: ":"})
		require.EqualError(t, err, `":" is an invalid tag value since it contains one or more of the`+
			` following substrings: ":", "<=", "<", ">=", ">"`)

		err = store.Put("key", []byte("value"), spi.Tag{Name: "<"})
		require.EqualError(t, err, `"<" is an invalid tag name since it contains one or more of the`+
			` following substrings: ":", "<=", "<", ">=", ">"`)

		err = store.Put("key", []byte("value"), spi.Tag{Value: "<"})
		require.EqualError(t, err, `"<" is an invalid tag value since it contains one or more of the`+
			` following substrings: ":", "<=", "<", ">=", ">"`)

		err = store.Put("key", []byte("value"), spi.Tag{Name: ">"})
		require.EqualError(t, err, `">" is an invalid tag name since it contains one or more of the`+
			` following substrings: ":", "<=", "<", ">=", ">"`)

		err = store.Put("key", []byte("value"), spi.Tag{Value: ">"})
		require.EqualError(t, err, `">" is an invalid tag value since it contains one or more of the`+
			` following substrings: ":", "<=", "<", ">=", ">"`)
	})
}

func testStoreQuery(t *testing.T, provider spi.Provider) {
	t.Helper()

	t.Run("Tag name only query - 2 values found", func(t *testing.T) {
		keysToPut := []string{"key1", "key2", "key3"}
		valuesToPut := [][]byte{[]byte("value1"), []byte("value2"), []byte(`3`)}
		tagsToPut := [][]spi.Tag{
			{{Name: "tagName1", Value: "tagValue1"}, {Name: "tagName2", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue"}, {Name: "tagName4"}},
			{{Name: "tagName3", Value: "tagValue2"}},
		}

		expectedKeys := []string{keysToPut[1], keysToPut[2]}
		expectedValues := [][]byte{valuesToPut[1], valuesToPut[2]}

		queryExpression := "tagName3"

		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4"}})
		require.NoError(t, err)

		putData(t, store, keysToPut, valuesToPut, tagsToPut)

		iterator, err := store.Query(queryExpression)
		require.NoError(t, err)

		verifyExpectedIterator(t, iterator, expectedKeys, expectedValues)
	})
	t.Run("Tag name only query - 0 values found", func(t *testing.T) {
		keysToPut := []string{"key1", "key2", "key3"}
		valuesToPut := [][]byte{[]byte("value1"), []byte("value2"), []byte("value3")}
		tagsToPut := [][]spi.Tag{
			{{Name: "tagName1", Value: "tagValue1"}, {Name: "tagName2", Value: "tagValue2"}},
			{{Name: "tagName3", Value: "tagValue"}, {Name: "tagName4"}},
			{{Name: "tagName3", Value: "tagValue2"}},
		}

		queryExpression := "tagName5"

		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		err = provider.SetStoreConfig(storeName,
			spi.StoreConfiguration{TagNames: []string{"tagName1", "tagName2", "tagName3", "tagName4", "tagName5"}})
		require.NoError(t, err)

		putData(t, store, keysToPut, valuesToPut, tagsToPut)

		iterator, err := store.Query(queryExpression)
		require.NoError(t, err)

		verifyExpectedIterator(t, iterator, nil, nil)
	})
	t.Run("Invalid expression formats", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		t.Run("Empty expression", func(t *testing.T) {
			iterator, err := store.Query("")
			require.EqualError(t, err, "expression cannot be empty")
			require.Empty(t, iterator)
		})
		t.Run("Tag name + value query, which isn't supported currently", func(t *testing.T) {
			iterator, err := store.Query("name:value:somethingElse")
			require.EqualError(t, err, "tag name + value queries not implemented")
			require.Empty(t, iterator)
		})
	})
	t.Run("Unsupported query options", func(t *testing.T) {
		storeName := randomStoreName()

		store, err := provider.OpenStore(storeName)
		require.NoError(t, err)
		require.NotNil(t, store)

		defer func() {
			require.NoError(t, store.Close())
		}()

		iterator, err := store.Query("expression", spi.WithInitialPageNum(1))
		require.EqualError(t, err, "setting initial page number not implemented")
		require.Nil(t, iterator)

		iterator, err = store.Query("expression", spi.WithSortOrder(&spi.SortOptions{}))
		require.EqualError(t, err, "custom sort options not implemented")
		require.Nil(t, iterator)
	})
}

func testStoreFlush(t *testing.T, provider spi.Provider) {
	t.Helper()

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	err = store.Flush()
	require.NoError(t, err)
}

func testStoreClose(t *testing.T, provider spi.Provider) {
	t.Helper()

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	err = store.Close()
	require.NoError(t, err)
}

func testProviderPing(t *testing.T, provider *postgresql.Provider) {
	t.Helper()

	err := provider.Ping()
	require.NoError(t, err)
}

func doPutThenUpdateThenGetTestWithJSONFormattedObject(t *testing.T, provider spi.Provider, key string) {
	t.Helper()

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	storedTestData := storeTestJSONData(t, store, key)

	storedTestData.String = "Some new string here"
	storedTestData.Test1Bool = true
	storedTestData.BigNegativeInt32 = -12345
	storedTestData.BigPositiveInt64 = 90000004
	storedTestData.Test3Float32 = 7.42
	storedTestData.Test3Float64 = -72.4208

	testDataBytes, err := json.Marshal(storedTestData)
	require.NoError(t, err)

	err = store.Put(key, testDataBytes)
	require.NoError(t, err)

	retrievedValue, err := store.Get(key)
	require.NoError(t, err)

	checkIfTestStructsMatch(t, retrievedValue, &storedTestData)
}

func doPutThenGetTestWithJSONFormattedObject(t *testing.T, provider spi.Provider, key string) {
	t.Helper()

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	storedTestData := storeTestJSONData(t, store, key)

	retrievedValue, err := store.Get(key)
	require.NoError(t, err)

	checkIfTestStructsMatch(t, retrievedValue, &storedTestData)
}

func doPutThenGetTest(t *testing.T, provider spi.Provider, key string, value []byte) {
	t.Helper()

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	err = store.Put(key, value)
	require.NoError(t, err)

	retrievedValue, err := store.Get(key)
	require.NoError(t, err)
	require.Equal(t, value, retrievedValue)
}

func putData(t *testing.T, store spi.Store, keys []string, values [][]byte, tags [][]spi.Tag) {
	t.Helper()

	for i := 0; i < len(keys); i++ {
		err := store.Put(keys[i], values[i], tags[i]...)
		require.NoError(t, err)
	}
}

func doPutThenUpdateThenGetTest(t *testing.T, provider spi.Provider, key string, value, updatedValue []byte) {
	t.Helper()

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	err = store.Put(key, value)
	require.NoError(t, err)

	err = store.Put(key, updatedValue)
	require.NoError(t, err)

	retrievedValue, err := store.Get(key)
	require.NoError(t, err)
	require.Equal(t, updatedValue, retrievedValue)
}

func storeTestJSONData(t *testing.T, store spi.Store, key string) testStruct {
	t.Helper()

	testData := testStruct{
		String: "Some string here",

		Test1Bool: false,
		Test2Bool: true,

		BigNegativeInt32:   -2147483648,
		SmallNegativeInt32: -3,
		ZeroInt32:          0,
		SmallPositiveInt32: 3,
		BigPositiveInt32:   2147483647,

		BigNegativeInt64:   -9223372036854775808,
		SmallNegativeInt64: -3,
		ZeroInt64:          0,
		SmallPositiveInt64: 3,
		BigPositiveInt64:   9223372036854775807,

		Test1Float32: 1.3,
		Test2Float32: 16,
		Test3Float32: 1.5869797,
		Test4Float32: 239.902,
		Test5Float32: -239.902,
		ZeroFloat32:  0.00,

		Test1Float64: 0.12345678912345678,
		Test2Float64: -478.875321,
		Test3Float64: 123456789,
		Test4Float64: 1.00000004,
		Test5Float64: -239.902,
		ZeroFloat64:  0.0000,
	}

	testDataBytes, err := json.Marshal(testData)
	require.NoError(t, err)

	err = store.Put(key, testDataBytes)
	require.NoError(t, err)

	return testData
}

func checkIfTestStructsMatch(t *testing.T, retrievedValue []byte, storedTestData *testStruct) {
	t.Helper()

	var retrievedTestData testStruct

	err := json.Unmarshal(retrievedValue, &retrievedTestData)
	require.NoError(t, err)

	require.Equal(t, storedTestData.String, retrievedTestData.String)

	require.Equal(t, storedTestData.Test1Bool, retrievedTestData.Test1Bool)
	require.Equal(t, storedTestData.Test2Bool, retrievedTestData.Test2Bool)

	require.Equal(t, storedTestData.BigNegativeInt32, retrievedTestData.BigNegativeInt32)
	require.Equal(t, storedTestData.SmallNegativeInt32, retrievedTestData.SmallNegativeInt32)
	require.Equal(t, storedTestData.ZeroInt32, retrievedTestData.ZeroInt32)
	require.Equal(t, storedTestData.SmallPositiveInt32, retrievedTestData.SmallPositiveInt32)
	require.Equal(t, storedTestData.BigPositiveInt32, retrievedTestData.BigPositiveInt32)

	require.Equal(t, storedTestData.BigNegativeInt64, retrievedTestData.BigNegativeInt64)
	require.Equal(t, storedTestData.SmallNegativeInt64, retrievedTestData.SmallNegativeInt64)
	require.Equal(t, storedTestData.ZeroInt64, retrievedTestData.ZeroInt64)
	require.Equal(t, storedTestData.SmallPositiveInt64, retrievedTestData.SmallPositiveInt64)
	require.Equal(t, storedTestData.BigPositiveInt64, retrievedTestData.BigPositiveInt64)

	require.Equal(t, storedTestData.Test1Float32, retrievedTestData.Test1Float32)
	require.Equal(t, storedTestData.Test2Float32, retrievedTestData.Test2Float32)
	require.Equal(t, storedTestData.Test3Float32, retrievedTestData.Test3Float32)
	require.Equal(t, storedTestData.Test4Float32, retrievedTestData.Test4Float32)
	require.Equal(t, storedTestData.ZeroFloat32, retrievedTestData.ZeroFloat32)

	require.Equal(t, storedTestData.Test1Float64, retrievedTestData.Test1Float64)
	require.Equal(t, storedTestData.Test2Float64, retrievedTestData.Test2Float64)
	require.Equal(t, storedTestData.Test3Float64, retrievedTestData.Test3Float64)
	require.Equal(t, storedTestData.Test4Float64, retrievedTestData.Test4Float64)
	require.Equal(t, storedTestData.ZeroFloat64, retrievedTestData.ZeroFloat64)
}

func testProviderAndStoreNotImplemented(t *testing.T, provider spi.Provider) {
	t.Helper()

	_, err := provider.GetStoreConfig("storename")
	require.EqualError(t, err, "not implemented")

	require.Panics(t, func() {
		provider.GetOpenStores()
	})

	store, err := provider.OpenStore(randomStoreName())
	require.NoError(t, err)

	tags, err := store.GetTags("key")
	require.EqualError(t, err, "not implemented")
	require.Nil(t, tags)

	values, err := store.GetBulk()
	require.EqualError(t, err, "not implemented")
	require.Nil(t, values)

	err = store.Batch(nil)
	require.EqualError(t, err, "not implemented")
}

func verifyExpectedIterator(t *testing.T, actualResultsItr spi.Iterator, // nolint:gocyclo // Test file
	expectedKeys []string, expectedValues [][]byte) {
	t.Helper()

	if len(expectedValues) != len(expectedKeys) {
		require.FailNow(t,
			"Invalid test case. Expected keys and values slices must be the same length.")
	}

	var dataChecklist struct {
		keys     []string
		values   [][]byte
		received []bool
	}

	dataChecklist.keys = expectedKeys
	dataChecklist.values = expectedValues
	dataChecklist.received = make([]bool, len(expectedKeys))

	moreResultsToCheck, err := actualResultsItr.Next()
	require.NoError(t, err)

	if !moreResultsToCheck && len(expectedKeys) != 0 {
		require.FailNow(t, "query unexpectedly returned no results")
	}

	for moreResultsToCheck {
		dataReceivedCount := 0

		for _, received := range dataChecklist.received {
			if received {
				dataReceivedCount++
			}
		}

		if dataReceivedCount == len(dataChecklist.received) {
			require.FailNow(t, "iterator contains more results than expected")
		}

		var itrErr error
		receivedKey, itrErr := actualResultsItr.Key()
		require.NoError(t, itrErr)

		receivedValue, itrErr := actualResultsItr.Value()
		require.NoError(t, itrErr)

		for i := 0; i < len(dataChecklist.keys); i++ {
			if receivedKey == dataChecklist.keys[i] {
				if string(receivedValue) == string(dataChecklist.values[i]) {
					dataChecklist.received[i] = true

					break
				}
			}
		}

		moreResultsToCheck, err = actualResultsItr.Next()
		require.NoError(t, err)
	}

	err = actualResultsItr.Close()
	require.NoError(t, err)

	tags, err := actualResultsItr.Tags()
	require.EqualError(t, err, "not implemented")
	require.Nil(t, tags)

	totalitems, err := actualResultsItr.TotalItems()
	require.EqualError(t, err, "not implemented")
	require.Equal(t, -1, totalitems)

	for _, received := range dataChecklist.received {
		if !received {
			require.FailNow(t, "received unexpected query results")
		}
	}
}

func ensurePostgreSQLIsUp() error {
	return backoff.Retry(func() error {
		ctxWithTimeout, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		_, err := pgx.Connect(ctxWithTimeout, postgreSQLConnectionString)

		return err
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 10))
}

func randomStoreName() string {
	return "store_" + strings.ReplaceAll(uuid.New().String(), "-", "_")
}

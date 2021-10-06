/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodb_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	commontest "github.com/hyperledger/aries-framework-go/test/component/storage"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
)

const (
	mongoDBConnString    = "mongodb://localhost:27017"
	dockerMongoDBImage   = "mongo"
	dockerMongoDBTagV400 = "4.0.0"
	dockerMongoDBTagV428 = "4.2.8"
	dockerMongoDBTagV500 = "5.0.0"
)

// This should function the same as the default logger in the mongodb package.
// This is here just to increase code coverage by allowing us to exercise the WithLogger option.
type testLogger struct {
	logger *log.Logger
}

func (d *testLogger) Infof(msg string, args ...interface{}) {
	d.logger.Printf(msg, args...)
}

func TestMongoDB_V4_0_0(t *testing.T) {
	startContainerAndDoAllTests(t, dockerMongoDBTagV400)
}

func TestMongoDB_V4_2_8(t *testing.T) {
	startContainerAndDoAllTests(t, dockerMongoDBTagV428)
}

func TestMongoDB_V5_0_0(t *testing.T) {
	startContainerAndDoAllTests(t, dockerMongoDBTagV500)
}

func TestProvider_New_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("BadConnString")
	require.EqualError(t, err, `failed to create a new MongoDB client: error parsing uri: `+
		`scheme must be "mongodb" or "mongodb+srv"`)
	require.Nil(t, provider)
}

func TestProvider_SetStoreConfig_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	_, err = provider.OpenStore("StoreName")
	require.NoError(t, err)

	err = provider.SetStoreConfig("StoreName", storage.StoreConfiguration{TagNames: []string{"tagName1"}})
	require.EqualError(t, err, "failed to set indexes: failed to get existing indexed tag names: "+
		"failed to get list of indexes from MongoDB: server selection error: context deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }") //nolint:lll
}

func TestProvider_GetStoreConfig_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	_, err = provider.OpenStore("TestStoreName")
	require.NoError(t, err)

	config, err := provider.GetStoreConfig("TestStoreName")
	require.EqualError(t, err, "failed to determine if the underlying database exists for teststorename: "+
		"server selection error: context deadline exceeded, current topology: { Type: Unknown, "+
		"Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
	require.Empty(t, config)
}

func TestStore_Put_Failure(t *testing.T) {
	t.Run("Deadline exceeded (server not reachable)", func(t *testing.T) {
		provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
		require.NoError(t, err)

		store, err := provider.OpenStore("StoreName")
		require.NoError(t, err)

		err = store.Put("key", []byte("value"))
		require.EqualError(t, err, "failed to run UpdateOne command in MongoDB: server selection error: context "+
			"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
	})
	t.Run("Invalid tags", func(t *testing.T) {
		// We only test for < and > here since the : case is handled in the common unit tests (commontest.TestAll)
		t.Run("Tag name contains <", func(t *testing.T) {
			provider, err := mongodb.NewProvider("mongodb://test")
			require.NoError(t, err)

			store, err := provider.OpenStore("StoreName")
			require.NoError(t, err)

			err = store.Put("key", []byte("value"), storage.Tag{Name: "<"})
			require.EqualError(t, err, `"<" is an invalid tag name since it contains one or more of the`+
				` following substrings: ":", "<=", "<", ">=", ">"`)
		})
		t.Run("Tag value contains <", func(t *testing.T) {
			provider, err := mongodb.NewProvider("mongodb://test")
			require.NoError(t, err)

			store, err := provider.OpenStore("StoreName")
			require.NoError(t, err)

			err = store.Put("key", []byte("value"), storage.Tag{Value: "<"})
			require.EqualError(t, err, `"<" is an invalid tag value since it contains one or more of the`+
				` following substrings: ":", "<=", "<", ">=", ">"`)
		})
		t.Run("Tag name contains >", func(t *testing.T) {
			provider, err := mongodb.NewProvider("mongodb://test")
			require.NoError(t, err)

			store, err := provider.OpenStore("StoreName")
			require.NoError(t, err)

			err = store.Put("key", []byte("value"), storage.Tag{Name: ">"})
			require.EqualError(t, err, `">" is an invalid tag name since it contains one or more of the`+
				` following substrings: ":", "<=", "<", ">=", ">"`)
		})
		t.Run("Tag value contains >", func(t *testing.T) {
			provider, err := mongodb.NewProvider("mongodb://test")
			require.NoError(t, err)

			store, err := provider.OpenStore("StoreName")
			require.NoError(t, err)

			err = store.Put("key", []byte("value"), storage.Tag{Value: ">"})
			require.EqualError(t, err, `">" is an invalid tag value since it contains one or more of the`+
				` following substrings: ":", "<=", "<", ">=", ">"`)
		})
	})
}

func TestStore_Get_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	value, err := store.Get("key")
	require.EqualError(t, err, "failed to run FindOne command in MongoDB: server selection error: context "+
		"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
	require.Nil(t, value)
}

func TestStore_GetTags_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	tags, err := store.GetTags("key")
	require.EqualError(t, err, "failed to run FindOne command in MongoDB: server selection error: "+
		"context deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, "+
		"Type: Unknown }, ] }")
	require.Nil(t, tags)
}

func TestStore_GetBulk_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	values, err := store.GetBulk("key1", "key2")
	require.EqualError(t, err, "failed to run Find command in MongoDB: server selection error: context "+
		"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
	require.Nil(t, values)
}

func TestStore_Delete_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	err = store.Delete("key1")
	require.EqualError(t, err, "failed to run DeleteOne command in MongoDB: server selection error: context "+
		"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
}

func TestStore_Batch_Failure(t *testing.T) {
	provider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))
	require.NoError(t, err)

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	err = store.Batch([]storage.Operation{{Key: "key"}})
	require.EqualError(t, err, "failed to run BulkWrite command in MongoDB: server selection error: context "+
		"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
}

func startContainerAndDoAllTests(t *testing.T, dockerMongoDBTag string) {
	t.Helper()

	pool, mongoDBResource := startMongoDBContainer(t, dockerMongoDBTag)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	doAllTests(t, mongoDBConnString)
}

func doAllTests(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString, mongodb.WithDBPrefix("dbPrefixTest_"),
		mongodb.WithLogger(&testLogger{
			logger: log.New(os.Stdout, "MongoDB-Provider ", log.Ldate|log.Ltime|log.LUTC),
		}))
	require.NoError(t, err)

	commontest.TestAll(t, provider)
	testGetStoreConfigUnderlyingDatabaseCheck(t, connString)
	testMultipleProvidersSettingSameStoreConfigurationAtTheSameTime(t, connString)
	testMultipleProvidersStoringSameDataAtTheSameTime(t, connString)
	testMultipleProvidersStoringSameBulkDataAtTheSameTime(t, connString)
	testCloseProviderTwice(t, connString)
	testQueryWithMultipleTags(t, connString)
	testQueryWithLessThanGreaterThanOperators(t, connString)
}

func testGetStoreConfigUnderlyingDatabaseCheck(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, provider.Close())
	}()

	storeName := randomStoreName()

	// The MongoDB database shouldn't exist yet.
	config, err := provider.GetStoreConfig(storeName)
	require.Equal(t, true, errors.Is(storage.ErrStoreNotFound, err),
		"unexpected error or no error")
	require.Empty(t, config)

	_, err = provider.OpenStore(storeName)
	require.NoError(t, err)

	// MongoDB defers creating the database until data is put in it or indexes are created.
	// The call above to OpenStore shouldn't have created the database yet.
	config, err = provider.GetStoreConfig(storeName)
	require.Equal(t, true, errors.Is(storage.ErrStoreNotFound, err),
		"unexpected error or no error")
	require.Empty(t, config)

	// This will create the database.
	err = provider.SetStoreConfig(storeName, storage.StoreConfiguration{TagNames: []string{"TagName1"}})
	require.NoError(t, err)

	// Now the underlying database should be found.
	config, err = provider.GetStoreConfig(storeName)
	require.NoError(t, err)
	require.Equal(t, "TagName1", config.TagNames[0])

	err = provider.Close()
	require.NoError(t, err)

	// Create a new Provider object.
	provider2, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, provider2.Close())
	}()

	// This method tells you how many store objects are open in this Provider.
	// Since it's a new Provider, there shouldn't be any.
	openStores := provider2.GetOpenStores()
	require.Len(t, openStores, 0)

	// This will succeed since GetStoreConfig checks the underlying databases instead of the
	// in-memory store objects.
	config, err = provider2.GetStoreConfig(storeName)
	require.NoError(t, err)
	require.Equal(t, "TagName1", config.TagNames[0])

	// The call above should not have created a new store object.
	openStores = provider2.GetOpenStores()
	require.Len(t, openStores, 0)

	// As mentioned above, MongoDB defers creating databases until there is data put in or indexes are set.
	// The code above triggered database creationg by creating indexes. Below we will do the same type of test, but this
	// time we create the database by storing data.
	storeName2 := randomStoreName()

	store, err := provider2.OpenStore(storeName2)
	require.NoError(t, err)

	// Underlying database shouldn't exist yet.
	config, err = provider2.GetStoreConfig(storeName2)
	require.Equal(t, true, errors.Is(storage.ErrStoreNotFound, err),
		"unexpected error or no error")
	require.Empty(t, config)

	err = store.Put("key", []byte("value"))
	require.NoError(t, err)

	// Now the underlying database should be found.
	// The config will be empty since it was never set
	config, err = provider2.GetStoreConfig(storeName2)
	require.NoError(t, err)
	require.Empty(t, config.TagNames)
}

func testMultipleProvidersSettingSameStoreConfigurationAtTheSameTime(t *testing.T, connString string) {
	t.Helper()

	const numberOfProviders = 100

	storeName := randomStoreName()

	providers := make([]*mongodb.Provider, numberOfProviders)

	openStores := make([]storage.Store, numberOfProviders)

	for i := 0; i < numberOfProviders; i++ {
		provider, err := mongodb.NewProvider(connString, mongodb.WithTimeout(time.Second*5),
			mongodb.WithMaxRetries(10),
			mongodb.WithTimeBetweenRetries(time.Second))
		require.NoError(t, err)

		// If you see a warning in your IDE about having a defer statement in a loop, it can be ignored in this case.
		// The goal is to close all the stores as soon as there's a failure anywhere in this test in order to free
		// up resources for other tests, which may still pass. We don't want them to close at the end of this loop,
		// so there's no issue having this here.
		defer func() {
			require.NoError(t, provider.Close())
		}()

		providers[i] = provider

		openStore, err := providers[i].OpenStore(storeName)
		require.NoError(t, err)

		openStores[i] = openStore
	}

	var waitGroup sync.WaitGroup

	for i := 0; i < numberOfProviders; i++ {
		i := i

		waitGroup.Add(1)

		setStoreConfig := func() {
			defer waitGroup.Done()

			errSetStoreConfig := providers[i].SetStoreConfig(storeName,
				storage.StoreConfiguration{TagNames: []string{
					"TagName1", "TagName2", "TagName3", "TagName4",
					"TagName5", "TagName6", "TagName7", "TagName8",
					"TagName9", "TagName10", "TagName11", "TagName12",
					"TagName13", "TagName14", "TagName15", "TagName16",
					"TagName17", "TagName18", "TagName19", "TagName20",
					"TagName21", "TagName22", "TagName23", "TagName24",
					"TagName25", "TagName26", "TagName27", "TagName28",
					"TagName29", "TagName30", "TagName31", "TagName32",
				}})
			require.NoError(t, errSetStoreConfig)

			// Close the store as soon as possible in order to free up resources for other threads.
			require.NoError(t, openStores[i].Close())
		}
		go setStoreConfig()
	}

	waitGroup.Wait()

	storeConfig, err := providers[0].GetStoreConfig(storeName)
	require.NoError(t, err)

	require.Len(t, storeConfig.TagNames, 32)

	for i := 0; i < len(storeConfig.TagNames); i++ {
		require.Equal(t, fmt.Sprintf("TagName%d", i+1), storeConfig.TagNames[i])
	}
}

func testMultipleProvidersStoringSameDataAtTheSameTime(t *testing.T, connString string) {
	t.Helper()

	const numberOfProviders = 100

	storeName := randomStoreName()

	providers := make([]*mongodb.Provider, numberOfProviders)

	openStores := make([]storage.Store, numberOfProviders)

	for i := 0; i < numberOfProviders; i++ {
		provider, err := mongodb.NewProvider(connString, mongodb.WithTimeout(time.Second*5),
			mongodb.WithMaxRetries(10),
			mongodb.WithTimeBetweenRetries(time.Second))
		require.NoError(t, err)

		// If you see a warning in your IDE about having a defer statement in a loop, it can be ignored in this case.
		// The goal is to close all the stores as soon as there's a failure anywhere in this test in order to free
		// up resources for other tests, which may still pass. We don't want them to close at the end of this loop,
		// so there's no issue having this here.
		defer func() {
			require.NoError(t, provider.Close())
		}()

		providers[i] = provider

		openStore, err := providers[i].OpenStore(storeName)
		require.NoError(t, err)

		openStores[i] = openStore
	}

	type sampleStruct struct {
		Entry1 string `json:"entry1"`
		Entry2 string `json:"entry2"`
		Entry3 string `json:"entry3"`
	}

	sampleData := sampleStruct{
		Entry1: "value1",
		Entry2: "value2",
		Entry3: "value3",
	}

	sampleDataBytes, err := json.Marshal(sampleData)
	require.NoError(t, err)

	var waitGroup sync.WaitGroup

	for i := 0; i < numberOfProviders; i++ {
		i := i

		waitGroup.Add(1)

		setStoreConfig := func() {
			defer waitGroup.Done()

			errPut := openStores[i].Put("key", sampleDataBytes)
			require.NoError(t, errPut)
		}
		go setStoreConfig()
	}

	waitGroup.Wait()

	value, err := openStores[0].Get("key")
	require.NoError(t, err)

	var retrievedData sampleStruct

	err = json.Unmarshal(value, &retrievedData)
	require.NoError(t, err)

	require.Equal(t, sampleData.Entry1, retrievedData.Entry1)
	require.Equal(t, sampleData.Entry2, retrievedData.Entry2)
	require.Equal(t, sampleData.Entry3, retrievedData.Entry3)
}

func testMultipleProvidersStoringSameBulkDataAtTheSameTime(t *testing.T, connString string) {
	t.Helper()

	const numberOfProviders = 100

	storeName := randomStoreName()

	providers := make([]*mongodb.Provider, numberOfProviders)

	openStores := make([]storage.Store, numberOfProviders)

	for i := 0; i < numberOfProviders; i++ {
		provider, err := mongodb.NewProvider(connString, mongodb.WithTimeout(time.Second*5),
			mongodb.WithMaxRetries(10),
			mongodb.WithTimeBetweenRetries(time.Second))
		require.NoError(t, err)

		// If you see a warning in your IDE about having a defer statement in a loop, it can be ignored in this case.
		// The goal is to close all the stores as soon as there's a failure anywhere in this test in order to free
		// up resources for other tests, which may still pass. We don't want them to close at the end of this loop,
		// so there's no issue having this here.
		defer func() {
			require.NoError(t, provider.Close())
		}()

		providers[i] = provider

		openStore, err := providers[i].OpenStore(storeName)
		require.NoError(t, err)

		openStores[i] = openStore
	}

	type sampleStruct struct {
		Entry1 string `json:"entry1"`
		Entry2 string `json:"entry2"`
		Entry3 string `json:"entry3"`
	}

	sampleData1 := sampleStruct{
		Entry1: "value1",
		Entry2: "value2",
		Entry3: "value3",
	}

	sampleData1Bytes, err := json.Marshal(sampleData1)
	require.NoError(t, err)

	sampleData2 := sampleStruct{
		Entry1: "value4",
		Entry2: "value5",
		Entry3: "value6",
	}

	sampleData2Bytes, err := json.Marshal(sampleData2)
	require.NoError(t, err)

	sampleData3 := sampleStruct{
		Entry1: "value7",
		Entry2: "value8",
		Entry3: "value9",
	}

	sampleData3Bytes, err := json.Marshal(sampleData3)
	require.NoError(t, err)

	operations := []storage.Operation{
		{Key: "key1", Value: sampleData1Bytes},
		{Key: "key2", Value: sampleData2Bytes},
		{Key: "key3", Value: sampleData3Bytes},
	}

	var waitGroup sync.WaitGroup

	for i := 0; i < numberOfProviders; i++ {
		i := i

		waitGroup.Add(1)

		setStoreConfig := func() {
			defer waitGroup.Done()

			errBatch := openStores[i].Batch(operations)
			require.NoError(t, errBatch)

			// Close the store as soon as possible in order to free up resources for other threads.
			require.NoError(t, openStores[i].Close())
		}
		go setStoreConfig()
	}

	waitGroup.Wait()

	values, err := openStores[0].GetBulk("key1", "key2", "key3")
	require.NoError(t, err)

	require.Len(t, values, 3)

	var retrievedData1 sampleStruct

	err = json.Unmarshal(values[0], &retrievedData1)
	require.NoError(t, err)

	require.Equal(t, sampleData1.Entry1, retrievedData1.Entry1)
	require.Equal(t, sampleData1.Entry2, retrievedData1.Entry2)
	require.Equal(t, sampleData1.Entry3, retrievedData1.Entry3)

	var retrievedData2 sampleStruct

	err = json.Unmarshal(values[1], &retrievedData2)
	require.NoError(t, err)

	require.Equal(t, sampleData2.Entry1, retrievedData2.Entry1)
	require.Equal(t, sampleData2.Entry2, retrievedData2.Entry2)
	require.Equal(t, sampleData2.Entry3, retrievedData2.Entry3)

	var retrievedData3 sampleStruct

	err = json.Unmarshal(values[2], &retrievedData3)
	require.NoError(t, err)

	require.Equal(t, sampleData3.Entry1, retrievedData3.Entry1)
	require.Equal(t, sampleData3.Entry2, retrievedData3.Entry2)
	require.Equal(t, sampleData3.Entry3, retrievedData3.Entry3)
}

func testCloseProviderTwice(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	_, err = provider.OpenStore("TestStore1")
	require.NoError(t, err)

	_, err = provider.OpenStore("TestStore2")
	require.NoError(t, err)

	require.NoError(t, provider.Close())
	require.NoError(t, provider.Close()) // Should succeed, even if called repeatedly.
}

func testQueryWithMultipleTags(t *testing.T, connString string) { //nolint: gocyclo // test file
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, provider.Close())
	}()

	keysToPut, valuesToPut, tagsToPut := getTestData()

	storeName := randomStoreName()

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	err = provider.SetStoreConfig(storeName,
		storage.StoreConfiguration{TagNames: []string{
			tagsToPut[0][0].Name,
			tagsToPut[0][1].Name,
			tagsToPut[0][2].Name,
			tagsToPut[0][3].Name,
			tagsToPut[0][4].Name,
		}})
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	putData(t, store, keysToPut, valuesToPut, tagsToPut)

	t.Run("Both pairs are tag names + values - 3 values found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"Breed:GoldenRetriever&&NumLegs:4",
			"NumLegs:4&&Breed:GoldenRetriever", // Should be equivalent to the above expression
		}

		expectedKeys := []string{keysToPut[0], keysToPut[3], keysToPut[4]}
		expectedValues := [][]byte{valuesToPut[0], valuesToPut[3], valuesToPut[4]}
		expectedTags := [][]storage.Tag{tagsToPut[0], tagsToPut[3], tagsToPut[4]}
		expectedTotalItemsCount := 3

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount)
			}
		}
	})
	t.Run("Both pairs are tag names + values - 2 values found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"Breed:GoldenRetriever&&Personality:Calm",
			"Personality:Calm&&Breed:GoldenRetriever", // Should be equivalent to the above expression
		}

		expectedKeys := []string{keysToPut[3], keysToPut[4]}
		expectedValues := [][]byte{valuesToPut[3], valuesToPut[4]}
		expectedTags := [][]storage.Tag{tagsToPut[3], tagsToPut[4]}
		expectedTotalItemsCount := 2

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount)
			}
		}
	})
	t.Run("Both pairs are tag names + values - 1 value found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"Personality:Shy&&EarType:Pointy",
			"EarType:Pointy&&Personality:Shy", // Should be equivalent to the above expression
		}

		expectedKeys := []string{keysToPut[1]}
		expectedValues := [][]byte{valuesToPut[1]}
		expectedTags := [][]storage.Tag{tagsToPut[1]}
		expectedTotalItemsCount := 1

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount)
			}
		}
	})
	t.Run("Both pairs are tag names + values - 0 values found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"Personality:Crazy&&EarType:Pointy",
			"EarType:Pointy&&Personality:Crazy", // Should be equivalent to the above expression
		}

		expectedTotalItemsCount := 0

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, nil, nil, nil, expectedTotalItemsCount)
			}
		}
	})
	t.Run("First pair is a tag name + value, second is a tag name only - 1 value found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"EarType:Pointy&&Nickname",
			"Nickname&&EarType:Pointy", // Should be equivalent to the above expression
		}

		expectedKeys := []string{keysToPut[2]}
		expectedValues := [][]byte{valuesToPut[2]}
		expectedTags := [][]storage.Tag{tagsToPut[2]}
		expectedTotalItemsCount := 1

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount)
			}
		}
	})
	t.Run("First pair is a tag name + value, second is a tag name only - 0 values found", func(t *testing.T) {
		queryExpressionsToTest := []string{
			"EarType:Pointy&&CoatType",
			"CoatType&&EarType:Pointy", // Should be equivalent to the above expression
		}

		expectedTotalItemsCount := 0

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryExpressionToTest := range queryExpressionsToTest {
			for _, queryOptionToTest := range queryOptionsToTest {
				iterator, err := store.Query(queryExpressionToTest, queryOptionToTest)
				require.NoError(t, err)

				verifyExpectedIterator(t, iterator, nil, nil, nil, expectedTotalItemsCount)
			}
		}
	})
}

func testQueryWithLessThanGreaterThanOperators(t *testing.T, connString string) {
	t.Helper()

	provider, err := mongodb.NewProvider(connString)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, provider.Close())
	}()

	keysToPut, valuesToPut, tagsToPut := getTestData()

	storeName := randomStoreName()

	store, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	err = provider.SetStoreConfig(storeName,
		storage.StoreConfiguration{TagNames: []string{
			tagsToPut[0][0].Name,
			tagsToPut[0][1].Name,
			tagsToPut[0][2].Name,
			tagsToPut[0][3].Name,
			tagsToPut[0][4].Name,
			tagsToPut[0][5].Name,
		}})
	require.NoError(t, err)

	defer func() {
		require.NoError(t, store.Close())
	}()

	putData(t, store, keysToPut, valuesToPut, tagsToPut)

	t.Run("Less than or equal to", func(t *testing.T) {
		queryExpression := "Age<=2"

		expectedKeys := []string{keysToPut[0], keysToPut[1], keysToPut[2]}
		expectedValues := [][]byte{valuesToPut[0], valuesToPut[1], valuesToPut[2]}
		expectedTags := [][]storage.Tag{tagsToPut[0], tagsToPut[1], tagsToPut[2]}
		expectedTotalItemsCount := 3

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryOptionToTest := range queryOptionsToTest {
			iterator, err := store.Query(queryExpression, queryOptionToTest)
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount)
		}
	})
	t.Run("Less than", func(t *testing.T) {
		queryExpression := "Age<2"

		expectedKeys := []string{keysToPut[1], keysToPut[2]}
		expectedValues := [][]byte{valuesToPut[1], valuesToPut[2]}
		expectedTags := [][]storage.Tag{tagsToPut[1], tagsToPut[2]}
		expectedTotalItemsCount := 2

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryOptionToTest := range queryOptionsToTest {
			iterator, err := store.Query(queryExpression, queryOptionToTest)
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount)
		}
	})
	t.Run("Greater than or equal to", func(t *testing.T) {
		queryExpression := "Age>=2"

		expectedKeys := []string{keysToPut[0], keysToPut[3]}
		expectedValues := [][]byte{valuesToPut[0], valuesToPut[3]}
		expectedTags := [][]storage.Tag{tagsToPut[0], tagsToPut[3]}
		expectedTotalItemsCount := 2

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryOptionToTest := range queryOptionsToTest {
			iterator, err := store.Query(queryExpression, queryOptionToTest)
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount)
		}
	})
	t.Run("Greater than", func(t *testing.T) {
		queryExpression := "Age>2"

		expectedKeys := []string{keysToPut[3]}
		expectedValues := [][]byte{valuesToPut[3]}
		expectedTags := [][]storage.Tag{tagsToPut[3]}
		expectedTotalItemsCount := 1

		queryOptionsToTest := []storage.QueryOption{
			nil,
			storage.WithPageSize(2),
			storage.WithPageSize(1),
			storage.WithPageSize(100),
		}

		for _, queryOptionToTest := range queryOptionsToTest {
			iterator, err := store.Query(queryExpression, queryOptionToTest)
			require.NoError(t, err)

			verifyExpectedIterator(t, iterator, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount)
		}
	})
	t.Run("Tag value is not a valid integer", func(t *testing.T) {
		iterator, err := store.Query("TagName>ThisIsNotAnInteger")
		require.EqualError(t, err, "invalid query format. when using any one of the <=, <, >=, > operators, "+
			"the immediate value on the right side side must be a valid integer: strconv.Atoi: parsing "+
			`"ThisIsNotAnInteger": invalid syntax`)
		require.Nil(t, iterator)
	})
}

func getTestData() (testKeys []string, testValues [][]byte, testTags [][]storage.Tag) {
	testKeys = []string{
		"Cassie",
		"Luna",
		"Miku",
		"Amber",
		"Brandy",
	}

	testValues = [][]byte{
		[]byte("is a big, young dog"),
		[]byte("is a small dog"),
		[]byte("is a fluffy dog (also small)"),
		[]byte("is a big, old dog"),
		[]byte("is a big dog of unknown age (but probably old)"),
	}

	testTags = [][]storage.Tag{
		{
			{Name: "Breed", Value: "GoldenRetriever"},
			{Name: "Personality", Value: "Playful"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Floppy"},
			{Name: "Nickname", Value: "Miss"},
			{Name: "Age", Value: "2"},
		},
		{
			{Name: "Breed", Value: "Schweenie"},
			{Name: "Personality", Value: "Shy"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Pointy"},
			{Name: "Age", Value: "1"},
		},
		{
			{Name: "Breed", Value: "Pomchi"},
			{Name: "Personality", Value: "Outgoing"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Pointy"},
			{Name: "Nickname", Value: "Fluffball"},
			{Name: "Age", Value: "1"},
		},
		{
			{Name: "Breed", Value: "GoldenRetriever"},
			{Name: "Personality", Value: "Calm"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Floppy"},
			{Name: "Age", Value: "14"},
		},
		{
			{Name: "Breed", Value: "GoldenRetriever"},
			{Name: "Personality", Value: "Calm"},
			{Name: "NumLegs", Value: "4"},
			{Name: "EarType", Value: "Floppy"},
		},
	}

	return testKeys, testValues, testTags
}

func putData(t *testing.T, store storage.Store, keys []string, values [][]byte, tags [][]storage.Tag) {
	t.Helper()

	for i := 0; i < len(keys); i++ {
		err := store.Put(keys[i], values[i], tags[i]...)
		require.NoError(t, err)
	}
}

// expectedKeys, expectedValues, and expectedTags are with respect to the query's page settings.
// Since Iterator.TotalItems' count is not affected by page settings, expectedTotalItemsCount must be passed in and
// can't be determined by looking at the length of expectedKeys, expectedValues, nor expectedTags.
func verifyExpectedIterator(t *testing.T, actualResultsItr storage.Iterator, expectedKeys []string,
	expectedValues [][]byte, expectedTags [][]storage.Tag, expectedTotalItemsCount int) {
	t.Helper()

	if len(expectedValues) != len(expectedKeys) || len(expectedTags) != len(expectedKeys) {
		require.FailNow(t,
			"Invalid test case. Expected keys, values and tags slices must be the same length.")
	}

	verifyIteratorAnyOrder(t, actualResultsItr, expectedKeys, expectedValues, expectedTags, expectedTotalItemsCount)
}

func verifyIteratorAnyOrder(t *testing.T, actualResultsItr storage.Iterator, //nolint: gocyclo // Test file
	expectedKeys []string, expectedValues [][]byte, expectedTags [][]storage.Tag, expectedTotalItemsCount int) {
	t.Helper()

	var dataChecklist struct {
		keys     []string
		values   [][]byte
		tags     [][]storage.Tag
		received []bool
	}

	dataChecklist.keys = expectedKeys
	dataChecklist.values = expectedValues
	dataChecklist.tags = expectedTags
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

		receivedTags, itrErr := actualResultsItr.Tags()
		require.NoError(t, itrErr)

		for i := 0; i < len(dataChecklist.keys); i++ {
			if receivedKey == dataChecklist.keys[i] {
				if string(receivedValue) == string(dataChecklist.values[i]) {
					if equalTags(receivedTags, dataChecklist.tags[i]) {
						dataChecklist.received[i] = true

						break
					}
				}
			}
		}

		moreResultsToCheck, err = actualResultsItr.Next()
		require.NoError(t, err)
	}

	count, errTotalItems := actualResultsItr.TotalItems()
	require.NoError(t, errTotalItems)
	require.Equal(t, expectedTotalItemsCount, count)

	err = actualResultsItr.Close()
	require.NoError(t, err)

	for _, received := range dataChecklist.received {
		if !received {
			require.FailNow(t, "received unexpected query results")
		}
	}
}

func equalTags(tags1, tags2 []storage.Tag) bool { //nolint:gocyclo // Test file
	if len(tags1) != len(tags2) {
		return false
	}

	matchedTags1 := make([]bool, len(tags1))
	matchedTags2 := make([]bool, len(tags2))

	for i, tag1 := range tags1 {
		for j, tag2 := range tags2 {
			if matchedTags2[j] {
				continue // This tag has already found a match. Tags can only have one match!
			}

			if tag1.Name == tag2.Name && tag1.Value == tag2.Value {
				matchedTags1[i] = true
				matchedTags2[j] = true

				break
			}
		}

		if !matchedTags1[i] {
			return false
		}
	}

	for _, matchedTag := range matchedTags1 {
		if !matchedTag {
			return false
		}
	}

	for _, matchedTag := range matchedTags2 {
		if !matchedTag {
			return false
		}
	}

	return true
}

func startMongoDBContainer(t *testing.T, dockerMongoDBTag string) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTag,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27017"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForMongoDBToBeUp())

	return pool, mongoDBResource
}

func waitForMongoDBToBeUp() error {
	return backoff.Retry(pingMongoDB, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func pingMongoDB() error {
	var err error

	tM := reflect.TypeOf(bson.M{})
	reg := bson.NewRegistryBuilder().RegisterTypeMapEntry(bsontype.EmbeddedDocument, tM).Build()
	clientOpts := options.Client().SetRegistry(reg).ApplyURI(mongoDBConnString)

	mongoClient, err := mongo.NewClient(clientOpts)
	if err != nil {
		return err
	}

	err = mongoClient.Connect(context.Background())
	if err != nil {
		return errors.Wrap(err, "error connecting to mongo")
	}

	db := mongoClient.Database("test")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return db.Client().Ping(ctx, nil)
}

func randomStoreName() string {
	return "store-" + uuid.New().String()
}

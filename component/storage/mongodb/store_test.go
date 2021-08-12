/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodb_test

import (
	"context"
	"log"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
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

func TestProvider_OpenStore_Failure(t *testing.T) {
	provider := mongodb.NewProvider("BadConnString")

	store, err := provider.OpenStore("StoreName")
	require.EqualError(t, err, `failed to create a new MongoDB client: error parsing uri: `+
		`scheme must be "mongodb" or "mongodb+srv"`)
	require.Nil(t, store)
}

func TestProvider_SetStoreConfig_Failure(t *testing.T) {
	provider := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))

	_, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	err = provider.SetStoreConfig("StoreName", storage.StoreConfiguration{TagNames: []string{"tagName1"}})
	require.EqualError(t, err, "failed to set indexes: failed to get existing indexed tag names: "+
		"failed to get list of indexes from MongoDB: server selection error: context deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
}

func TestProvider_GetStoreConfig_Failure(t *testing.T) {
	provider := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))

	_, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	config, err := provider.GetStoreConfig("StoreName")
	require.EqualError(t, err, "failed to get existing indexed tag names: failed to get list of indexes "+
		"from MongoDB: server selection error: context deadline exceeded, current topology: { Type: Unknown, "+
		"Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
	require.Empty(t, config)
}

func TestStore_Put_Failure(t *testing.T) {
	provider := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	err = store.Put("key", []byte("value"))
	require.EqualError(t, err, "failed to run UpdateOne command in MongoDB: server selection error: context "+
		"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
}

func TestStore_Get_Failure(t *testing.T) {
	provider := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	value, err := store.Get("key")
	require.EqualError(t, err, "failed to run FindOne command in MongoDB: server selection error: context "+
		"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
	require.Nil(t, value)
}

func TestStore_GetTags_Failure(t *testing.T) {
	provider := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	tags, err := store.GetTags("key")
	require.EqualError(t, err, "failed to run FindOne command in MongoDB: server selection error: "+
		"context deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, "+
		"Type: Unknown }, ] }")
	require.Nil(t, tags)
}

func TestStore_GetBulk_Failure(t *testing.T) {
	provider := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	values, err := store.GetBulk("key1", "key2")
	require.EqualError(t, err, "failed to run Find command in MongoDB: server selection error: context "+
		"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
	require.Nil(t, values)
}

func TestStore_Delete_Failure(t *testing.T) {
	provider := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))

	store, err := provider.OpenStore("StoreName")
	require.NoError(t, err)

	err = store.Delete("key1")
	require.EqualError(t, err, "failed to run DeleteOne command in MongoDB: server selection error: context "+
		"deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, Type: Unknown }, ] }")
}

func TestStore_Batch_Failure(t *testing.T) {
	provider := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(1))

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

	provider := mongodb.NewProvider(connString, mongodb.WithDBPrefix("dbPrefixTest_"),
		mongodb.WithLogger(&testLogger{
			logger: log.New(os.Stdout, "MongoDB-Provider ", log.Ldate|log.Ltime|log.LUTC),
		}))
	require.NotNil(t, provider)

	commontest.TestAll(t, provider, commontest.WithIteratorTotalItemCountTests())
	testMultipleProvidersSettingSameStoreConfigurationAtTheSameTime(t, connString)
}

func testMultipleProvidersSettingSameStoreConfigurationAtTheSameTime(t *testing.T, connString string) {
	t.Helper()

	const numberOfProviders = 100

	providers := make([]*mongodb.Provider, numberOfProviders)

	openStores := make([]storage.Store, numberOfProviders)

	for i := 0; i < numberOfProviders; i++ {
		provider := mongodb.NewProvider(connString, mongodb.WithTimeout(time.Second*3),
			mongodb.WithMaxIndexCreationConflictRetries(10),
			mongodb.WithIndexCreationConflictTimeBetweenRetries(time.Second))
		require.NotNil(t, provider)

		providers[i] = provider
	}

	for i := 0; i < numberOfProviders; i++ {
		openStore, err := providers[i].OpenStore("MultipleProviderTest")
		require.NoError(t, err)

		openStores[i] = openStore
	}

	for i := 0; i < numberOfProviders; i++ {
		openStore, err := providers[i].OpenStore("MultipleProviderTest")
		require.NoError(t, err)

		// If you see a warning in your IDE about having a defer statement in a loop, it can be ignored in this case.
		// The goal is to close all the stores as soon as there's a failure anywhere in this test in order to free
		// up resources for other tests, which may still pass. We don't want them to close at the end of this loop,
		// so there's no issue having this here.
		defer func() {
			require.NoError(t, openStore.Close())
		}()

		openStores[i] = openStore
	}

	var waitGroup sync.WaitGroup

	for i := 0; i < numberOfProviders; i++ {
		i := i

		waitGroup.Add(1)

		setStoreConfig := func() {
			defer waitGroup.Done()

			errSetStoreConfig := providers[i].SetStoreConfig("MultipleProviderTest",
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

			// Close the store as soon as possible in order to free up resources for other threads.
			require.NoError(t, openStores[i].Close())

			require.NoError(t, errSetStoreConfig)
		}
		go setStoreConfig()
	}

	waitGroup.Wait()
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

/*
Copyright Scoir, Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp_test

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	mockpackager "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/packager"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/streadway/amqp"
	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go-ext/component/didcomm/transport/amqp"
)

const (
	externalAddr      = "http://example.com"
	dockerRabbitImage = "rabbitmq"
	dockerRabbitTag   = "3.8.9"
	amqpAddr          = "amqp://127.0.0.1:5673"
)

func TestMain(m *testing.M) {
	code := 1

	defer func() { os.Exit(code) }()

	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("pool: %v", err))
	}

	rabbitResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerRabbitImage, Tag: dockerRabbitTag, Env: []string{},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"5672/tcp": {{HostIP: "", HostPort: "5673"}},
		},
	})
	if err != nil {
		panic(fmt.Sprintf("run with options: %v", err))
	}

	defer func() {
		if err = pool.Purge(rabbitResource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

	if err := checkRabbit(); err != nil {
		panic(fmt.Sprintf("check Rabbit: %v", err))
	}

	code = m.Run()
}

func checkRabbit() error {
	const retries = 60

	return backoff.Retry(func() error {
		_, err := amqp.Dial(amqpAddr)

		return err
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), retries))
}

func TestInboundTransport(t *testing.T) {
	t.Run("test inbound transport - with host/port", func(t *testing.T) {
		addr := amqpAddr

		inbound, err := NewInbound(addr, externalAddr, "queue", "", "")
		require.NoError(t, err)
		require.Equal(t, externalAddr, inbound.Endpoint())
	})

	t.Run("test inbound transport - with host/port, no external address", func(t *testing.T) {
		internalAddr := "amqp://example.com:5672"
		_, err := NewInbound(internalAddr, "", "queue", "", "")
		require.Error(t, err)
	})

	t.Run("test inbound transport - without host/port", func(t *testing.T) {
		port := ":5555"
		inbound, err := NewInbound(port, externalAddr, "queue", "", "")
		require.NoError(t, err)

		mockPackager := &mockpackager.Packager{UnpackValue: &transport.Envelope{Message: []byte("data")}}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.Error(t, err)
	})

	t.Run("test inbound transport - nil context", func(t *testing.T) {
		addr := amqpAddr
		inbound, err := NewInbound(addr, externalAddr, "queue", "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		err = inbound.Start(nil)
		require.Error(t, err)
	})

	t.Run("test inbound transport - invalid TLS", func(t *testing.T) {
		addr := amqpAddr
		inbound, err := NewInbound(addr, externalAddr, "queue", "invalid", "invalid")
		require.NoError(t, err)

		mockPackager := &mockpackager.Packager{UnpackValue: &transport.Envelope{Message: []byte("data")}}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid cert")
	})

	t.Run("test inbound transport - invalid port number", func(t *testing.T) {
		_, err := NewInbound("", "", "", "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "AMQP URL is mandatory")
	})
}

func TestInboundDataProcessing(t *testing.T) {
	t.Run("test inbound transport - multiple invocation with same client", func(t *testing.T) {
		addr := amqpAddr
		queue := "queue1"
		// initiate inbound with port
		inbound, err := NewInbound(addr, "http://example.com", queue, "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		// start server
		mockPackager := &mockpackager.Packager{UnpackValue: &transport.Envelope{Message: []byte("valid-data")}}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})

		require.NoError(t, err)
		// create ws client
		ch, cleanup := amqpClient(t, addr)
		defer cleanup()

		wait := make(chan amqp.Confirmation, 5)
		_ = ch.NotifyPublish(wait)
		for i := 1; i <= 5; i++ {
			err = ch.Publish(
				"",    // exchange
				queue, // routing key
				false, // mandatory
				false, // immediate
				amqp.Publishing{
					ContentType: "test/test",
					Body:        []byte("random"),
				})
			require.NoError(t, err)
			<-wait
		}
		err = inbound.Stop()
		require.NoError(t, err)
	})

	t.Run("test inbound transport - unpacking error", func(t *testing.T) {
		addr := amqpAddr
		queue := "queue2"
		inbound, err := NewInbound(addr, "http://example.com", queue, "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		// start server
		mockPackager := &mockpackager.Packager{UnpackErr: errors.New("error unpacking")}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.NoError(t, err)

		// create ws client
		ch, cleanup := amqpClient(t, addr)
		defer cleanup()

		wait := make(chan amqp.Confirmation, 1)
		_ = ch.NotifyPublish(wait)
		err = ch.Publish(
			"",    // exchange
			queue, // routing key
			false, // mandatory
			false, // immediate
			amqp.Publishing{
				ContentType: "text/plain",
				Body:        []byte(""),
			})
		<-wait
		require.NoError(t, err)
	})

	t.Run("test inbound transport - message handler error", func(t *testing.T) {
		addr := amqpAddr
		queue := "queue3"

		inbound, err := NewInbound(addr, "http://example.com", queue, "", "")
		require.NoError(t, err)
		require.NotEmpty(t, inbound)

		// start server
		mockPackager := &mockpackager.Packager{UnpackValue: &transport.Envelope{Message: []byte("invalid-data")}}
		err = inbound.Start(&mockProvider{packagerValue: mockPackager})
		require.NoError(t, err)

		// create ws client
		ch, cleanup := amqpClient(t, addr)
		defer cleanup()

		wait := make(chan amqp.Confirmation, 1)
		_ = ch.NotifyPublish(wait)

		err = ch.Publish(
			"",    // exchange
			queue, // routing key
			false, // mandatory
			false, // immediate
			amqp.Publishing{
				ContentType: "text/plain",
				Body:        []byte(""),
			})
		<-wait
		require.NoError(t, err)
	})
}

func amqpClient(t *testing.T, addr string) (ch *amqp.Channel, cleanup func()) {
	t.Helper()

	conn, err := amqp.Dial(addr)
	require.NoError(t, err)

	ch, err = conn.Channel()
	require.NoError(t, err)

	err = ch.Confirm(false)
	require.NoError(t, err)

	return ch, func() {
		require.NoError(t, conn.Close(), "closing the connection")
	}
}

type mockProvider struct {
	packagerValue transport.Packager
}

func (p *mockProvider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(envelope *transport.Envelope) error {
		if envelope != nil && string(envelope.Message) == "invalid-data" {
			return errors.New("error")
		}

		return nil
	}
}

func (p *mockProvider) Packager() transport.Packager {
	return p.packagerValue
}

func (p *mockProvider) AriesFrameworkID() string {
	return uuid.New().String()
}

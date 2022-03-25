/*
Copyright Scoir, Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package amqp implements an inbound DIDComm transport for Aries (aries-framework-go).
//
package amqp

import (
	"crypto/tls"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/pkg/errors"
	"github.com/streadway/amqp"
)

// Inbound amqp type.
type Inbound struct {
	internalAddr      string
	externalAddr      string
	queueName         string
	conn              *amqp.Connection
	ch                *amqp.Channel
	que               amqp.Queue
	certFile, keyFile string
	packager          transport.Packager
	msgHandler        transport.InboundMessageHandler
	logger            *log.Log
}

// NewInbound creates a new AMQP inbound transport instance.
func NewInbound(amqpServerURL, externalAddr, queueName, certFile, keyFile string) (*Inbound, error) {
	if amqpServerURL == "" {
		return nil, errors.New("AMQP URL is mandatory")
	}

	if externalAddr == "" {
		return nil, errors.New("external address is mandatory")
	}

	return &Inbound{
		certFile:     certFile,
		keyFile:      keyFile,
		internalAddr: amqpServerURL,
		externalAddr: externalAddr,
		queueName:    queueName,
		logger:       log.New("aries-framework/transport/amqp"),
	}, nil
}

// Start the AMQP message loop.
func (i *Inbound) Start(prov transport.Provider) error {
	if prov == nil || prov.InboundMessageHandler() == nil {
		return errors.New("creation of inbound handler failed")
	}

	conn, err := i.connection()
	if err != nil {
		return err
	}

	ch, err := conn.Channel()
	if err != nil {
		return errors.Wrap(err, "unable to get channel")
	}

	q, err := ch.QueueDeclare(
		i.queueName, // name
		false,       // durable
		false,       // delete when unused
		false,       // exclusive
		false,       // no-wait
		nil,         // arguments
	)
	if err != nil {
		return errors.Wrap(err, "unable to declare queue")
	}

	i.conn = conn
	i.ch = ch
	i.que = q
	i.packager = prov.Packager()
	i.msgHandler = prov.InboundMessageHandler()

	go func() {
		if err := i.listenAndServe(); err != nil {
			i.logger.Fatalf("AMQP start with address [%s] failed, cause:  %v", i.externalAddr, err)
		}
	}()

	return nil
}

func (i *Inbound) connection() (*amqp.Connection, error) {
	var conn *amqp.Connection

	var err error

	if i.certFile != "" && i.keyFile != "" {
		config := &tls.Config{MinVersion: tls.VersionTLS13}
		config.Certificates = make([]tls.Certificate, 1)

		config.Certificates[0], err = tls.LoadX509KeyPair(i.certFile, i.keyFile)
		if err != nil {
			return nil, errors.Wrap(err, "invalid cert")
		}

		conn, err = amqp.DialTLS(i.internalAddr, config)
		if err != nil {
			return nil, errors.Wrap(err, "unable to connect to AMQP server")
		}
	} else {
		conn, err = amqp.Dial(i.internalAddr)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to connect to AMQP server at %s", i.internalAddr)
		}
	}

	return conn, nil
}

func (i *Inbound) listenAndServe() error {
	msgs, err := i.ch.Consume(
		i.queueName, // queue
		"",          // consumer
		true,        // auto-ack
		false,       // exclusive
		false,       // no-local
		false,       // no-wait
		nil,         // args
	)
	if err != nil {
		return errors.Wrap(err, "unable to consume")
	}

	for d := range msgs {
		message := d.Body

		unpackMsg, err := i.packager.UnpackMessage(message)
		if err != nil {
			i.logger.Errorf("failed to unpack msg: %v", err)

			continue
		}

		trans := &decorator.Transport{}

		err = json.Unmarshal(unpackMsg.Message, trans)
		if err != nil {
			i.logger.Errorf("unmarshal transport decorator : %v", err)
		}

		messageHandler := i.msgHandler

		err = messageHandler(unpackMsg)
		if err != nil {
			i.logger.Errorf("incoming msg processing failed: %v", err)
		}
	}

	return nil
}

// Stop the AMQP message loop.
func (i *Inbound) Stop() error {
	if err := i.ch.Close(); err != nil {
		return fmt.Errorf("channel shutdown failed: %w", err)
	}

	if err := i.conn.Close(); err != nil {
		return fmt.Errorf("connection shutdown failed: %w", err)
	}

	return nil
}

// Endpoint provides the AMQP connection details.
func (i *Inbound) Endpoint() string {
	return i.externalAddr
}

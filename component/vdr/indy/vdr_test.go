/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go-ext/component/vdr/indy"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/indy/mock"
)

const (
	genesisFilePath = "%s/testdata/pool_transactions_sandbox_genesis.txt"
)

func TestNew(t *testing.T) {
	type args struct {
		methodName string
		opts       []Option
	}

	tests := []struct {
		name    string
		args    args
		want    *VDR
		wantErr bool
	}{
		{
			name: "with indy client and refresh",
			args: args{
				methodName: "sov",
				opts:       []Option{WithIndyClient(&mock.IndyClient{}), WithRefresh(true)},
			},
			want: &VDR{
				MethodName: "sov",
				Refresh:    true,
				Client:     &mock.IndyClient{},
			},
			wantErr: false,
		},
		{
			name: "pool refresh fails",
			args: args{
				methodName: "sov",
				opts: []Option{WithIndyClient(&mock.IndyClient{
					RefreshErr: errors.New("boom"),
				}), WithRefresh(true)},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "with no indy client",
			args: args{
				methodName: "sov",
				opts:       []Option{},
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		thisTest := tt
		t.Run(thisTest.name, func(t *testing.T) {
			got, err := New(thisTest.args.methodName, thisTest.args.opts...)
			if (err != nil) != thisTest.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, thisTest.wantErr)

				return
			}
			if !reflect.DeepEqual(got, thisTest.want) {
				t.Errorf("New() got = %v, want %v", got, thisTest.want)
			}
		})
	}
}

func TestVDRI_Accept(t *testing.T) {
	type fields struct {
		methodName string
	}

	type args struct {
		method string
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "matching method",
			fields: fields{
				methodName: "sov",
			},
			args: args{
				method: "sov",
			},
			want: true,
		},
		{
			name: "mismatching method",
			fields: fields{
				methodName: "sov",
			},
			args: args{
				method: "ioe",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		thisTest := tt
		t.Run(tt.name, func(t *testing.T) {
			r := &VDR{
				MethodName: thisTest.fields.methodName,
			}
			if got := r.Accept(thisTest.args.method); got != thisTest.want {
				t.Errorf("Accept() = %v, want %v", got, thisTest.want)
			}
		})
	}
}

func TestVDRI_Close(t *testing.T) {
	type fields struct {
		client Client
	}

	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Close works",
			fields: fields{
				client: &mock.IndyClient{
					CloseErr: nil,
				},
			},
			wantErr: false,
		},
		{
			name: "Close fails",
			fields: fields{
				client: &mock.IndyClient{
					CloseErr: errors.New("boom"),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		thisTest := tt
		t.Run(thisTest.name, func(t *testing.T) {
			r := &VDR{
				Client: thisTest.fields.client,
			}
			if err := r.Close(); (err != nil) != thisTest.wantErr {
				t.Errorf("Close() error = %v, wantErr %v", err, thisTest.wantErr)
			}
		})
	}
}

func TestWithRefresh(t *testing.T) {
	t.Run("refresh sets the value", func(t *testing.T) {
		refresh := WithRefresh(true)
		opts := &VDR{}
		refresh(opts)
		require.True(t, opts.Refresh)
	})
}

func TestWithIndyVDRGenesisFile(t *testing.T) {
	t.Run("with file", func(t *testing.T) {
		path, err := filepath.Abs("./")
		require.NoError(t, err)

		withIndyGF := WithIndyVDRGenesisFile(fmt.Sprintf(genesisFilePath, path))
		opts := &VDR{}
		withIndyGF(opts)
		require.NotNil(t, opts.Client)
	})

	t.Run("with bad path", func(t *testing.T) {
		withIndyGF := WithIndyVDRGenesisFile("badfile.txt")
		opts := &VDR{}
		withIndyGF(opts)
		require.Nil(t, opts.Client)
	})

	t.Run("with bad genesis file", func(t *testing.T) {
		f, err := ioutil.TempFile("", "emptygenesis.txn")
		require.NoError(t, err)
		defer func() {
			err := os.Remove(f.Name())
			require.NoError(t, err)
		}()

		withIndyGF := WithIndyVDRGenesisFile(f.Name())
		opts := &VDR{}
		withIndyGF(opts)
		require.Nil(t, opts.Client)
	})
}

func TestWithIndyVDRGenesisReader(t *testing.T) {
	t.Run("with file", func(t *testing.T) {
		path, err := filepath.Abs("./")
		require.NoError(t, err)

		reader, err := os.Open(fmt.Sprintf(genesisFilePath, path))
		require.NoError(t, err)

		withIndyGF := WithIndyVDRGenesisReader(reader)
		opts := &VDR{}
		withIndyGF(opts)
		require.NotNil(t, opts.Client)
	})
	t.Run("with file", func(t *testing.T) {
		f, err := ioutil.TempFile("", "emptygenesis.txn")
		require.NoError(t, err)
		defer func() {
			err = os.Remove(f.Name())
			require.NoError(t, err)
		}()

		reader, err := os.Open(f.Name())
		require.NoError(t, err)

		withIndyGF := WithIndyVDRGenesisReader(reader)
		opts := &VDR{}
		withIndyGF(opts)
		require.Nil(t, opts.Client)
	})
}

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mysql

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStore_OpenStore_Internal(t *testing.T) {
	db, err := sql.Open("mysql", "root:wrong-password@tcp(127.0.0.1:3301)/")
	require.NoError(t, err)

	provider := Provider{db: db}

	store, err := provider.OpenStore("TestStore")
	require.EqualError(t, err, "failure while creating DB teststore: Error 1045: "+
		"Access denied for user 'root'@'172.17.0.1' (using password: YES)")
	require.Nil(t, store)
}

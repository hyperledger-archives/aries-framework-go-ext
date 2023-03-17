/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package validator holds validation handlers for status fields
// for different formats of verifiable credential status list.
package validator

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go-ext/component/vc/status/api"
	"github.com/hyperledger/aries-framework-go-ext/component/vc/status/validator/statuslist2021"
)

// GetValidator returns the VC status list validator for the given status type.
func GetValidator(statusType string) (api.Validator, error) {
	switch statusType {
	case statuslist2021.StatusList2021Type:
		return &statuslist2021.Validator{}, nil
	default:
		return nil, fmt.Errorf("unsupported VCStatusListType %s", statusType)
	}
}

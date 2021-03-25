#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did_method_rest
Feature: Using DID method REST API

  @e2e_sidetree
  Scenario Outline: create trustbloc did and resolve through sidetree-mock
    Then Bloc VDR is initialized with resolver URL "https://localhost:48326/sidetree/v1/identifiers"
    Then TrustBloc DID is created through "https://localhost:48326/sidetree/v1" with key type "<keyType>" with signature suite "<signatureSuite>"
    Then Resolve created DID and validate key type "<keyType>", signature suite "<signatureSuite>"
    Examples:
      | keyType  |  signatureSuite             |
      | Ed25519  |  JwsVerificationKey2020     |
      | P256     |  JwsVerificationKey2020     |
      | Ed25519  |  Ed25519VerificationKey2018 |

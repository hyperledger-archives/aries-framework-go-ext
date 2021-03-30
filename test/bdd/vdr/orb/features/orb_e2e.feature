#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@orb
Feature: Test orb vdr

  @orb_did_ops
  Scenario Outline:
    Then Orb DID is created through "https://localhost:48327/sidetree/v1" with key type "<keyType>" with signature suite "<signatureSuite>"
    Then Resolve created DID through "https://localhost:48327/sidetree/v1/identifiers" and validate key type "<keyType>", signature suite "<signatureSuite>"
    Then Orb DID is updated through "https://localhost:48327/sidetree/v1" with key type "<keyType>" with signature suite "<signatureSuite>"
    Then Resolve updated DID through "https://localhost:48327/sidetree/v1/identifiers"
    Then Orb DID is recovered through "https://localhost:48327/sidetree/v1" with key type "<keyType>" with signature suite "<signatureSuite>"
    Then Resolve recovered DID through "https://localhost:48327/sidetree/v1/identifiers"
    Then Orb DID is deactivated through "https://localhost:48327/sidetree/v1"
    Examples:
      | keyType    |  signatureSuite             |
      | Ed25519    |  JsonWebKey2020             |
      | Ed25519    |  Ed25519VerificationKey2018 |
      | Bls12381G2 |  Bls12381G2Key2020          |
      | P256       |  JsonWebKey2020             |
      | P384       |  JsonWebKey2020             |

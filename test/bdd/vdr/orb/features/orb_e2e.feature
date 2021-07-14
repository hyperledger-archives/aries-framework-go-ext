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
    Then Orb DID is created with key type "<keyType>" with signature suite "<signatureSuite>"
    Then Resolve created DID and validate key type "<keyType>", signature suite "<signatureSuite>"
    Then Orb DID is updated with key type "<keyType>" with signature suite "<signatureSuite>"
    Then Resolve updated DID
    Then Orb DID is recovered with key type "<keyType>" with signature suite "<signatureSuite>"
    Then Resolve recovered DID
    Then Orb DID is deactivated
    Examples:
      | keyType    |  signatureSuite             |
      | Ed25519    |  JsonWebKey2020             |
      | Ed25519    |  Ed25519VerificationKey2018 |
      | Bls12381G2 |  Bls12381G2Key2020          |
      | P256       |  JsonWebKey2020             |
      | P384       |  JsonWebKey2020             |


  @orb_did_anchor_origin
  Scenario:
    Then Orb DID is created with key type "Ed25519" with signature suite "JsonWebKey2020" with anchor origin ipns
    Then Resolve created DID through anchor origin
    Then Orb DID is created with key type "Ed25519" with signature suite "JsonWebKey2020" with anchor origin https
    Then Resolve created DID through anchor origin

  @orb_did_stress_test
  Scenario:
    When client sends request to "ORB_STRESS_DID_DOMAINS" to create and update "ORB_STRESS_DID_NUMS" DID documents with anchor origin "ORB_STRESS_ANCHOR_ORIGIN" using "ORB_STRESS_CONCURRENT_REQ" concurrent requests


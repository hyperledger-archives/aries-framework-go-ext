#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@orb
Feature: Test orb vdr

  @orb_ipfs
  @orb_did_ops
  Scenario Outline:
    Then Execute shell script "./create_follow_activity.sh"
    Then Orb DID is created with key type "<keyType>" with signature suite "<signatureSuite>" with resolve DID "true"
    Then Resolve created DID and validate key type "<keyType>", signature suite "<signatureSuite>"
    Then Orb DID is updated with key type "<keyType>" with signature suite "<signatureSuite>" with resolve DID "true"
    Then Resolve updated DID
    Then Resolve created DID using "versionID"
    Then Resolve created DID using "versionTime"
    Then Orb DID is recovered with key type "<keyType>" with signature suite "<signatureSuite>"
    Then Resolve recovered DID
    Then Orb DID is deactivated
    Examples:
      | keyType    |  signatureSuite             |
      | Ed25519    |  Ed25519VerificationKey2020 |
      | Ed25519    |  JsonWebKey2020             |
      | Ed25519    |  Ed25519VerificationKey2018 |
      | Bls12381G2 |  Bls12381G2Key2020          |
      | P256       |  JsonWebKey2020             |
      | P384       |  JsonWebKey2020             |

  @orb_ipfs
  @orb_did_anchor_origin
  Scenario:
    Then Execute shell script "./create_follow_activity.sh"
#    Then Orb DID is created with key type "Ed25519" with signature suite "JsonWebKey2020" with anchor origin ipns
#    Then Resolve created DID through anchor origin
    Then Orb DID is created with key type "Ed25519" with signature suite "JsonWebKey2020" with anchor origin https
    Then Resolve created DID through anchor origin

  @orb_cas
  @orb_did_local_cas
  Scenario:
    Then Execute shell script "./create_follow_activity.sh"
    Then Orb DID is created with key type "Ed25519" with signature suite "JsonWebKey2020" with resolve DID "false"
    Then Resolve created DID through https hint
    Then Orb DID is updated with key type "Ed25519" with signature suite "JsonWebKey2020" with resolve DID "false"
    Then Resolve update DID through cache
    Then Orb DID is created with key type "Ed25519" with signature suite "JsonWebKey2020" with anchor origin https
    Then Resolve created DID through anchor origin

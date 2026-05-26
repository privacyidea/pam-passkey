// Tests for parseCoseKey, the COSE_Key (CBOR) → EVP_PKEY conversion used by
// offline FIDO authentication.
//
// Fixture captured on 2026-05-26 from a successful end-to-end offline
// authentication against a privacyIDEA 3.12 dev server using a YubiKey 5.
// See pam_privacyidea_passkey syslog tagged "OFFLINE-ASSERT" / "ecKeyFromCbor"
// in that session for the original capture.

#include <gtest/gtest.h>
#include "cose_key.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>

namespace
{

// COSE_Key blob for the offline-credential public key (base64url, as emitted
// by privacyIDEA's /validate/check `pubKey` field). Decodes to a 77-byte CBOR
// map: { 1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: X, -3: Y }.
constexpr const char *kPubKeyB64Url =
    "pQECAyYgASFYIF02slFKiyhYcc8UTCEIoVL71sn_qxG80iox6bL1lkOg"
    "IlggwlJnY49ry0LdcVpnZIgp3tWluYIRHHDmMZ0VUP1Wkts";

// Same blob, hex-encoded (as it may also be stored on disk after refill).
constexpr const char *kPubKeyHex =
    "a50102032620012158205d36b2514a8b285871cf144c2108a152fbd6c9ffab11bcd2"
    "2a31e9b2f59643a0225820c25267638f6bcb42dd715a67648829ded5a5b982111c70"
    "e6319d1550fd5692db";

constexpr int kCoseAlgEs256 = -7;

} // namespace

TEST(ParseCoseKey, AcceptsBase64UrlEncodedCoseKey)
{
    EVP_PKEY *pkey = nullptr;
    int alg = 0;
    EXPECT_EQ(parseCoseKey(kPubKeyB64Url, &pkey, &alg), CoseKeyParseResult::Ok);
    ASSERT_NE(pkey, nullptr);
    EXPECT_EQ(alg, kCoseAlgEs256);
    EVP_PKEY_free(pkey);
}

TEST(ParseCoseKey, AcceptsHexEncodedCoseKey)
{
    EVP_PKEY *pkey = nullptr;
    int alg = 0;
    EXPECT_EQ(parseCoseKey(kPubKeyHex, &pkey, &alg), CoseKeyParseResult::Ok);
    ASSERT_NE(pkey, nullptr);
    EXPECT_EQ(alg, kCoseAlgEs256);
    EVP_PKEY_free(pkey);
}

TEST(ParseCoseKey, ResultingKeyIsEcPrime256v1)
{
    // Regression for the original bug: pushing X and Y as two separate "pub"
    // OSSL_PARAM entries produced a null pkey on OpenSSL 3.0.13. With the SEC1
    // uncompressed-point encoding the resulting key must be a valid P-256 EC
    // public key — check the group name explicitly.
    EVP_PKEY *pkey = nullptr;
    int alg = 0;
    ASSERT_EQ(parseCoseKey(kPubKeyB64Url, &pkey, &alg), CoseKeyParseResult::Ok);
    ASSERT_NE(pkey, nullptr);

    EXPECT_EQ(EVP_PKEY_base_id(pkey), EVP_PKEY_EC);

    char groupName[64] = {0};
    size_t groupNameLen = 0;
    EXPECT_EQ(EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                             groupName, sizeof(groupName), &groupNameLen),
              1);
    EXPECT_STREQ(groupName, "prime256v1");

    EVP_PKEY_free(pkey);
}

TEST(ParseCoseKey, RejectsGarbage)
{
    EVP_PKEY *pkey = nullptr;
    int alg = 0;
    // Not valid base64url, not valid hex of valid CBOR.
    EXPECT_EQ(parseCoseKey("zz", &pkey, &alg), CoseKeyParseResult::InvalidCbor);
    EXPECT_EQ(pkey, nullptr);
}

TEST(ParseCoseKey, RejectsNonEs256Algorithm)
{
    // COSE_Key with alg = -8 (EdDSA) instead of -7. Same structure otherwise so
    // the CBOR parser is happy; only the algorithm check should fail.
    // Map of 2 pairs: { 3: -8, 1: 1 } → CBOR: a2 03 27 01 01
    EVP_PKEY *pkey = nullptr;
    int alg = 0;
    EXPECT_EQ(parseCoseKey("a203270101", &pkey, &alg), CoseKeyParseResult::UnsupportedAlgorithm);
    EXPECT_EQ(pkey, nullptr);
    EXPECT_EQ(alg, -8);
}

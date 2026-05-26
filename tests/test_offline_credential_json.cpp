#include <gtest/gtest.h>
#include "offline_fido_credential.h"
#include <nlohmann/json.hpp>

// to_json / from_json are defined in privacyidea.cpp at file scope. They are
// found via ADL because the OfflineFIDOCredential is a user type and nlohmann
// looks them up in the type's namespace (global). Declaring them here would
// risk a mismatch — instead we link in privacyidea.cpp from the test target.
using json = nlohmann::json;

void from_json(const json &j, OfflineFIDOCredential &cred);
void to_json(json &j, const OfflineFIDOCredential &cred);

namespace
{
OfflineFIDOCredential sample()
{
    return OfflineFIDOCredential{
        /*public_key_hex=*/"pQECAyYgASFYIE_pubkey_x_y_blob",
        /*username=*/"hans",
        /*rpId=*/"cool.nils",
        /*credId=*/"T9TJpDbUuq0TIdIpErltERuboEdR1GBa7pVtdYMQYTQZ582wmBwp5TWuZ_sE_Ag4",
        /*serial=*/"PIPK0000BE5A",
        /*refilltoken=*/"7bc6cfd5ffb726c5e795ad",
        /*sign_count=*/42,
        /*expiry_timestamp=*/"2026-06-01T12:00:00Z"};
}
} // namespace

TEST(OfflineCredentialJson, RoundTripPreservesAllFields)
{
    auto original = sample();
    json j = original;
    OfflineFIDOCredential restored = j.get<OfflineFIDOCredential>();

    EXPECT_EQ(restored.public_key_hex, original.public_key_hex);
    EXPECT_EQ(restored.username, original.username);
    EXPECT_EQ(restored.rpId, original.rpId);
    EXPECT_EQ(restored.credId, original.credId);
    EXPECT_EQ(restored.serial, original.serial);
    EXPECT_EQ(restored.refilltoken, original.refilltoken);
    EXPECT_EQ(restored.sign_count, original.sign_count);
    EXPECT_EQ(restored.expiry_timestamp, original.expiry_timestamp);
}

TEST(OfflineCredentialJson, SerializedShapeMatchesOfflineFileSchema)
{
    auto cred = sample();
    json j = cred;

    // Pin down the JSON keys — changing any of these breaks the on-disk format
    // and silently invalidates existing offline files in deployed installs.
    ASSERT_TRUE(j.contains("pubKey"));
    ASSERT_TRUE(j.contains("username"));
    ASSERT_TRUE(j.contains("rpId"));
    ASSERT_TRUE(j.contains("credentialId"));
    ASSERT_TRUE(j.contains("serial"));
    ASSERT_TRUE(j.contains("refilltoken"));
    ASSERT_TRUE(j.contains("sign_count"));
    ASSERT_TRUE(j.contains("expiry_timestamp"));
    EXPECT_EQ(j.size(), 8u);
}

TEST(OfflineCredentialJson, MissingFieldThrowsOnRead)
{
    // The offline file is trusted local state; from_json uses .at(), so a
    // partial entry surfaces as an exception (caught and logged by the
    // PrivacyIDEA constructor). Pin down that behavior.
    json j = sample();
    j.erase("refilltoken");

    EXPECT_THROW({ (void)j.get<OfflineFIDOCredential>(); }, nlohmann::json::out_of_range);
}

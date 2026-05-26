#include <gtest/gtest.h>
#include "privacyidea.h"
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace
{

std::string readFixture(const std::string &name)
{
    fs::path p = fs::path(FIXTURES_DIR) / name;
    std::ifstream in(p);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

OfflineFIDOCredential makeCred()
{
    return OfflineFIDOCredential{
        /*public_key_hex=*/"pQECAyYgASFYIE_UyaQ21LqtEyHSKRJpShO-wOGDv7qDWURk30_U26xtIlgglAzzrE4UkAFqhrNdg2OToNFk6it8EAzLuZwfWM8neyc",
        /*username=*/"hans",
        /*rpId=*/"cool.nils",
        /*credId=*/"T9TJpDbUuq0TIdIpErltERuboEdR1GBa7pVtdYMQYTQZ582wmBwp5TWuZ_sE_Ag4",
        /*serial=*/"PIPK0000BE5A",
        /*refilltoken=*/"7bc6cfd5ffb726c5e795ad3776f5936dbfa5137eee7f8b63f8c5f452ec9600d1f0aa6aeba52182a8",
        /*sign_count=*/0,
        /*expiry_timestamp=*/""};
}

class RefillFixture : public ::testing::Test
{
protected:
    void SetUp() override
    {
        const ::testing::TestInfo *info = ::testing::UnitTest::GetInstance()->current_test_info();
        offlinePath_ = fs::path(::testing::TempDir()) /
                       (std::string("pipam-refill-") + info->name() + ".json");
        std::error_code ec;
        fs::remove(offlinePath_, ec);
    }

    void TearDown() override
    {
        std::error_code ec;
        fs::remove(offlinePath_, ec);
    }

    std::unique_ptr<PrivacyIDEA> makePI(long expiryDays = 30)
    {
        return std::make_unique<PrivacyIDEA>(nullptr, "https://example.test", "",
                                             true, offlinePath_.string(),
                                             false, 0, expiryDays);
    }

    fs::path offlinePath_;
};

} // namespace

TEST_F(RefillFixture, SuccessRotatesRefillTokenAndRefreshesExpiry)
{
    auto pi = makePI(/*expiryDays=*/30);
    auto cred = makeCred();
    const std::string oldToken = cred.refilltoken;

    int rc = pi->parseOfflineRefillResponse(readFixture("refill_success.json"), cred);

    EXPECT_EQ(rc, 0);
    EXPECT_NE(cred.refilltoken, oldToken);
    EXPECT_EQ(cred.refilltoken,
              "4e6063807d22d5baf2aa1f958d068219559ccc6c5c43da54c3f96c71b4c3912f8bfd203a3ff32e09");
    EXPECT_FALSE(cred.expiry_timestamp.empty());
}

TEST_F(RefillFixture, SuccessWithExpiryDisabledLeavesExpiryUntouched)
{
    auto pi = makePI(/*expiryDays=*/0);
    auto cred = makeCred();
    cred.expiry_timestamp = ""; // already empty

    int rc = pi->parseOfflineRefillResponse(readFixture("refill_success.json"), cred);

    EXPECT_EQ(rc, 0);
    EXPECT_TRUE(cred.expiry_timestamp.empty());
}

TEST_F(RefillFixture, Error905InvalidRefilltokenSignalsDeletion)
{
    auto pi = makePI();
    auto cred = makeCred();
    const std::string oldToken = cred.refilltoken;

    int rc = pi->parseOfflineRefillResponse(readFixture("refill_905_invalid_refilltoken.json"), cred);

    EXPECT_EQ(rc, 905);
    EXPECT_EQ(cred.refilltoken, oldToken); // unchanged on deletion signal
}

TEST_F(RefillFixture, Error905TokenNotValidSignalsDeletion)
{
    auto pi = makePI();
    auto cred = makeCred();

    int rc = pi->parseOfflineRefillResponse(readFixture("refill_905_token_not_valid.json"), cred);
    EXPECT_EQ(rc, 905);
}

TEST_F(RefillFixture, Error905TokenDoesNotExistSignalsDeletion)
{
    auto pi = makePI();
    auto cred = makeCred();

    int rc = pi->parseOfflineRefillResponse(readFixture("refill_905_token_does_not_exist.json"), cred);
    EXPECT_EQ(rc, 905);
}

// With the server-side `hide_specific_error_message_for_offline_refill` policy active,
// genuine errors come back as code 401 instead of 905. We deliberately do NOT delete
// the credential in that case — the safer fallback is "keep until expiry."
// This test pins down the current behavior so any future change is intentional.
TEST_F(RefillFixture, Error401HiddenIsNoOpAndKeepsCredential)
{
    auto pi = makePI();
    auto cred = makeCred();
    const std::string oldToken = cred.refilltoken;

    int rc = pi->parseOfflineRefillResponse(readFixture("refill_401_hidden_error.json"), cred);

    EXPECT_EQ(rc, 0);                      // not a deletion signal
    EXPECT_EQ(cred.refilltoken, oldToken); // unchanged
}

TEST_F(RefillFixture, MalformedJsonReturnsParseError)
{
    auto pi = makePI();
    auto cred = makeCred();
    const std::string oldToken = cred.refilltoken;

    int rc = pi->parseOfflineRefillResponse("not json at all }", cred);

    EXPECT_EQ(rc, 1);
    EXPECT_EQ(cred.refilltoken, oldToken);
}

TEST_F(RefillFixture, EmptyObjectIsNoOp)
{
    auto pi = makePI();
    auto cred = makeCred();
    const std::string oldToken = cred.refilltoken;

    int rc = pi->parseOfflineRefillResponse("{}", cred);

    EXPECT_EQ(rc, 0);
    EXPECT_EQ(cred.refilltoken, oldToken);
}

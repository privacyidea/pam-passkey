#include <gtest/gtest.h>
#include "privacyidea.h"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

namespace
{

std::string readFixture(const std::string &name)
{
    fs::path p = fs::path(FIXTURES_DIR) / name;
    std::ifstream in(p);
    if (!in)
    {
        ADD_FAILURE() << "Fixture not found: " << p;
        return "";
    }
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// PrivacyIDEA persists offline data via its destructor. Give each test a unique
// path under the gtest temp dir so destructors don't clobber one another.
class PrivacyIDEAFixture : public ::testing::Test
{
protected:
    void SetUp() override
    {
        const ::testing::TestInfo *info = ::testing::UnitTest::GetInstance()->current_test_info();
        offlinePath_ = fs::path(::testing::TempDir()) /
                       (std::string("pipam-test-") + info->test_suite_name() + "-" + info->name() + ".json");
        // Make sure we start clean.
        std::error_code ec;
        fs::remove(offlinePath_, ec);
    }

    void TearDown() override
    {
        std::error_code ec;
        fs::remove(offlinePath_, ec);
    }

    std::unique_ptr<PrivacyIDEA> makePI(long expiryDays = 30, const std::string &rpId = "")
    {
        return std::make_unique<PrivacyIDEA>(
            /*pamh=*/nullptr,
            /*baseURL=*/"https://example.test",
            /*realm=*/"",
            /*sslVerify=*/true,
            offlinePath_.string(),
            /*debug=*/false,
            /*timeout=*/0,
            expiryDays,
            /*caCertPath=*/"",
            rpId);
    }

    fs::path offlinePath_;
};

} // namespace

TEST_F(PrivacyIDEAFixture, ParseInitializeUvPreferredPopulatesSignRequest)
{
    auto pi = makePI();
    Response resp;
    int rc = pi->parseResponse(readFixture("initialize_uv_preferred.json"), resp);
    ASSERT_EQ(rc, 0);

    ASSERT_TRUE(resp.signRequest.has_value());
    EXPECT_EQ(resp.signRequest->challenge, "SPRITfnl8pStiyaHx4v0kgdmNy5HdLCUvBjIsd5PUV0");
    EXPECT_EQ(resp.signRequest->rpId, "cool.nils");
    EXPECT_EQ(resp.signRequest->transaction_id, "12052838135417104562");
    EXPECT_EQ(resp.signRequest->userVerification, "preferred");
    EXPECT_EQ(resp.signRequest->message, "Please authenticate with your passkey!");

    EXPECT_FALSE(resp.authenticationSuccess); // CHALLENGE, not ACCEPT
}

TEST_F(PrivacyIDEAFixture, ParseInitializeUvRequiredPropagatesUv)
{
    auto pi = makePI();
    Response resp;
    int rc = pi->parseResponse(readFixture("initialize_uv_required.json"), resp);
    ASSERT_EQ(rc, 0);

    ASSERT_TRUE(resp.signRequest.has_value());
    EXPECT_EQ(resp.signRequest->userVerification, "required");
}

TEST_F(PrivacyIDEAFixture, ParseCheckAccept)
{
    auto pi = makePI();
    Response resp;
    int rc = pi->parseResponse(readFixture("check_accept.json"), resp);
    ASSERT_EQ(rc, 0);

    EXPECT_TRUE(resp.authenticationSuccess);
    EXPECT_EQ(resp.username, "hans");
    EXPECT_FALSE(resp.signRequest.has_value());
}

TEST_F(PrivacyIDEAFixture, ParseCheckReject)
{
    auto pi = makePI();
    Response resp;
    int rc = pi->parseResponse(readFixture("check_reject.json"), resp);
    ASSERT_EQ(rc, 0);

    EXPECT_FALSE(resp.authenticationSuccess);
}

TEST_F(PrivacyIDEAFixture, ParseErrorResponseExtractsCodeAndMessage)
{
    auto pi = makePI();
    Response resp;
    int rc = pi->parseResponse(readFixture("check_error_403.json"), resp);
    ASSERT_EQ(rc, 0);

    EXPECT_EQ(resp.errorCode, 403);
    EXPECT_FALSE(resp.errorMessage.empty());
    EXPECT_NE(resp.errorMessage.find("not meant for the token"), std::string::npos);
}

TEST_F(PrivacyIDEAFixture, ParseAcceptWithOfflineStoresCredential)
{
    auto pi = makePI();
    Response resp;
    int rc = pi->parseResponse(readFixture("check_accept_with_offline.json"), resp);
    ASSERT_EQ(rc, 0);
    EXPECT_TRUE(resp.authenticationSuccess);

    auto all = pi->getAllOfflineCredentials();
    ASSERT_EQ(all.size(), 1u);

    const auto &cred = all.front();
    EXPECT_EQ(cred.serial, "PIPK0000BE5A");
    EXPECT_EQ(cred.username, "hans");
    EXPECT_EQ(cred.rpId, "cool.nils");
    EXPECT_EQ(cred.credId, "T9TJpDbUuq0TIdIpErltERuboEdR1GBa7pVtdYMQYTQZ582wmBwp5TWuZ_sE_Ag4");
    EXPECT_FALSE(cred.public_key_hex.empty());
    EXPECT_FALSE(cred.refilltoken.empty());
    EXPECT_EQ(cred.sign_count, 0u);
    EXPECT_FALSE(cred.expiry_timestamp.empty()); // 30 days default, so non-empty
}

TEST_F(PrivacyIDEAFixture, ParseAcceptWithOfflineExpiryDisabledLeavesTimestampEmpty)
{
    auto pi = makePI(/*expiryDays=*/0);
    Response resp;
    int rc = pi->parseResponse(readFixture("check_accept_with_offline.json"), resp);
    ASSERT_EQ(rc, 0);

    auto all = pi->getAllOfflineCredentials();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_TRUE(all.front().expiry_timestamp.empty());
}

TEST_F(PrivacyIDEAFixture, ParseAcceptWithOfflineUpdatesExistingCredential)
{
    // First ingest creates the credential.
    {
        auto pi = makePI();
        Response resp;
        ASSERT_EQ(pi->parseResponse(readFixture("check_accept_with_offline.json"), resp), 0);
    }

    // Second instance loads from disk and ingests again — should UPDATE, not duplicate.
    {
        auto pi = makePI();
        ASSERT_EQ(pi->getAllOfflineCredentials().size(), 1u);

        Response resp;
        ASSERT_EQ(pi->parseResponse(readFixture("check_accept_with_offline.json"), resp), 0);
        EXPECT_EQ(pi->getAllOfflineCredentials().size(), 1u);
    }
}

TEST_F(PrivacyIDEAFixture, FindOfflineCredentialsForUserFiltersBySerial)
{
    auto pi = makePI();
    Response resp;
    ASSERT_EQ(pi->parseResponse(readFixture("check_accept_with_offline.json"), resp), 0);

    auto hans = pi->findOfflineCredentialsForUser("hans");
    EXPECT_EQ(hans.size(), 1u);

    auto nobody = pi->findOfflineCredentialsForUser("nobody");
    EXPECT_TRUE(nobody.empty());

    auto byserial = pi->findOfflineCredential("PIPK0000BE5A");
    ASSERT_TRUE(byserial.has_value());
    EXPECT_EQ(byserial->username, "hans");

    auto missing = pi->findOfflineCredential("NOPE");
    EXPECT_FALSE(missing.has_value());
}

TEST_F(PrivacyIDEAFixture, UpdateSignCountPersistsAcrossInstances)
{
    {
        auto pi = makePI();
        Response resp;
        ASSERT_EQ(pi->parseResponse(readFixture("check_accept_with_offline.json"), resp), 0);
        pi->updateSignCount("PIPK0000BE5A", 42);
    }

    auto pi2 = makePI();
    auto cred = pi2->findOfflineCredential("PIPK0000BE5A");
    ASSERT_TRUE(cred.has_value());
    EXPECT_EQ(cred->sign_count, 42u);
}

TEST_F(PrivacyIDEAFixture, MalformedJsonReturnsError)
{
    auto pi = makePI();
    Response resp;
    EXPECT_NE(pi->parseResponse("this is not json {{{", resp), 0);
}

TEST_F(PrivacyIDEAFixture, EmptyObjectDoesNotCrash)
{
    auto pi = makePI();
    Response resp;
    EXPECT_EQ(pi->parseResponse("{}", resp), 0);
    EXPECT_FALSE(resp.signRequest.has_value());
    EXPECT_FALSE(resp.authenticationSuccess);
}

// Pin down type-safety guards: malformed-but-parseable responses with wrong
// JSON types must not throw out of parseResponse (which would be UB at the
// PAM C-linkage boundary).
TEST_F(PrivacyIDEAFixture, ResultErrorMissingFieldsDoesNotThrow)
{
    auto pi = makePI();
    Response resp;
    EXPECT_NO_THROW({
        int rc = pi->parseResponse(R"({"result":{"error":{}}})", resp);
        EXPECT_EQ(rc, 0);
    });
    EXPECT_EQ(resp.errorCode, 0);
    EXPECT_TRUE(resp.errorMessage.empty());
}

TEST_F(PrivacyIDEAFixture, ResultValueAsIntegerDoesNotThrow)
{
    // /validate/triggerchallenge returns "value": 2 — non-bool, would have
    // crashed the prior implementation.
    auto pi = makePI();
    Response resp;
    EXPECT_NO_THROW({
        int rc = pi->parseResponse(
            R"({"result":{"value":2,"authentication":"CHALLENGE"}})", resp);
        EXPECT_EQ(rc, 0);
    });
    EXPECT_FALSE(resp.authenticationSuccess);
}

TEST_F(PrivacyIDEAFixture, DetailUsernameAsObjectDoesNotThrow)
{
    // Some responses put rich user info under detail.user (an object) while
    // detail.username stays a string. A response where username is an object
    // (hypothetical schema drift) must not throw.
    auto pi = makePI();
    Response resp;
    EXPECT_NO_THROW({
        int rc = pi->parseResponse(R"({"detail":{"username":{"name":"hans"}}})", resp);
        EXPECT_EQ(rc, 0);
    });
    EXPECT_TRUE(resp.username.empty());
}

TEST_F(PrivacyIDEAFixture, PartialOfflineEntryIsSkippedNotCrashed)
{
    // auth_items.offline entry missing rpId / refilltoken — must be skipped.
    auto pi = makePI();
    Response resp;
    int rc = pi->parseResponse(R"({
        "result":{"value":true,"authentication":"ACCEPT"},
        "auth_items":{"offline":[
            {"user":"hans","serial":"X","response":{}}
        ]}
    })", resp);
    EXPECT_EQ(rc, 0);
    EXPECT_TRUE(pi->getAllOfflineCredentials().empty());
}

TEST_F(PrivacyIDEAFixture, ServerSuppliedOfflineCredentialWithMismatchedRpIdIsRejected)
{
    // The server response carries rpId "evil.example"; the PAM module is
    // configured for rpId "cool.nils". The credential MUST NOT be stored —
    // accepting it would let a hostile/misconfigured server seed credentials
    // that drive fido_assert_set_rp under a different RP at offline-verify
    // time.
    auto pi = makePI(/*expiryDays=*/30, /*rpId=*/"cool.nils");
    Response resp;
    int rc = pi->parseResponse(R"({
        "result":{"value":true,"authentication":"ACCEPT"},
        "auth_items":{"offline":[
            {"user":"hans","serial":"PIPK1","refilltoken":"t",
             "response":{"pubKey":"AA","credentialId":"BB","rpId":"evil.example"}}
        ]}
    })", resp);
    EXPECT_EQ(rc, 0);
    EXPECT_TRUE(resp.authenticationSuccess);
    EXPECT_TRUE(pi->getAllOfflineCredentials().empty())
        << "credential with foreign rpId was accepted";
}

TEST_F(PrivacyIDEAFixture, ServerSuppliedOfflineCredentialWithMatchingRpIdIsStored)
{
    // Companion to the rejection test: same shape, matching rpId, should land.
    auto pi = makePI(/*expiryDays=*/30, /*rpId=*/"cool.nils");
    Response resp;
    int rc = pi->parseResponse(R"({
        "result":{"value":true,"authentication":"ACCEPT"},
        "auth_items":{"offline":[
            {"user":"hans","serial":"PIPK1","refilltoken":"t",
             "response":{"pubKey":"AA","credentialId":"BB","rpId":"cool.nils"}}
        ]}
    })", resp);
    EXPECT_EQ(rc, 0);
    ASSERT_EQ(pi->getAllOfflineCredentials().size(), 1u);
    EXPECT_EQ(pi->getAllOfflineCredentials().front().rpId, "cool.nils");
}

TEST_F(PrivacyIDEAFixture, MalformedEntryInOfflineFileIsSkippedAtLoadTime)
{
    // Pre-seed the offline file with one valid entry and one entry missing
    // required fields (no `pubKey`). The malformed entry must be skipped at
    // load time without throwing out of the constructor, and the valid one
    // must survive.
    std::ofstream out(offlinePath_);
    out << R"({"schema_version":1,"fido_offline":[
        {"pubKey":"AA","username":"good","rpId":"cool.nils","credentialId":"C1",
         "serial":"S1","refilltoken":"t1","sign_count":0,"expiry_timestamp":""},
        {"username":"bad","rpId":"cool.nils","credentialId":"C2",
         "serial":"S2","refilltoken":"t2","sign_count":0,"expiry_timestamp":""}
    ]})";
    out.close();

    auto pi = makePI();
    auto creds = pi->getAllOfflineCredentials();
    ASSERT_EQ(creds.size(), 1u);
    EXPECT_EQ(creds.front().serial, "S1");
}

TEST_F(PrivacyIDEAFixture, OfflineFileWithFutureSchemaVersionIsRefused)
{
    // A file written by a future module version with an unknown
    // schema_version must be treated as unreadable, not silently mis-parsed.
    std::ofstream out(offlinePath_);
    out << R"({"schema_version":9999,"fido_offline":[
        {"pubKey":"AA","username":"x","rpId":"cool.nils","credentialId":"C1",
         "serial":"S1","refilltoken":"t1","sign_count":0,"expiry_timestamp":""}
    ]})";
    out.close();

    auto pi = makePI();
    EXPECT_TRUE(pi->getAllOfflineCredentials().empty());
}

TEST_F(PrivacyIDEAFixture, LegacyOfflineFileWithoutSchemaVersionLoads)
{
    // A pre-versioning (legacy) file has no schema_version key; treat it as
    // version 0 and load normally for backwards compatibility.
    std::ofstream out(offlinePath_);
    out << R"({"fido_offline":[
        {"pubKey":"AA","username":"x","rpId":"cool.nils","credentialId":"C1",
         "serial":"S1","refilltoken":"t1","sign_count":0,"expiry_timestamp":""}
    ]})";
    out.close();

    auto pi = makePI();
    ASSERT_EQ(pi->getAllOfflineCredentials().size(), 1u);
    EXPECT_EQ(pi->getAllOfflineCredentials().front().serial, "S1");
}

#include <gtest/gtest.h>
#include "convert.h"

namespace
{

std::vector<unsigned char> bytes(std::initializer_list<int> v)
{
    return std::vector<unsigned char>(v.begin(), v.end());
}

} // namespace

TEST(Base64Url, EncodeKnownVector)
{
    // RFC 4648 §10: "f" → "Zg", "fo" → "Zm8", "foo" → "Zm9v"
    auto in = bytes({'f', 'o', 'o'});
    EXPECT_EQ(Convert::Base64URLEncode(in), "Zm9v");
}

TEST(Base64Url, EncodeUsesUrlSafeAlphabet)
{
    // bytes that would produce '+' and '/' in standard base64 must become '-' and '_'.
    auto in = bytes({0xFB, 0xFF, 0xBF});
    auto out = Convert::Base64URLEncode(in);
    EXPECT_EQ(out.find('+'), std::string::npos);
    EXPECT_EQ(out.find('/'), std::string::npos);
}

TEST(Base64Url, DecodeUnpaddedInput)
{
    // The privacyIDEA server emits base64url without '=' padding (see spec
    // challenges like "SPRITfnl8pStiyaHx4v0kgdmNy5HdLCUvBjIsd5PUV0").
    auto out = Convert::Base64URLDecode("Zm9v");
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], 'f');
    EXPECT_EQ(out[1], 'o');
    EXPECT_EQ(out[2], 'o');
}

TEST(Base64Url, RoundTrip)
{
    auto original = bytes({0x00, 0x01, 0x02, 0xFE, 0xFF, 0x42, 0xAA});
    auto encoded = Convert::Base64URLEncode(original);
    auto decoded = Convert::Base64URLDecode(encoded);
    EXPECT_EQ(decoded, original);
}

TEST(Hex, RoundTrip)
{
    auto original = bytes({0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF});
    auto hex = Convert::BytesToHex(original);
    EXPECT_EQ(hex, "deadbeef00ff");

    auto round = Convert::HexToBytes(hex);
    EXPECT_EQ(round, original);
}

TEST(Hex, OddLengthThrows)
{
    EXPECT_THROW(Convert::HexToBytes("abc"), std::invalid_argument);
}

TEST(Hex, InvalidCharThrows)
{
    EXPECT_THROW(Convert::HexToBytes("zz"), std::invalid_argument);
}

TEST(UrlEncode, KeepsUnreservedChars)
{
    EXPECT_EQ(Convert::UrlEncode("AZaz09-_.~"), "AZaz09-_.~");
}

TEST(UrlEncode, PercentEncodesSpaceAndSpecial)
{
    EXPECT_EQ(Convert::UrlEncode("a b"), "a%20b");
    EXPECT_EQ(Convert::UrlEncode("+="), "%2B%3D");
}

TEST(Iso8601, RoundTrip)
{
    // 2024-01-15T12:34:56Z → fixed timestamp
    time_t t = 1705322096;
    auto iso = Convert::timeTToIso8601(t);
    EXPECT_EQ(iso, "2024-01-15T12:34:56Z");

    EXPECT_EQ(Convert::iso8601ToTimeT(iso), t);
}

TEST(Iso8601, EmptyStringReturnsZero)
{
    EXPECT_EQ(Convert::iso8601ToTimeT(""), 0);
}

TEST(Iso8601, ZeroTimestampReturnsEmpty)
{
    EXPECT_EQ(Convert::timeTToIso8601(0), "");
}

TEST(Iso8601, MalformedInputReturnsMinusOneSentinel)
{
    // Pre-versioning this returned 0, which the offline-expiry caller
    // mis-treated as "no expiry configured" — silently disabling expiry on
    // credentials with a corrupt timestamp. Now non-empty-but-unparseable
    // input returns (time_t)-1 so the caller can fail closed.
    EXPECT_EQ(Convert::iso8601ToTimeT("not a date"), static_cast<time_t>(-1));
}

#include <memory>
#include "convert.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <sstream>

std::vector<unsigned char> Convert::Base64Decode(const std::string &base64String)
{
    size_t decoded_len = (base64String.length() / 4) * 3; // Max possible length
    std::vector<unsigned char> decoded_data(decoded_len);

    int final_len = EVP_DecodeBlock(decoded_data.data(),
                                    reinterpret_cast<const unsigned char *>(base64String.c_str()),
                                    base64String.length());
    if (final_len < 0)
    {
        // Handle error, maybe log it
        return {};
    }
    // EVP_DecodeBlock counts trailing '=' as zero bytes in its returned length.
    // Strip them so the result reflects the actual decoded payload size.
    int padding = 0;
    for (auto it = base64String.rbegin(); it != base64String.rend() && *it == '='; ++it)
        ++padding;
    if (final_len < padding)
    {
        // Defensive: prevents underflow into a huge size_t if final_len ever
        // ends up smaller than padding (e.g. all-padding input "====").
        return {};
    }
    decoded_data.resize(final_len - padding);
    return decoded_data;
}

std::vector<unsigned char> Convert::Base64URLDecode(const std::string &base64URLString)
{
    std::string base64String = base64URLString;
    Base64URLToBase64(base64String);

    // Add padding if necessary
    size_t remainder = base64String.length() % 4;
    if (remainder != 0)
    {
        base64String.append(4 - remainder, '=');
    }

    return Base64Decode(base64String);
}

std::string Convert::Base64Encode(const unsigned char *data, const size_t size, bool padded)
{
    size_t encoded_len = 4 * ((size + 2) / 3);
    std::string encoded_string(encoded_len, '\0');
    int final_len = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(encoded_string.data()), data, size);
    if (final_len < 0)
    {
        // Handle error, maybe log it
        return "";
    }
    encoded_string.resize(final_len);
    // EVP_EncodeBlock always pads; honor padded=false by stripping trailing '='.
    if (!padded)
    {
        while (!encoded_string.empty() && encoded_string.back() == '=')
            encoded_string.pop_back();
    }
    return encoded_string;
}

std::string Convert::Base64Encode(const std::vector<unsigned char> &data, bool padded)
{
    return Base64Encode(data.data(), data.size(), padded);
}

std::string Convert::Base64URLEncode(const unsigned char *data, const size_t size, bool padded)
{
    std::string base64 = Base64Encode(data, size, padded);
    Base64ToBase64URL(base64);
    return base64;
}

std::string Convert::Base64URLEncode(const std::vector<unsigned char> &data, bool padded)
{
    return Base64URLEncode(data.data(), data.size(), padded);
}

std::string Convert::UrlEncode(const std::string &input)
{
    // Locale-independent: check ASCII unreserved characters per RFC 3986 by
    // explicit ranges. std::isalnum is locale-dependent and would behave
    // differently under non-C locales (e.g. tr_TR treating Turkish letters
    // as alphanumeric and emitting them raw).
    auto isUnreserved = [](unsigned char c) noexcept {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
               || c == '-' || c == '_' || c == '.' || c == '~';
    };

    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex << std::uppercase;

    for (unsigned char c : input)
    {
        if (isUnreserved(c))
        {
            escaped << static_cast<char>(c);
        }
        else
        {
            escaped << '%' << std::setw(2) << static_cast<int>(c);
        }
    }

    return escaped.str();
}

void Convert::Base64ToBase64URL(std::string &base64)
{
    std::replace(base64.begin(), base64.end(), '+', '-');
    std::replace(base64.begin(), base64.end(), '/', '_');
}

void Convert::Base64URLToBase64(std::string &base64URL)
{
    std::replace(base64URL.begin(), base64URL.end(), '-', '+');
    std::replace(base64URL.begin(), base64URL.end(), '_', '/');
}

std::string Convert::GenerateRandomAsBase64URL(size_t size)
{
    std::vector<unsigned char> buffer(size);
    if (RAND_bytes(buffer.data(), size) != 1)
    {
        // Error generating random bytes, OpenSSL error queue will have details.
        return "";
    }
    return Base64URLEncode(buffer, false);
}

std::string Convert::BytesToHex(const unsigned char *data, const size_t dataSize)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < dataSize; ++i)
    {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string Convert::BytesToHex(std::vector<unsigned char> bytes)
{
    return BytesToHex(bytes.data(), bytes.size());
}

std::vector<unsigned char> Convert::HexToBytes(const std::string &hexString)
{
    if (hexString.length() % 2 != 0)
    {
        throw std::invalid_argument("Hex string must have an even number of characters");
    }

    std::vector<unsigned char> bytes;
    bytes.reserve(hexString.length() / 2);

    for (size_t i = 0; i < hexString.length(); i += 2)
    {
        std::string byteString = hexString.substr(i, 2);
        try
        {
            unsigned long byteValue = std::stoul(byteString, nullptr, 16);
            bytes.push_back(static_cast<unsigned char>(byteValue));
        }
        catch (const std::invalid_argument &e)
        {
            throw std::invalid_argument("Invalid character in hex string");
        }
        catch (const std::out_of_range &e)
        {
            throw std::out_of_range("Hex value out of range for a byte");
        }
    }

    return bytes;
}

std::string Convert::timeTToIso8601(time_t timestamp)
{
    if (timestamp == 0)
    {
        return "";
    }
    // Thread-safe variant — PAM modules can be loaded into multi-threaded
    // daemons (e.g. sshd) where the static buffer used by std::gmtime is unsafe.
    std::tm gmt{};
    if (gmtime_r(&timestamp, &gmt) == nullptr)
    {
        return ""; // Error converting time
    }
    std::stringstream ss;
    ss << std::put_time(&gmt, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

time_t Convert::iso8601ToTimeT(const std::string &isoString)
{
    // Sentinels:
    //   0  → empty input, "no expiry configured"
    //  -1  → input was non-empty but failed to parse; the caller should treat
    //        this as expired so that a corrupt timestamp fails closed rather
    //        than silently disabling the expiry check on that credential.
    if (isoString.empty())
    {
        return 0;
    }
    std::tm t = {};
    std::istringstream ss(isoString);
    ss >> std::get_time(&t, "%Y-%m-%dT%H:%M:%SZ");
    if (ss.fail())
    {
        return static_cast<time_t>(-1);
    }
    return timegm(&t); // timegm is a non-standard but widely available GNU extension that correctly handles UTC.
}
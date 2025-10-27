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
    decoded_data.resize(final_len);
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
    int final_len = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&encoded_string[0]), data, size);
    if (final_len < 0)
    {
        // Handle error, maybe log it
        return "";
    }
    encoded_string.resize(final_len);
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
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (auto c : input)
    {
        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            escaped << c;
        }
        // Any other characters are percent-encoded
        else
        {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char)c);
            escaped << std::nouppercase;
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

void Convert::Base64ToABase64(std::string &base64)
{
    std::replace(base64.begin(), base64.end(), '.', '+');
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
    std::tm *gmt = std::gmtime(&timestamp);
    if (!gmt)
    {
        return ""; // Error converting time
    }
    std::stringstream ss;
    ss << std::put_time(gmt, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

time_t Convert::iso8601ToTimeT(const std::string &isoString)
{
    if (isoString.empty())
    {
        return 0;
    }
    std::tm t = {};
    std::istringstream ss(isoString);
    ss >> std::get_time(&t, "%Y-%m-%dT%H:%M:%SZ");
    if (ss.fail())
    {
        return 0; // Parsing failed
    }
    return timegm(&t); // timegm is a non-standard but widely available GNU extension that correctly handles UTC.
}
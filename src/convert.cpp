#include "convert.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <sstream>

std::vector<unsigned char> Convert::Base64Decode(const std::string& base64String)
{
    BIO* bio = BIO_new_mem_buf(base64String.c_str(), -1);
    if (!bio)
    {
        throw std::runtime_error("Failed to create memory buffer for Base64 decoding");
    }

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    std::vector<unsigned char> decodedData(base64String.length());
    int decodedLength = BIO_read(bio, decodedData.data(), decodedData.size());

    BIO_free_all(bio);

    if (decodedLength < 0)
    {
        throw std::runtime_error("Failed to decode Base64 string");
    }

    decodedData.resize(decodedLength);
    return decodedData;
}

std::vector<unsigned char> Convert::Base64URLDecode(const std::string& base64URLString)
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

std::string Convert::Base64Encode(const unsigned char* data, const size_t size, bool padded)
{
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    BIO_write(bio, data, size);
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encodedData(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);

    if (!padded)
    {
        encodedData.erase(std::remove(encodedData.begin(), encodedData.end(), '='), encodedData.end());
    }

    return encodedData;
}

std::string Convert::Base64Encode(const std::vector<unsigned char>& data, bool padded)
{
    return Base64Encode(data.data(), data.size(), padded);
}

std::string Convert::Base64URLEncode(const unsigned char* data, const size_t size, bool padded)
{
    std::string base64 = Base64Encode(data, size, padded);
    Base64ToBase64URL(base64);
    return base64;
}

std::string Convert::Base64URLEncode(const std::vector<unsigned char>& data, bool padded)
{
    return Base64URLEncode(data.data(), data.size(), padded);
}

void Convert::Base64ToBase64URL(std::string& base64)
{
    std::replace(base64.begin(), base64.end(), '+', '-');
    std::replace(base64.begin(), base64.end(), '/', '_');
}

void Convert::Base64URLToBase64(std::string& base64URL)
{
    std::replace(base64URL.begin(), base64URL.end(), '-', '+');
    std::replace(base64URL.begin(), base64URL.end(), '_', '/');
}

void Convert::Base64ToABase64(std::string& base64)
{
    std::replace(base64.begin(), base64.end(), '.', '+');
}

std::string Convert::BytesToHex(const unsigned char* data, const size_t dataSize)
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

std::vector<unsigned char> Convert::HexToBytes(const std::string& hexString)
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
        catch (const std::invalid_argument& e)
        {
            throw std::invalid_argument("Invalid character in hex string");
        }
        catch (const std::out_of_range& e)
        {
            throw std::out_of_range("Hex value out of range for a byte");
        }
    }

    return bytes;
}
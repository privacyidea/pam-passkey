#include "cose_key.h"
#include "convert.h"
#include <cbor.h>
#include <openssl/param_build.h>
#include <vector>

namespace
{
constexpr int COSE_ALG_KEY = 3;
constexpr int COSE_EC_X = -2;
constexpr int COSE_EC_Y = -3;
constexpr int COSE_ALG_ES256 = -7;
} // namespace

CoseKeyParseResult parseCoseKey(const std::string &cborInput, EVP_PKEY **pkey, int *algorithm)
{
    *pkey = nullptr;
    *algorithm = 0;

    std::vector<unsigned char> bytes;
    try
    {
        // Hex strings have even length; base64url encodings of an ES256
        // COSE_Key (77 bytes) are 103 characters, which is odd. Use that to
        // discriminate. Either decoder may throw on malformed input.
        if (cborInput.length() % 2 == 0)
            bytes = Convert::HexToBytes(cborInput);
        else
            bytes = Convert::Base64URLDecode(cborInput);
    }
    catch (const std::exception &)
    {
        return CoseKeyParseResult::InvalidCbor;
    }

    cbor_load_result loadRes = {};
    cbor_item_t *map = cbor_load(bytes.data(), bytes.size(), &loadRes);
    if (map == nullptr)
        return CoseKeyParseResult::InvalidCbor;
    if (!cbor_isa_map(map))
    {
        cbor_decref(&map);
        return CoseKeyParseResult::InvalidCbor;
    }

    const size_t size = cbor_map_size(map);
    cbor_pair *pairs = cbor_map_handle(map);

    int alg = 0;
    for (size_t i = 0; i < size; i++)
    {
        if (cbor_isa_uint(pairs[i].key) && cbor_get_uint8(pairs[i].key) == COSE_ALG_KEY
            && cbor_isa_negint(pairs[i].value))
        {
            alg = -1 - static_cast<int>(cbor_get_int(pairs[i].value));
            break;
        }
    }

    *algorithm = alg;
    if (alg != COSE_ALG_ES256)
    {
        cbor_decref(&map);
        return CoseKeyParseResult::UnsupportedAlgorithm;
    }

    std::vector<uint8_t> x, y;
    for (size_t i = 0; i < size; i++)
    {
        if (!cbor_isa_negint(pairs[i].key))
            continue;
        const int key = -1 - static_cast<int>(cbor_get_int(pairs[i].key));
        if (!cbor_isa_bytestring(pairs[i].value))
            continue;
        const uint8_t *handle = cbor_bytestring_handle(pairs[i].value);
        const size_t len = cbor_bytestring_length(pairs[i].value);
        if (key == COSE_EC_X)
            x.assign(handle, handle + len);
        else if (key == COSE_EC_Y)
            y.assign(handle, handle + len);
    }
    cbor_decref(&map);

    if (x.empty() || y.empty())
        return CoseKeyParseResult::InvalidCbor;

    // SEC1 uncompressed point: 0x04 || X || Y. OpenSSL 3 requires a single
    // OSSL_PKEY_PARAM_PUB_KEY entry; pushing X and Y as two "pub" entries makes
    // EVP_PKEY_fromdata return 0 with a null pkey.
    std::vector<uint8_t> pub;
    pub.reserve(1 + x.size() + y.size());
    pub.push_back(0x04);
    pub.insert(pub.end(), x.begin(), x.end());
    pub.insert(pub.end(), y.begin(), y.end());

    CoseKeyParseResult result = CoseKeyParseResult::OpenSslError;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (bld)
    {
        if (OSSL_PARAM_BLD_push_utf8_string(bld, "group", "prime256v1", 0)
            && OSSL_PARAM_BLD_push_octet_string(bld, "pub", pub.data(), pub.size()))
        {
            OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
            if (params)
            {
                EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
                if (ctx)
                {
                    if (EVP_PKEY_fromdata_init(ctx) > 0
                        && EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params) > 0
                        && *pkey != nullptr)
                    {
                        result = CoseKeyParseResult::Ok;
                    }
                    else
                    {
                        *pkey = nullptr;
                    }
                    EVP_PKEY_CTX_free(ctx);
                }
                OSSL_PARAM_free(params);
            }
        }
        OSSL_PARAM_BLD_free(bld);
    }
    return result;
}

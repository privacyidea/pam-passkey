// Repro: does pam-passkey's ecKeyFromCbor actually produce a correct EC
// public key, given it pushes X and Y as two separate "pub" octet strings?
//
// We replicate the production pattern verbatim, then export the resulting
// EVP_PKEY's "pub" param and compare against the canonical SEC1 uncompressed
// form (0x04 || X || Y). If the two produce different outputs, the production
// code is silently building a wrong key. If they match, OpenSSL is doing
// something more lenient than the docs suggest and I need to update my model.

#include <cbor.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

// The base64url-encoded COSE_Key blob captured in passkey.md test_08 Call 2.
static const char *SPEC_PUBKEY_B64URL =
    "a50102032620012158203f98500ddcedc3aa16d34ae9b7c12f71fa04d37b8af28e7c59d4e733880375fb22582068aa8c921ffc5fa5629bac23e864aaf7fcde0af0d480929e4eea3e37193f8f3d";

static std::vector<unsigned char> b64url_decode(const std::string &in)
{
    std::string s = in;
    std::replace(s.begin(), s.end(), '-', '+');
    std::replace(s.begin(), s.end(), '_', '/');
    while (s.size() % 4) s += '=';

    std::vector<unsigned char> out(s.size());
    int n = EVP_DecodeBlock(out.data(),
                            reinterpret_cast<const unsigned char *>(s.data()),
                            s.size());
    if (n < 0) { std::fprintf(stderr, "b64 decode failed\n"); std::exit(1); }
    int pad = 0;
    for (auto it = s.rbegin(); it != s.rend() && *it == '='; ++it) ++pad;
    out.resize(n - pad);
    return out;
}

static void hex(const char *label, const unsigned char *data, size_t len)
{
    std::printf("%-30s (%2zu bytes): ", label, len);
    for (size_t i = 0; i < len; ++i) std::printf("%02x", data[i]);
    std::printf("\n");
}

static void extract_x_y(const std::vector<unsigned char> &cborBytes,
                        std::vector<uint8_t> &x, std::vector<uint8_t> &y)
{
    cbor_load_result result = {};
    cbor_item_t *map = cbor_load(cborBytes.data(), cborBytes.size(), &result);
    if (!map || !cbor_isa_map(map)) {
        std::fprintf(stderr, "CBOR parse failed\n");
        std::exit(1);
    }
    size_t sz = cbor_map_size(map);
    cbor_pair *pairs = cbor_map_handle(map);
    for (size_t i = 0; i < sz; ++i) {
        if (cbor_isa_negint(pairs[i].key)) {
            int key = -1 - cbor_get_int(pairs[i].key);
            if (key == -2 && cbor_isa_bytestring(pairs[i].value)) {
                x.assign(cbor_bytestring_handle(pairs[i].value),
                         cbor_bytestring_handle(pairs[i].value) + cbor_bytestring_length(pairs[i].value));
            } else if (key == -3 && cbor_isa_bytestring(pairs[i].value)) {
                y.assign(cbor_bytestring_handle(pairs[i].value),
                         cbor_bytestring_handle(pairs[i].value) + cbor_bytestring_length(pairs[i].value));
            }
        }
    }
    cbor_decref(&map);
}

// Construct EVP_PKEY using the EXACT production pattern from ecKeyFromCbor.
static EVP_PKEY *build_pkey_production_pattern(const std::vector<uint8_t> &x,
                                               const std::vector<uint8_t> &y)
{
    EVP_PKEY *pkey = nullptr;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, "group", "prime256v1", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, "pub", x.data(), x.size());  // <-- X as "pub"
    OSSL_PARAM_BLD_push_octet_string(bld, "pub", y.data(), y.size());  // <-- Y as "pub" (same key!)

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    int init_ok = EVP_PKEY_fromdata_init(ctx);
    int fromdata_ok = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);

    std::printf("[production pattern] init=%d fromdata=%d pkey=%p\n",
                init_ok, fromdata_ok, (void*)pkey);

    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return pkey;
}

// Construct EVP_PKEY using the canonical SEC1 uncompressed form: 0x04 || X || Y.
static EVP_PKEY *build_pkey_sec1_uncompressed(const std::vector<uint8_t> &x,
                                              const std::vector<uint8_t> &y)
{
    std::vector<uint8_t> point;
    point.push_back(0x04);
    point.insert(point.end(), x.begin(), x.end());
    point.insert(point.end(), y.begin(), y.end());

    EVP_PKEY *pkey = nullptr;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, "group", "prime256v1", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, "pub", point.data(), point.size());

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    int init_ok = EVP_PKEY_fromdata_init(ctx);
    int fromdata_ok = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);

    std::printf("[sec1 uncompressed]  init=%d fromdata=%d pkey=%p\n",
                init_ok, fromdata_ok, (void*)pkey);

    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return pkey;
}

static void dump_pkey_pub(const char *label, EVP_PKEY *pkey)
{
    if (!pkey) { std::printf("%-30s: pkey is null\n", label); return; }
    unsigned char buf[256];
    size_t out_len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, "pub", buf, sizeof(buf), &out_len) == 1) {
        hex(label, buf, out_len);
    } else {
        std::printf("%-30s: get_octet_string_param failed\n", label);
    }
}

static std::vector<unsigned char> hex_decode(const std::string &s)
{
    std::vector<unsigned char> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<unsigned char>(std::stoul(s.substr(i, 2), nullptr, 16)));
    }
    return out;
}

int main()
{
    std::string in = SPEC_PUBKEY_B64URL;
    // Match the production decoder: hex if even-length and all-hex, else base64url.
    bool isHex = (in.size() % 2 == 0) &&
                 std::all_of(in.begin(), in.end(),
                             [](char c){ return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'); });
    auto cborBytes = isHex ? hex_decode(in) : b64url_decode(in);
    std::printf("Decoded as %s, CBOR blob: %zu bytes\n", isHex ? "hex" : "base64url", cborBytes.size());

    std::vector<uint8_t> x, y;
    extract_x_y(cborBytes, x, y);
    hex("X coordinate", x.data(), x.size());
    hex("Y coordinate", y.data(), y.size());
    std::printf("\n");

    EVP_PKEY *pkey_prod = build_pkey_production_pattern(x, y);
    EVP_PKEY *pkey_sec1 = build_pkey_sec1_uncompressed(x, y);
    std::printf("\n");

    dump_pkey_pub("Exported pub (production)", pkey_prod);
    dump_pkey_pub("Exported pub (SEC1)", pkey_sec1);

    EVP_PKEY_free(pkey_prod);
    EVP_PKEY_free(pkey_sec1);
    return 0;
}

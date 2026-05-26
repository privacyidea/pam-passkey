/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2025 NetKnights GmbH
** Author: Nils Behlen
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */

#ifndef PRIVACYIDEA_PAM_COSE_KEY_H
#define PRIVACYIDEA_PAM_COSE_KEY_H

#include <string>
#include <openssl/evp.h>

enum class CoseKeyParseResult
{
    Ok,
    InvalidCbor,
    UnsupportedAlgorithm,
    OpenSslError
};

// Parse a COSE_Key CBOR blob (hex- or base64url-encoded) into an EVP_PKEY.
// On success, *pkey is set to a newly allocated EVP_PKEY (caller frees with
// EVP_PKEY_free) and *algorithm to the COSE algorithm identifier (e.g. -7 for
// ES256). On failure, *pkey is set to nullptr.
//
// Currently only ES256 (alg -7, P-256 EC key) is supported.
CoseKeyParseResult parseCoseKey(const std::string &cborInput, EVP_PKEY **pkey, int *algorithm);

#endif // PRIVACYIDEA_PAM_COSE_KEY_H

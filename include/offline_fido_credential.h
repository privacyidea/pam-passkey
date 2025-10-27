#ifndef OFFLINE_FIDO_CREDENTIAL_H
#define OFFLINE_FIDO_CREDENTIAL_H

#include <string>

struct OfflineFIDOCredential
{
    std::string public_key_hex;
    std::string username;
    std::string rpId;
    std::string credId;
    std::string serial;
    uint32_t sign_count = 0;
};

#endif // OFFLINE_FIDO_CREDENTIAL_H
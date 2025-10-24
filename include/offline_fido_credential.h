#ifndef OFFLINE_FIDO_CREDENTIAL_H
#define OFFLINE_FIDO_CREDENTIAL_H

#include <string>

struct OfflineFIDOCredential
{
    std::string public_key_hex;
};

#endif // OFFLINE_FIDO_CREDENTIAL_H
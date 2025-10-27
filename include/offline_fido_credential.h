#ifndef OFFLINE_FIDO_CREDENTIAL_H
#define OFFLINE_FIDO_CREDENTIAL_H

#include <string>

struct OfflineFIDOCredential
{
    std::string public_key_hex;
    std::string username;
    std::string rpId; // rpId is part of the offline credential data
    std::string credId;
    std::string serial;
    std::string refilltoken; // Added for offline validation/refresh
    uint32_t sign_count = 0;
    std::string expiry_timestamp = ""; // ISO 8601 string. Empty means no expiry.
};

#endif // OFFLINE_FIDO_CREDENTIAL_H
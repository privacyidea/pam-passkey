#ifndef RESPONSE_H
#define RESPONSE_H

#include <optional>
#include <string>
#include "fido_sign_request.h"

struct Response
{
     // In case of a passkey challenge, this will be set
    std::optional<FIDOSignRequest> signRequest;

    std::string errorMessage;
    int errorCode;
    std::string username = "";
    bool authenticationSuccess = false;
};

#endif // RESPONSE_H
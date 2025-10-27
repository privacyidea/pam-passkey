#ifndef FIDO_SIGN_REQUEST_H
#define FIDO_SIGN_REQUEST_H

#include <string>
#include <vector>

struct FIDOSignRequest
{
	std::string challenge;
	std::string message;
	std::string rpId;
	std::string transaction_id;
	std::string userVerification;
	std::vector<std::string> allowedCredentials;
};

#endif // FIDO_SIGN_REQUEST_H
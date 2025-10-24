#ifndef FIDO_SIGN_REQUEST_H
#define FIDO_SIGN_REQUEST_H

#include <string>

struct FIDOSignRequest
{
	std::string challenge;
	std::string message;
	std::string rpId;
	std::string transaction_id;
	std::string user_verification;
};

#endif // FIDO_SIGN_REQUEST_H
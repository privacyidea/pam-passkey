#ifndef FIDO_SIGN_RESPONSE_H
#define FIDO_SIGN_RESPONSE_H

#include <string>

struct FIDOSignResponse
{
	std::string credentialid;
	std::string clientdata;
	std::string authenticatordata;
	std::string signaturedata;
	std::string userHandle;
};

#endif // FIDO_SIGN_RESPONSE_H
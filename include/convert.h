#ifndef CONVERT_H
#define CONVERT_H

#include <string>
#include <vector>

class Convert
{
public:
	static std::vector<unsigned char> Base64Decode(const std::string& base64String);
	static std::vector<unsigned char> Base64URLDecode(const std::string &base64String);
	static std::string Base64Encode(const unsigned char *data, const size_t size, bool padded = false);
	static std::string Base64Encode(const std::vector<unsigned char> &data, bool padded = false);
	static std::string Base64URLEncode(const unsigned char *data, const size_t size, bool padded = false);
	static std::string Base64URLEncode(const std::vector<unsigned char> &data, bool padded = false);
	static std::string UrlEncode(const std::string &input);
	static std::string GenerateRandomAsBase64URL(size_t size);

	// replace '+' with '-' and '/' with '_'
	static void Base64ToBase64URL(std::string &base64);
	// replace '-' with '+' and '_' with '/'
	static void Base64URLToBase64(std::string &base64URL);

	// Replaces '.' with '+'.
	static void Base64ToABase64(std::string &base64);

	static std::string BytesToHex(const unsigned char *data, const size_t dataSize);
	static std::string BytesToHex(std::vector<unsigned char> bytes);

	static std::vector<unsigned char> HexToBytes(const std::string &hexString);
};
#endif // CONVERT_H
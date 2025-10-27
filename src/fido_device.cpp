#include <fido/es256.h>
#include <algorithm>
#include <security/pam_ext.h> // For pam_syslog
#include <cbor.h>
#include "fido_device.h"
#include "privacyidea.h"
#include "convert.h"
#include <sys/syslog.h>

struct FidoDevDeleter
{
	void operator()(fido_dev_t *dev) const
	{
		if (dev)
		{
			fido_dev_close(dev);
			fido_dev_free(&dev);
		}
	}
};
using unique_fido_dev_t = std::unique_ptr<fido_dev_t, FidoDevDeleter>;

struct FidoAssertDeleter
{
	void operator()(fido_assert_t *a) const
	{
		if (a)
			fido_assert_free(&a);
	}
};
using unique_fido_assert_t = std::unique_ptr<fido_assert_t, FidoAssertDeleter>;

	// Forward declarations for functions used in this file
	constexpr auto cosePubKeyAlg = 3;
	constexpr auto cosePubKeyX = -2;
	constexpr auto cosePubKeyY = -3;
	constexpr auto cosePubKeyE = -2;
	constexpr auto cosePubKeyN = -1;

	int FIDODevice::ecKeyFromCbor(
		const std::string &cborPubKey,
		EC_KEY **ecKey,
		int *algorithm) const
	{
		int res = FIDO_OK;
		std::vector<unsigned char> pubKeyBytes;
		if (cborPubKey.length() % 2 == 0)
		{
			// hex encoded
			pubKeyBytes = Convert::HexToBytes(cborPubKey);
		}
		else
		{
			pubKeyBytes = Convert::Base64URLDecode(cborPubKey);
		}

		struct cbor_load_result result;
		cbor_item_t *map = cbor_load(pubKeyBytes.data(), pubKeyBytes.size(), &result);

		if (map == NULL)
		{
			pam_syslog(_pamh, LOG_ERR, "Failed to parse CBOR public key");
			return FIDO_ERR_INVALID_ARGUMENT;
		}
		if (!cbor_isa_map(map))
		{
			pam_syslog(_pamh, LOG_ERR, "CBOR public key is not a map");
			cbor_decref(&map);
			return FIDO_ERR_INVALID_ARGUMENT;
		}

		size_t size = cbor_map_size(map);
		cbor_pair *pairs = cbor_map_handle(map);
		// cbor_map
		//  Find the algorithm
		int alg = 0;
		for (int i = 0; i < size; i++)
		{
			if (cbor_isa_uint(pairs[i].key) && cbor_get_uint8(pairs[i].key) == cosePubKeyAlg)
			{
				if (cbor_isa_negint(pairs[i].value))
				{
					alg = -1 - cbor_get_int(pairs[i].value);
				}
			}
		}

		// Depending on the algorithm, find the values to build the public key
		if (alg == COSE_ES256)
		{
			*algorithm = alg;
			std::vector<uint8_t> x, y;
			for (int i = 0; i < size; i++)
			{
				if (cbor_isa_negint(pairs[i].key))
				{
					int key = -1 - cbor_get_int(pairs[i].key);
					if (key == cosePubKeyX)
					{
						if (cbor_isa_bytestring(pairs[i].value))
						{
							x = std::vector<uint8_t>(cbor_bytestring_handle(pairs[i].value), cbor_bytestring_handle(pairs[i].value) + cbor_bytestring_length(pairs[i].value));
						}
					}
					else if (key == cosePubKeyY)
					{
						if (cbor_isa_bytestring(pairs[i].value))
						{
							y = std::vector<uint8_t>(cbor_bytestring_handle(pairs[i].value), cbor_bytestring_handle(pairs[i].value) + cbor_bytestring_length(pairs[i].value));
						}
					}
				}
			}

			if (x.size() != 32)
			{
				pam_syslog(_pamh, LOG_ERR, "cosePubKeyX has the wrong size. Expected 32, actual: %zu", x.size());
				cbor_decref(&map);
				return FIDO_ERR_INVALID_ARGUMENT;
			}
			if (y.size() != 32)
			{
				pam_syslog(_pamh, LOG_ERR, "cosePubKeyY has the wrong size. Expected 32, actual: %zu", y.size());
				cbor_decref(&map);
				return FIDO_ERR_INVALID_ARGUMENT;
			}

			// secp256r1 is called prime256v1 in OpenSSL (RFC 5480, Section 2.1.1.1)
			*ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
			BIGNUM *bnx = BN_new();
			BN_bin2bn(x.data(), x.size(), bnx);
			BIGNUM *bny = BN_new();
			BN_bin2bn(y.data(), y.size(), bny);
			EC_KEY_set_public_key_affine_coordinates(*ecKey, bnx, bny);
			BN_free(bnx);
			BN_free(bny);
		}
		else
		{
			// TODO implement other COSE algorithms if supported by privacyIDEA
			pam_syslog(_pamh, LOG_ERR, "Unimplemented alg: %d", alg);
			res = FIDO_ERR_INVALID_ARGUMENT;
		}

		cbor_decref(&map);
		return res;
	}

	static unique_fido_dev_t OpenFidoDevice(pam_handle_t* pamh, const std::string &devicePath, int &outError)
	{
		outError = FIDO_OK;
		if (devicePath.empty())
		{
			pam_syslog(pamh, LOG_ERR, "No device path provided");
			outError = FIDO_ERR_INVALID_ARGUMENT;
			return nullptr;
		}

		unique_fido_dev_t dev(fido_dev_new());
		if (!dev)
		{
			pam_syslog(pamh, LOG_ERR, "fido_dev_new failed.");
			outError = FIDO_ERR_INTERNAL;
			return nullptr;
		}

		int res = fido_dev_open(dev.get(), devicePath.c_str());
		if (res != FIDO_OK)
		{
			pam_syslog(pamh, LOG_ERR, "fido_dev_open: %s (code: %d)", fido_strerr(res), res);
			outError = FIDO_ERR_INTERNAL;
			return nullptr;
		}

		return dev;
	}

std::vector<FIDODevice> FIDODevice::getDevices(pam_handle_t* pamh, bool log)
{
	if (log)
	{
		pam_syslog(pamh, LOG_DEBUG, "Searching for connected FIDO devices");
	}
	std::vector<FIDODevice> ret;
	size_t ndevs;
	int res = FIDO_OK;
	fido_dev_info_t *deviceList = nullptr;
	if ((deviceList = fido_dev_info_new(64)) == nullptr)
	{
		pam_syslog(pamh, LOG_ERR, "fido_dev_info_new returned NULL");
		return ret;
	}

	if ((res = fido_dev_info_manifest(deviceList, 64, &ndevs)) != FIDO_OK)
	{
		std::string fidoStrerr = fido_strerr(res);
		pam_syslog(pamh, LOG_ERR, "fido_dev_info_manifest: %s (code: %d)", fidoStrerr.c_str(), res);
		return ret;
	}

	for (size_t i = 0; i < ndevs; i++)
	{
		const fido_dev_info_t *di = fido_dev_info_ptr(deviceList, i);
		ret.emplace_back(pamh, di, log);
	}
	if (log)
	{
		pam_syslog(pamh, LOG_DEBUG, "Found %zu FIDO device(s)", ret.size());
	}
	return ret;
}

int FIDODevice::signAndVerifyAssertion(
	std::vector<OfflineFIDOCredential>& offlineData,
	const std::string& origin,
	const std::string& pin,
	std::string& serialUsed,
	uint32_t &newSignCount) const
{
	// Make a signRequest from the offlineData
	FIDOSignRequest signRequest;
	signRequest.rpId = offlineData.front().rpId;
	signRequest.challenge = Convert::GenerateRandomAsBase64URL(OFFLINE_CHALLENGE_SIZE);
	for (auto& item : offlineData)
	{
		if (item.rpId != signRequest.rpId)
		{
			pam_syslog(_pamh, LOG_ERR, "Offline data for ID %s has different rpId. Expected: %s, actual: %s", item.credId.c_str(), signRequest.rpId.c_str(), item.rpId.c_str());
			pam_syslog(_pamh, LOG_ERR, "The data will not be used for offline authentication");
		}
		else
		{
			signRequest.allowedCredentials.push_back(item.credId);
		}
	}

	fido_assert_t* assert = nullptr;
	std::vector<unsigned char> cDataBytes;
	int res = getAssert(signRequest, origin, pin, &assert, cDataBytes);

	EC_KEY* ecKey = nullptr;
	es256_pk_t* pk = es256_pk_new();
	int algorithm = 0;

	if (res == FIDO_OK)
	{
		// Find the credential which signed the assert and use it's public key to verify the signature
		auto pbId = fido_assert_id_ptr(assert, 0);
		auto cbId = fido_assert_id_len(assert, 0);
		auto idUsed = Convert::Base64URLEncode(pbId, cbId);
		
		OfflineFIDOCredential* credUsed = nullptr;
		for (auto& item : offlineData)
		{
			if (item.credId == idUsed)
			{
				credUsed = &item;
				serialUsed = item.serial;
				break;
			}
		}

		if (credUsed == nullptr)
		{
			pam_syslog(_pamh, LOG_ERR, "No offline credential found for the credential ID used for signing.");
			return FIDO_ERR_INVALID_ARGUMENT;
		}

		res = ecKeyFromCbor(credUsed->public_key_hex, &ecKey, &algorithm);
		if (ecKey == nullptr)
		{
			pam_syslog(_pamh, LOG_ERR, "Failed to create EC_KEY from public key CBOR.");
			return FIDO_ERR_INTERNAL;
		}

		// TODO other algorithms if privacyidea supports them
		if (algorithm != COSE_ES256)
		{
			pam_syslog(_pamh, LOG_ERR, "Unsupported algorithm: %d", algorithm);
			return FIDO_ERR_UNSUPPORTED_OPTION;
		}

		res = es256_pk_from_EC_KEY(pk, ecKey);
		if (res == FIDO_OK)
		{
			res = fido_assert_verify(assert, 0, algorithm, pk);
			if (res == FIDO_OK)
			{
				uint32_t new_sigcount = fido_assert_sigcount(assert, 0);
				if (new_sigcount > credUsed->sign_count)
				{
					pam_syslog(_pamh, LOG_DEBUG, "Offline assertion verified successfully! New signature count: %u (was %u)", new_sigcount, credUsed->sign_count);
					newSignCount = new_sigcount;
				}
				else
				{
					pam_syslog(_pamh, LOG_ERR, "Signature counter did not increase. Possible replay attack. New: %u, Old: %u", new_sigcount, credUsed->sign_count);
					res = FIDO_ERR_INVALID_SIG; // Or a more specific error
				}
			}
			else
			{
				pam_syslog(_pamh, LOG_ERR, "fido_assert_verify: %s (code: %d)", fido_strerr(res), res);
			}
		}
		else
		{
			pam_syslog(_pamh, LOG_ERR, "es256_pk_from_EC_KEY: %s (code: %d)", fido_strerr(res), res);
		}
	}
	else
	{
		pam_syslog(_pamh, LOG_ERR, "fido_dev_get_assert: %s (code: %d)", fido_strerr(res), res);
	}

	if (pk)
	{
		es256_pk_free(&pk);
	}
	if (ecKey)
	{
		EC_KEY_free(ecKey);
	}
	if (assert)
	{
		fido_assert_free(&assert);
	}

	return res;
}


FIDODevice::FIDODevice(pam_handle_t* pamh, const fido_dev_info_t *devinfo, bool log) : _pamh(pamh),
																					   _path(fido_dev_info_path(devinfo)),
																   _manufacturer(fido_dev_info_manufacturer_string(devinfo)),
																   _product(fido_dev_info_product_string(devinfo))
{
	unique_fido_dev_t dev(fido_dev_new_with_info(devinfo));
	if (dev != NULL)
	{
		_hasPin = fido_dev_has_pin(dev.get());
		_hasUV = fido_dev_has_uv(dev.get());
		if (log) pam_syslog(pamh, LOG_DEBUG, "New FIDO device: %s hasPin: %d", toString().c_str(), _hasPin);
	}
}

std::string FIDODevice::toString() const
{
	return "[" + _manufacturer + "][" + _product + "][" + _path + "]";
}

int FIDODevice::sign(
	const FIDOSignRequest &signRequest,
	const std::string &origin,
	const std::string &pin,
	FIDOSignResponse &signResponse) const
{
	fido_assert_t *assert = nullptr;
	std::vector<unsigned char> vecClientData;
	int res = getAssert(signRequest, origin, pin, &assert, vecClientData);

	if (res != FIDO_OK)
	{
		pam_syslog(_pamh, LOG_DEBUG, "fido_dev_get_assert: %s (code: %d)", fido_strerr(res), res);
	}

	if (res == FIDO_OK)
	{
		signResponse.clientdata = Convert::Base64URLEncode(vecClientData);

		auto pbId = fido_assert_id_ptr(assert, 0);
		auto cbId = fido_assert_id_len(assert, 0);
		signResponse.credentialid = Convert::Base64URLEncode(pbId, cbId);

		auto pbAuthData = fido_assert_authdata_raw_ptr(assert, 0);
		auto cbAuthData = fido_assert_authdata_raw_len(assert, 0);
		signResponse.authenticatordata = Convert::Base64URLEncode(pbAuthData, cbAuthData);

		auto pbSig = fido_assert_sig_ptr(assert, 0);
		auto cbSig = fido_assert_sig_len(assert, 0);
		signResponse.signaturedata = Convert::Base64URLEncode(pbSig, cbSig);

		auto pbUserHandle = fido_assert_user_id_ptr(assert, 0);
		auto cbUserHandle = fido_assert_user_id_len(assert, 0);
		signResponse.userHandle = Convert::Base64URLEncode(pbUserHandle, cbUserHandle);
	}

	fido_assert_free(&assert);

	return res;
}

int FIDODevice::getAssert(
	const FIDOSignRequest& signRequest,
	const std::string& origin,
	const std::string& pin,
	fido_assert_t** assert,
	std::vector<unsigned char>& clientDataOut) const
{
	int res = FIDO_OK;
	pam_syslog(_pamh, LOG_ERR, "getAssert: OpenFidoDevice");
	auto dev = OpenFidoDevice(_pamh, _path, res);
	pam_syslog(_pamh, LOG_ERR, "getAssert: device opened");

	if (res != FIDO_OK)
	{
		pam_syslog(_pamh, LOG_ERR, "getAssert: OpenFidoDevice failed with error %d", res);
		return res;
	}

	// Create assertion
	if ((*assert = fido_assert_new()) == NULL)
	{
		pam_syslog(_pamh, LOG_ERR, "getAssert: fido_assert_new failed");
		fido_dev_close(dev.get());
		return FIDO_ERR_INTERNAL;
	}

	std::string challenge = signRequest.challenge;
	std::vector<unsigned char> bytes(signRequest.challenge.begin(), signRequest.challenge.end());
	challenge = Convert::Base64URLEncode(bytes.data(), bytes.size());
	pam_syslog(_pamh, LOG_ERR, "challenge encoded: %s", challenge.c_str());
	std::string cData = "{\"type\": \"webauthn.get\", \"challenge\": \"" + challenge + "\", \"origin\": \"" + origin + "\", \"crossOrigin\": false}";
	clientDataOut = std::vector<unsigned char>(cData.begin(), cData.end());
	pam_syslog(_pamh, LOG_ERR, "getAssert: clientdataout set");
	res = fido_assert_set_clientdata(*assert, clientDataOut.data(), clientDataOut.size());
	if (res != FIDO_OK)
	{
		pam_syslog(_pamh, LOG_DEBUG, "fido_assert_set_clientdata: %s (code: %d)", fido_strerr(res), res);
	}
	pam_syslog(_pamh, LOG_ERR, "getAssert: client data set");
	// RP
	res = fido_assert_set_rp(*assert, signRequest.rpId.c_str());
	if (res != FIDO_OK)
	{
		pam_syslog(_pamh, LOG_DEBUG, "fido_assert_set_rp: %s (code: %d)", fido_strerr(res), res);
	}

	// User verification
	bool hasUV = fido_dev_has_uv(dev.get());
	pam_syslog(_pamh, LOG_DEBUG, "Device has user verification: %d and request is: %s", hasUV, signRequest.userVerification.c_str());

	if (hasUV && signRequest.userVerification == "discouraged")
	{
		res = fido_assert_set_uv(*assert, FIDO_OPT_FALSE);
		if (res != FIDO_OK)
		{
			pam_syslog(_pamh, LOG_DEBUG, "fido_assert_set_uv: %s (code: %d)", fido_strerr(res), res);
		}
		else
		{
			pam_syslog(_pamh, LOG_DEBUG, "User verification set to 'discouraged'");
		}
	}
	// Get assert and close
	return fido_dev_get_assert(dev.get(), *assert, pin.empty() ? NULL : pin.c_str());
}

int FIDODevice::getDetails()
{
	if (_path.empty())
	{
		pam_syslog(_pamh, LOG_ERR, "No device path provided");
		return FIDO_ERR_INVALID_ARGUMENT;
	}

	int res = FIDO_OK;
	unique_fido_dev_t dev(fido_dev_new());
	if (dev == nullptr)
	{
		pam_syslog(_pamh, LOG_ERR, "fido_dev_new failed.");
		return FIDO_ERR_INTERNAL;
	}

	res = fido_dev_open(dev.get(), _path.c_str());
	if (res != FIDO_OK)
	{
		pam_syslog(_pamh, LOG_ERR, "fido_dev_open: %s (code: %d)", fido_strerr(res), res);
		return FIDO_ERR_INTERNAL;
	}

	// Get info
	fido_cbor_info_t *info = fido_cbor_info_new();
	if (info == nullptr)
	{
		pam_syslog(_pamh, LOG_ERR, "Unable to allocate memory for fido_cbor_info_t!");
		res = FIDO_ERR_INTERNAL;
	}
	// This call may block
	res = fido_dev_get_cbor_info(dev.get(), info);
	if (res != FIDO_OK)
	{
		pam_syslog(_pamh, LOG_ERR, "fido_dev_get_cbor_info: %s (code: %d)", fido_strerr(res), res);
		res = FIDO_ERR_INTERNAL;
	}

	if (res == FIDO_OK)
	{
		// Algorithms
		size_t nalg = fido_cbor_info_algorithm_count(info);
		for (size_t i = 0; i < nalg; i++)
		{
			auto alg = fido_cbor_info_algorithm_cose(info, i);
			_supportedAlgorithms.push_back(alg);
		}
		// Remaining Resident Keys
		auto remainingResidentKeys = fido_cbor_info_rk_remaining(info);
		if (remainingResidentKeys == -1)
		{
			pam_syslog(_pamh, LOG_DEBUG, "Authenticator can not report remaining resident keys");
		}
		else
		{
			_remainingResidentKeys = remainingResidentKeys;
		}
		// New PIN required
		_newPinRequired = fido_cbor_info_new_pin_required(info);
	}

	fido_cbor_info_free(&info);
	return 0;
}

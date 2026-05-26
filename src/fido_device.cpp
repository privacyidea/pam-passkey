#include <fido/es256.h>
#include <fido/param.h>
#include <algorithm>
#include <security/pam_ext.h> // For pam_syslog
#include "fido_device.h"
#include "privacyidea.h"
#include "convert.h"
#include "cose_key.h"
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

struct EvpPkeyDeleter
{
	void operator()(EVP_PKEY *pkey) const
	{
		if (pkey)
			EVP_PKEY_free(pkey);
	}
};
using unique_evp_pkey_t = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

struct Es256PkDeleter
{
	void operator()(es256_pk_t *pk) const
	{
		if (pk)
			es256_pk_free(&pk);
	}
};
using unique_es256_pk_t = std::unique_ptr<es256_pk_t, Es256PkDeleter>;

struct BIGNUMDeleter
{
	void operator()(BIGNUM *bn) const
	{
		if (bn)
			BN_free(bn);
	}
};
using unique_bignum_t = std::unique_ptr<BIGNUM, BIGNUMDeleter>;

constexpr size_t MAX_FIDO_DEVICES = 64;

struct FidoDevInfoDeleter
{
	void operator()(fido_dev_info_t *list) const
	{
		if (list)
			fido_dev_info_free(&list, MAX_FIDO_DEVICES);
	}
};
using unique_fido_dev_info_t = std::unique_ptr<fido_dev_info_t, FidoDevInfoDeleter>;


static unique_fido_dev_t OpenFidoDevice(pam_handle_t *pamh, const std::string &devicePath, int &outError)
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

std::vector<FIDODevice> FIDODevice::getDevices(pam_handle_t *pamh)
{
	std::vector<FIDODevice> ret;
	size_t ndevs = 0;
	int res = FIDO_OK;
	unique_fido_dev_info_t deviceList(fido_dev_info_new(MAX_FIDO_DEVICES));
	if (!deviceList)
	{
		pam_syslog(pamh, LOG_ERR, "fido_dev_info_new returned nullptr");
		return ret;
	}

	if ((res = fido_dev_info_manifest(deviceList.get(), MAX_FIDO_DEVICES, &ndevs)) != FIDO_OK)
	{
		pam_syslog(pamh, LOG_ERR, "fido_dev_info_manifest: %s (code: %d)", fido_strerr(res), res);
		return ret;
	}

	for (size_t i = 0; i < ndevs; i++)
	{
		const fido_dev_info_t *di = fido_dev_info_ptr(deviceList.get(), i);
		ret.emplace_back(pamh, di);
	}
	return ret;
}

// Configure a fido_assert_t for the given signRequest and run
// fido_dev_get_assert on the supplied (already-open) device. Used by both the
// one-shot and parallel paths so the assertion setup lives in one place.
static int doGetAssert(
	pam_handle_t *pamh,
	fido_dev_t *dev,
	const FIDOSignRequest &signRequest,
	const std::string &origin,
	const char *pin,
	fido_assert_t **assert,
	std::vector<unsigned char> &clientDataOut)
{
	int res = FIDO_OK;
	if ((*assert = fido_assert_new()) == nullptr)
	{
		pam_syslog(pamh, LOG_ERR, "fido_assert_new failed");
		return FIDO_ERR_INTERNAL;
	}

	std::string challenge = Convert::Base64URLEncode(
		reinterpret_cast<const unsigned char *>(signRequest.challenge.data()),
		signRequest.challenge.size());
	std::string cData = "{\"type\": \"webauthn.get\", \"challenge\": \"" + challenge + "\", \"origin\": \"" + origin + "\", \"crossOrigin\": false}";
	clientDataOut = std::vector<unsigned char>(cData.begin(), cData.end());
	res = fido_assert_set_clientdata(*assert, clientDataOut.data(), clientDataOut.size());
	if (res != FIDO_OK)
	{
		pam_syslog(pamh, LOG_ERR, "fido_assert_set_clientdata: %s (code: %d)", fido_strerr(res), res);
		return res;
	}
	res = fido_assert_set_rp(*assert, signRequest.rpId.c_str());
	if (res != FIDO_OK)
	{
		pam_syslog(pamh, LOG_ERR, "fido_assert_set_rp: %s (code: %d)", fido_strerr(res), res);
		return res;
	}
	if (fido_dev_has_uv(dev) && signRequest.userVerification == "discouraged")
	{
		res = fido_assert_set_uv(*assert, FIDO_OPT_FALSE);
		if (res != FIDO_OK)
			pam_syslog(pamh, LOG_ERR, "fido_assert_set_uv: %s (code: %d)", fido_strerr(res), res);
	}
	return fido_dev_get_assert(dev, *assert, (pin && *pin) ? pin : nullptr);
}

// Shared implementation body for signAndVerifyAssertion variants.
static int doSignAndVerifyAssertion(
	pam_handle_t *pamh,
	fido_dev_t *dev,
	std::vector<OfflineFIDOCredential> &offlineData,
	const std::string &expectedRpId,
	const std::string &origin,
	const char *pin,
	bool requireUserVerification,
	std::string &serialUsed,
	uint32_t &newSignCount)
{
	if (offlineData.empty())
	{
		pam_syslog(pamh, LOG_ERR, "signAndVerifyAssertion called with no credentials.");
		return FIDO_ERR_INVALID_ARGUMENT;
	}

	// Defense in depth: callers should already have filtered offlineData by
	// config.rpId. Reject if anything slipped through — never let
	// fido_assert_set_rp run with an attacker-controlled rpId taken from a
	// tampered offline file.
	if (offlineData.front().rpId != expectedRpId)
	{
		pam_syslog(pamh, LOG_ERR, "Refusing offline auth: stored rpId '%s' does not match configured rpId '%s'.",
			offlineData.front().rpId.c_str(), expectedRpId.c_str());
		return FIDO_ERR_INVALID_ARGUMENT;
	}

	FIDOSignRequest signRequest;
	signRequest.rpId = expectedRpId;
	signRequest.challenge = Convert::GenerateRandomAsBase64URL(OFFLINE_CHALLENGE_SIZE);
	if (signRequest.challenge.empty())
	{
		pam_syslog(pamh, LOG_ERR, "Failed to generate random challenge for offline assertion (RAND_bytes failed).");
		return FIDO_ERR_INTERNAL;
	}
	signRequest.userVerification = requireUserVerification ? "required" : "discouraged";
	for (auto &item : offlineData)
	{
		if (item.rpId != signRequest.rpId)
		{
			pam_syslog(pamh, LOG_ERR, "Offline data for ID %s has different rpId. Expected: %s, actual: %s", item.credId.c_str(), signRequest.rpId.c_str(), item.rpId.c_str());
			pam_syslog(pamh, LOG_ERR, "The data will not be used for offline authentication");
		}
		else
		{
			signRequest.allowedCredentials.push_back(item.credId);
		}
	}

	fido_assert_t *assert_raw = nullptr;
	std::vector<unsigned char> cDataBytes;
	int res = doGetAssert(pamh, dev, signRequest, origin, pin, &assert_raw, cDataBytes);
	unique_fido_assert_t fido_assertion(assert_raw);

	unique_evp_pkey_t pkey(nullptr);
	unique_es256_pk_t pk(es256_pk_new());
	int algorithm = 0;

	if (res == FIDO_OK)
	{
		// Find the credential which signed the assert and use it's public key to verify the signature
		auto pbId = fido_assert_id_ptr(fido_assertion.get(), 0);
		auto cbId = fido_assert_id_len(fido_assertion.get(), 0);
		auto idUsed = Convert::Base64URLEncode(pbId, cbId);

		OfflineFIDOCredential *credUsed = nullptr;
		for (auto &item : offlineData)
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
			pam_syslog(pamh, LOG_ERR, "No offline credential found for the credential ID used for signing.");
			return FIDO_ERR_INVALID_ARGUMENT;
		}

		EVP_PKEY *pkey_raw = nullptr;
		// ecKeyFromCbor's static helper handles logging; null pkey signals failure.
		CoseKeyParseResult parseRes = parseCoseKey(credUsed->public_key_hex, &pkey_raw, &algorithm);
		pkey.reset(pkey_raw);
		if (!pkey)
		{
			switch (parseRes)
			{
				case CoseKeyParseResult::UnsupportedAlgorithm:
					pam_syslog(pamh, LOG_ERR, "Unsupported COSE algorithm in stored public key: %d", algorithm);
					return FIDO_ERR_INVALID_ARGUMENT;
				case CoseKeyParseResult::InvalidCbor:
					pam_syslog(pamh, LOG_ERR, "Failed to parse CBOR public key");
					return FIDO_ERR_INVALID_ARGUMENT;
				default:
					return FIDO_ERR_INTERNAL;
			}
		}

		res = es256_pk_from_EVP_PKEY(pk.get(), pkey.get());
		if (res == FIDO_OK)
		{
			res = fido_assert_verify(fido_assertion.get(), 0, algorithm, pk.get());
			if (res == FIDO_OK)
			{
				// When UV was required (PIN-based offline auth), enforce that the
				// authenticator actually performed user verification. libfido2's
				// fido_assert_verify validates the signature and rpIdHash but does
				// not enforce the UV flag — that is the verifier's job. Without
				// this check, a device with the right credential but no PIN could
				// satisfy an auth attempt that should have required UV.
				const uint8_t flags = fido_assert_flags(fido_assertion.get(), 0);
				if (requireUserVerification && !(flags & CTAP_AUTHDATA_USER_VERIFIED))
				{
					pam_syslog(pamh, LOG_ERR, "Offline assertion verified but user verification was required and not performed (authData flags=0x%02x).", flags);
					return FIDO_ERR_PIN_REQUIRED;
				}

				uint32_t new_sigcount = fido_assert_sigcount(fido_assertion.get(), 0);
				if (new_sigcount > credUsed->sign_count)
				{
					pam_syslog(pamh, LOG_INFO, "Offline assertion verified successfully. New signature count: %u (was %u)", new_sigcount, credUsed->sign_count);
					newSignCount = new_sigcount;
				}
				else
				{
					pam_syslog(pamh, LOG_ERR, "Signature counter did not increase. Possible replay attack. New: %u, Old: %u", new_sigcount, credUsed->sign_count);
					res = FIDO_ERR_INVALID_SIG; // Or a more specific error
				}
			}
			else
			{
				pam_syslog(pamh, LOG_ERR, "fido_assert_verify: %s (code: %d)", fido_strerr(res), res);
			}
		}
		else
		{
			pam_syslog(pamh, LOG_ERR, "es256_pk_from_EVP_PKEY: %s (code: %d)", fido_strerr(res), res);
		}
	}
	else
	{
		pam_syslog(pamh, LOG_ERR, "fido_dev_get_assert: %s (code: %d)", fido_strerr(res), res);
	}

	return res;
}

int FIDODevice::signAndVerifyAssertion(
	std::vector<OfflineFIDOCredential> &offlineData,
	const std::string &expectedRpId,
	const std::string &origin,
	const char *pin,
	bool requireUserVerification,
	std::string &serialUsed,
	uint32_t &newSignCount) const
{
	int err = FIDO_OK;
	auto dev = OpenFidoDevice(_pamh, _path, err);
	if (err != FIDO_OK)
		return err;
	return doSignAndVerifyAssertion(_pamh, dev.get(), offlineData, expectedRpId, origin, pin, requireUserVerification, serialUsed, newSignCount);
}

int FIDODevice::signAndVerifyAssertionOnOpenDevice(
	std::vector<OfflineFIDOCredential> &offlineData,
	const std::string &expectedRpId,
	const std::string &origin,
	const char *pin,
	bool requireUserVerification,
	std::string &serialUsed,
	uint32_t &newSignCount) const
{
	if (_dev == nullptr)
	{
		pam_syslog(_pamh, LOG_ERR, "signAndVerifyAssertionOnOpenDevice called without openDevice().");
		return FIDO_ERR_INTERNAL;
	}
	return doSignAndVerifyAssertion(_pamh, _dev, offlineData, expectedRpId, origin, pin, requireUserVerification, serialUsed, newSignCount);
}

FIDODevice::FIDODevice(pam_handle_t *pamh, const fido_dev_info_t *devinfo)
	: _pamh(pamh),
	  _path(fido_dev_info_path(devinfo)),
	  _manufacturer(fido_dev_info_manufacturer_string(devinfo)),
	  _product(fido_dev_info_product_string(devinfo))
{
	// Static info from devinfo only — opening the device here would waste a
	// USB transaction; sign() opens fresh per operation anyway.
}

FIDODevice::FIDODevice(FIDODevice &&other) noexcept
	: _pamh(other._pamh),
	  _path(std::move(other._path)),
	  _manufacturer(std::move(other._manufacturer)),
	  _product(std::move(other._product)),
	  _dev(other._dev)
{
	other._dev = nullptr;
	other._pamh = nullptr;
}

FIDODevice &FIDODevice::operator=(FIDODevice &&other) noexcept
{
	if (this != &other)
	{
		closeDevice();
		_pamh = other._pamh;
		_path = std::move(other._path);
		_manufacturer = std::move(other._manufacturer);
		_product = std::move(other._product);
		_dev = other._dev;
		other._dev = nullptr;
		other._pamh = nullptr;
	}
	return *this;
}

FIDODevice::~FIDODevice()
{
	closeDevice();
}

int FIDODevice::openDevice()
{
	if (_dev != nullptr)
		return FIDO_OK; // already open
	if (_path.empty())
	{
		pam_syslog(_pamh, LOG_ERR, "openDevice: no device path");
		return FIDO_ERR_INVALID_ARGUMENT;
	}
	_dev = fido_dev_new();
	if (_dev == nullptr)
	{
		pam_syslog(_pamh, LOG_ERR, "fido_dev_new failed");
		return FIDO_ERR_INTERNAL;
	}
	int res = fido_dev_open(_dev, _path.c_str());
	if (res != FIDO_OK)
	{
		pam_syslog(_pamh, LOG_ERR, "fido_dev_open: %s (code: %d)", fido_strerr(res), res);
		fido_dev_free(&_dev);
		_dev = nullptr;
		return res;
	}
	return FIDO_OK;
}

void FIDODevice::cancelDevice()
{
	// fido_dev_cancel is documented thread-safe wrt a concurrent
	// fido_dev_get_assert blocked on the same device handle. That is the
	// whole point of having this method: another thread can unblock the
	// worker thread that is currently waiting for user touch.
	if (_dev != nullptr)
		fido_dev_cancel(_dev);
}

void FIDODevice::closeDevice()
{
	if (_dev != nullptr)
	{
		fido_dev_close(_dev);
		fido_dev_free(&_dev);
		_dev = nullptr;
	}
}

std::string FIDODevice::toString() const
{
	return "[" + _manufacturer + "][" + _product + "][" + _path + "]";
}

// Shared implementation body for sign() variants. Packages the result of a
// fido_dev_get_assert into a FIDOSignResponse.
static int doSign(
	pam_handle_t *pamh,
	fido_dev_t *dev,
	const FIDOSignRequest &signRequest,
	const std::string &origin,
	const char *pin,
	FIDOSignResponse &signResponse)
{
	fido_assert_t *assert_raw = nullptr;
	std::vector<unsigned char> vecClientData;
	int res = doGetAssert(pamh, dev, signRequest, origin, pin, &assert_raw, vecClientData);
	unique_fido_assert_t fido_assertion(assert_raw);

	if (res != FIDO_OK)
	{
		pam_syslog(pamh, LOG_ERR, "fido_dev_get_assert: %s (code: %d)", fido_strerr(res), res);
		return res;
	}

	signResponse.clientdata = Convert::Base64URLEncode(vecClientData);

	auto pbId = fido_assert_id_ptr(fido_assertion.get(), 0);
	auto cbId = fido_assert_id_len(fido_assertion.get(), 0);
	signResponse.credentialid = Convert::Base64URLEncode(pbId, cbId);

	auto pbAuthData = fido_assert_authdata_raw_ptr(fido_assertion.get(), 0);
	auto cbAuthData = fido_assert_authdata_raw_len(fido_assertion.get(), 0);
	signResponse.authenticatordata = Convert::Base64URLEncode(pbAuthData, cbAuthData);

	auto pbSig = fido_assert_sig_ptr(fido_assertion.get(), 0);
	auto cbSig = fido_assert_sig_len(fido_assertion.get(), 0);
	signResponse.signaturedata = Convert::Base64URLEncode(pbSig, cbSig);

	auto pbUserHandle = fido_assert_user_id_ptr(fido_assertion.get(), 0);
	auto cbUserHandle = fido_assert_user_id_len(fido_assertion.get(), 0);
	signResponse.userHandle = Convert::Base64URLEncode(pbUserHandle, cbUserHandle);

	return res;
}

int FIDODevice::sign(
	const FIDOSignRequest &signRequest,
	const std::string &origin,
	const char *pin,
	FIDOSignResponse &signResponse) const
{
	int err = FIDO_OK;
	auto dev = OpenFidoDevice(_pamh, _path, err);
	if (err != FIDO_OK)
		return err;
	return doSign(_pamh, dev.get(), signRequest, origin, pin, signResponse);
}

int FIDODevice::signOnOpenDevice(
	const FIDOSignRequest &signRequest,
	const std::string &origin,
	const char *pin,
	FIDOSignResponse &signResponse) const
{
	if (_dev == nullptr)
	{
		pam_syslog(_pamh, LOG_ERR, "signOnOpenDevice called without openDevice().");
		return FIDO_ERR_INTERNAL;
	}
	return doSign(_pamh, _dev, signRequest, origin, pin, signResponse);
}


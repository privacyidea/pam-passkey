/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2025 NetKnights GmbH
** Author: Nils Behlen
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */

#ifndef FIDO_DEVICE_H
#define FIDO_DEVICE_H

#include <string>
#include <fido.h>
#include <vector>
#include <optional>
#include "fido_sign_request.h"
#include "fido_sign_response.h"
#include "offline_fido_credential.h"
// fido_init is now called once in pam_sm_authenticate, so fidoFlags is not needed here.
// constexpr auto fidoFlags = FIDO_DISABLE_U2F_FALLBACK; // | FIDO_DEBUG;

constexpr auto FIDO_DEVICE_ERR_TX = 0x88809089;

constexpr auto OFFLINE_CHALLENGE_SIZE = 64;

class FIDODevice
{
public:
	static std::vector<FIDODevice> getDevices(pam_handle_t *pamh, bool log = true);

	FIDODevice(pam_handle_t *pamh, const fido_dev_info_t *devinfo, bool log = true);
	FIDODevice() = default;

	int sign(
		const FIDOSignRequest &signRequest,
		const std::string &origin,
		const std::string &pin,
		FIDOSignResponse &signResponse) const;

	int signAndVerifyAssertion(
		std::vector<OfflineFIDOCredential> &offlineData,
		const std::string &origin,
		const std::string &pin,
		std::string &serialUsed,
		uint32_t &newSignCount) const;

	std::string getPath() const { return _path; }
	std::string getManufacturer() const { return _manufacturer; }
	std::string getProduct() const { return _product; }
	bool hasPin() const noexcept { return _hasPin; }
	bool hasUV() const noexcept { return _hasUV; }

	std::string toString() const;

	int getDetails();

private:
	pam_handle_t *_pamh = nullptr;
	std::string _path;
	std::string _manufacturer;
	std::string _product;
	bool _hasPin = false;
	bool _hasUV = false;
	std::vector<int> _supportedAlgorithms;
	long _remainingResidentKeys = -1;
	bool _newPinRequired = false;

	int getAssert(
		const FIDOSignRequest &signRequest,
		const std::string &origin,
		const std::string &pin,
		fido_assert_t **assert,
		std::vector<unsigned char> &clientDataOut) const;

	int ecKeyFromCbor(
		const std::string &cborPubKey,
		EC_KEY **ecKey,
		int *algorithm) const;
};

#endif // FIDO_DEVICE_H
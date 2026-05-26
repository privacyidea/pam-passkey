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
#include <openssl/evp.h>
// fido_init is now called once in pam_sm_authenticate, so fidoFlags is not needed here.
// constexpr auto fidoFlags = FIDO_DISABLE_U2F_FALLBACK; // | FIDO_DEBUG;

constexpr auto FIDO_DEVICE_ERR_TX = 0x88809089;

constexpr auto OFFLINE_CHALLENGE_SIZE = 64;

class FIDODevice
{
public:
	static std::vector<FIDODevice> getDevices(pam_handle_t *pamh);

	FIDODevice(pam_handle_t *pamh, const fido_dev_info_t *devinfo);
	FIDODevice() = default;
	~FIDODevice();

	// Move-only: holding a libfido2 device handle is owning state, copying would
	// share the same fido_dev_t between instances and double-free on destruction.
	FIDODevice(const FIDODevice &) = delete;
	FIDODevice &operator=(const FIDODevice &) = delete;
	FIDODevice(FIDODevice &&) noexcept;
	FIDODevice &operator=(FIDODevice &&) noexcept;

	// One-shot APIs that open the device, perform the operation, and close it.
	// Use these for single-device flows.
	int sign(
		const FIDOSignRequest &signRequest,
		const std::string &origin,
		const char *pin,
		FIDOSignResponse &signResponse) const;

	int signAndVerifyAssertion(
		std::vector<OfflineFIDOCredential> &offlineData,
		const std::string &expectedRpId,
		const std::string &origin,
		const char *pin,
		bool requireUserVerification,
		std::string &serialUsed,
		uint32_t &newSignCount) const;

	// Parallel-touch APIs: openDevice() leaves the handle open so that one
	// thread can block inside signOnOpenDevice/signAndVerifyAssertionOnOpenDevice
	// while a different thread calls cancelDevice() to unblock it. This lets
	// the module race multiple connected security keys against each other and
	// use whichever the user touches first.
	int openDevice();
	void cancelDevice();
	void closeDevice();

	int signOnOpenDevice(
		const FIDOSignRequest &signRequest,
		const std::string &origin,
		const char *pin,
		FIDOSignResponse &signResponse) const;

	int signAndVerifyAssertionOnOpenDevice(
		std::vector<OfflineFIDOCredential> &offlineData,
		const std::string &expectedRpId,
		const std::string &origin,
		const char *pin,
		bool requireUserVerification,
		std::string &serialUsed,
		uint32_t &newSignCount) const;

	std::string toString() const;

private:
	pam_handle_t *_pamh = nullptr;
	std::string _path;
	std::string _manufacturer;
	std::string _product;
	// Non-null between openDevice() and closeDevice(). Manually managed because
	// fido_dev_cancel needs to be callable on it from a different thread.
	fido_dev_t *_dev = nullptr;

};

#endif // FIDO_DEVICE_H
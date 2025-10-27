#define PAM_SM_AUTH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <fido.h>
#include <unistd.h> // For geteuid
#include <curl/curl.h> // For cURL error codes
#include <chrono>
#include <privacyidea.h>
#include <config.h>
#include <fido_device.h>
#include "privacyidea.h"
#include "config.h"
#include "fido_device.h"

extern "C"
{

    PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);

    PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
    {
        return PAM_SUCCESS;
    }

    PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
    {
        return PAM_SUCCESS;
    }

    PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
    {
        return PAM_SUCCESS;
    }

    PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
    {
        return PAM_SUCCESS;
    }

    PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
    {
        return PAM_SUCCESS;
    }
}

void getConfig(pam_handle_t *pamh, int argc, const char **argv, Config &config)
{
    for (int i = 0; i < argc; ++i)
    {
        std::string tmp(argv[i]);
        std::string key;
        std::string value;

        auto separator_pos = tmp.find('=');
        if (separator_pos == std::string::npos)
        {
            // This is a boolean flag like 'debug' or 'nossl'
            key = tmp;
        }
        else
        {
            // This is a key-value pair
            key = tmp.substr(0, separator_pos);
            value = tmp.substr(separator_pos + 1);
        }

        if (key == "url")
        {
            config.url = value;
            pam_syslog(pamh, LOG_DEBUG, "Setting url=%s", config.url.c_str());
        }
        else if (key == "rpid")
        {
            config.rpid = value;
            pam_syslog(pamh, LOG_DEBUG, "Setting rpid=%s", config.rpid.c_str());
        }
        else if (key == "debug")
        {
            config.debug = true;
            pam_syslog(pamh, LOG_DEBUG, "Setting debug=true");
        }
        else if (key == "nossl")
        {
            config.disableSSLVerify = true;
            pam_syslog(pamh, LOG_DEBUG, "Setting nossl=true");
        }
        else if (key == "realm")
        {
            config.realm = value;
            pam_syslog(pamh, LOG_DEBUG, "Setting realm=%s", config.realm.c_str());
        }
        else if (key == "offlineFile")
        {
            config.offlineFile = value;
            pam_syslog(pamh, LOG_DEBUG, "Setting offlineFile=%s", config.offlineFile.c_str());
        }
        else if (key == "prompt")
        {
            config.promptText = value;
            pam_syslog(pamh, LOG_DEBUG, "Setting prompt=%s", config.promptText.c_str());
        }
        else if (key == "timeout")
        {
            try
            {
                long timeout_val = std::stol(value);
                if (timeout_val >= 0) {
                    config.timeout = timeout_val;
                    pam_syslog(pamh, LOG_DEBUG, "Setting timeout=%lds", config.timeout);
                } else {
                    pam_syslog(pamh, LOG_WARNING, "Ignoring invalid negative timeout value: %s", value.c_str());
                }
            }
            catch (const std::exception& e) {
                pam_syslog(pamh, LOG_ERR, "Invalid timeout value: '%s'. Using default. Error: %s", value.c_str(), e.what());
            }
        }
        else if (key == "noPIN")
        {
            config.noPIN = true;
            pam_syslog(pamh, LOG_DEBUG, "Setting noPIN=true (PIN will not be required for offline authentication)");
        }
        else
        {
            pam_syslog(pamh, LOG_WARNING, "Unknown argument: %s", tmp.c_str());
        }
    }
}

static int getPinFromUser(pam_handle_t *pamh, const std::string &prompt, std::string &outPin)
{
    char *response_ptr = nullptr;
    pam_syslog(pamh, LOG_DEBUG, "Requesting PIN from user...");
    int prompt_ret = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response_ptr, prompt.c_str());

    if (prompt_ret != PAM_SUCCESS || response_ptr == nullptr)
    {
        pam_syslog(pamh, LOG_ERR, "Failed to get PIN from user (prompt result: %d).", prompt_ret);
        if (response_ptr)
            free(response_ptr);
        return PAM_AUTH_ERR;
    }

    outPin = response_ptr;

    // Securely erase and free the memory that held the PIN
    memset(response_ptr, 0, outPin.length());
    free(response_ptr);

    return PAM_SUCCESS;
}

static std::vector<FIDODevice> getDevicesWithWait(pam_handle_t *pamh, bool debug)
{
    auto devices = FIDODevice::getDevices(pamh, debug);

    if (devices.empty())
    {
        pam_syslog(pamh, LOG_INFO, "No FIDO device found. Prompting user for insertion with a 30-second timeout.");
        pam_prompt(pamh, PAM_TEXT_INFO, NULL, "Please insert your security key.");

        const auto timeout = std::chrono::seconds(30);
        auto startTime = std::chrono::steady_clock::now();

        while (std::chrono::steady_clock::now() - startTime < timeout)
        {
            // Don't spam the logs in the loop
            devices = FIDODevice::getDevices(pamh, false);
            if (!devices.empty())
            {
                pam_syslog(pamh, LOG_INFO, "FIDO device detected.");
                break;
            }
            sleep(1); // Check once per second
        }
    }

    return devices;
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int pamRet = PAM_AUTH_ERR;
    fido_init(0); // Initialize libfido2 once at the beginning


    openlog("pam_privacyidea_passkey", LOG_PID | LOG_CONS, LOG_AUTH);

    // Do not try to authenticate the root user, as this is a very bad idea
    // which could lock you out if misconfigured.
    const char *pamUserCheck = nullptr;
    if (pam_get_user(pamh, &pamUserCheck, nullptr) == PAM_SUCCESS && pamUserCheck != nullptr)
    {
        if (strcmp(pamUserCheck, "root") == 0)
        {
            pam_syslog(pamh, LOG_INFO, "Skipping passkey authentication for root user.");
            return PAM_IGNORE;
        }
    }

    // Get arguments, url is required
    if (argc == 0 || argv == NULL)
    {
        pam_syslog(pamh, LOG_ERR, "No url specified!");
        pam_syslog(pamh, LOG_DEBUG, "pam_sm_authenticate returns %s", pam_strerror(pamh, PAM_SERVICE_ERR));
        return PAM_SERVICE_ERR;
    }
    Config config;
    getConfig(pamh, argc, argv, config);

    if (config.rpid.empty())
    {
        pam_syslog(pamh, LOG_ERR, "Required 'rpid' configuration option is missing!");
        pam_syslog(pamh, LOG_DEBUG, "pam_sm_authenticate returns %s", pam_strerror(pamh, PAM_SERVICE_ERR));
        return PAM_SERVICE_ERR;
    }

    PrivacyIDEA privacyidea(pamh, config.url, config.realm, !config.disableSSLVerify, config.offlineFile, config.debug, config.timeout);
    
    Response initializeResponse;
    int res = privacyidea.validateInitializePasskey(initializeResponse);

    // Check if the online request failed.
    if (res != CURLE_OK)
    {
        // It failed. Now, determine if it was a network error that should trigger offline mode.
        // A simple check for common network-related cURL errors.
        bool isNetworkError = (res == CURLE_COULDNT_RESOLVE_HOST ||
                               res == CURLE_COULDNT_CONNECT ||
                               res == CURLE_OPERATION_TIMEDOUT ||
                               res == CURLE_RECV_ERROR ||
                               res == CURLE_SEND_ERROR);

        if (isNetworkError)
        {
            pam_syslog(pamh, LOG_INFO, "Online authentication failed with network error %d. Attempting offline authentication.", res);

            const char* pamUser = nullptr;
            if (pam_get_user(pamh, &pamUser, nullptr) != PAM_SUCCESS || pamUser == nullptr)
            {
                pam_syslog(pamh, LOG_ERR, "Cannot perform offline authentication without a username.");
                return PAM_USER_UNKNOWN;
            }

            auto offlineCredentials = privacyidea.findOfflineCredentialsForUser(pamUser);
            if (offlineCredentials.empty())
            {
                pam_syslog(pamh, LOG_ERR, "No offline credentials found for user '%s'.", pamUser);
                return PAM_AUTH_ERR;
            }

            // Set the rpId for all credentials for this user
            for (auto& cred : offlineCredentials)
            {
                cred.rpId = config.rpid;
            }

            auto devices = getDevicesWithWait(pamh, config.debug);
            if (devices.empty())
            {
                pam_syslog(pamh, LOG_ERR, "Timeout waiting for FIDO device insertion for offline authentication.");
                pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Timeout waiting for security key.");
                return PAM_AUTH_ERR;
            }

            // For now, just use the first device found
            auto& device = devices[0];
            std::string serialUsed;
            uint32_t newSignCount = 0;
            std::string pin;

            if (!config.noPIN)
            {
                if (getPinFromUser(pamh, "Enter security key PIN for offline use: ", pin) != PAM_SUCCESS)
                {
                    return PAM_AUTH_ERR;
                }
            }

            pam_prompt(pamh, PAM_TEXT_INFO, NULL, "Touch your security key for offline authentication.");
            // The vector is passed by value, but the sign count is updated on the original object in PrivacyIDEA
            res = device.signAndVerifyAssertion(offlineCredentials, "https://" + config.rpid, pin, serialUsed, newSignCount);

            if (res == FIDO_OK)
            {
                privacyidea.updateSignCount(serialUsed, newSignCount);
                pam_syslog(pamh, LOG_INFO, "Offline authentication successful for user '%s' with token '%s'.", pamUser, serialUsed.c_str());
                pamRet = PAM_SUCCESS;
            }
            else
            {
                pam_syslog(pamh, LOG_ERR, "Offline authentication failed: %s (code: %d)", fido_strerr(res), res);
                pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Offline authentication failed: %s", fido_strerr(res));
                pamRet = PAM_AUTH_ERR;
            }
        }
        else
        {
            // The failure was not a network error (e.g., SSL error). Fail securely.
            pam_syslog(pamh, LOG_ERR, "Online authentication failed with non-network error %d. Not attempting offline.", res);
            pam_syslog(pamh, LOG_DEBUG, "pam_sm_authenticate returns %s", pam_strerror(pamh, PAM_SERVICE_ERR));
            return PAM_SERVICE_ERR;
        }
    }
    else if (initializeResponse.signRequest)
    {

        // Compare the RP ID from privacyIDEA with the one configured for this module
        if (initializeResponse.signRequest->rpId != config.rpid)
        {
            pam_syslog(pamh, LOG_ERR, "RP ID mismatch! Expected '%s' but server sent '%s'.", config.rpid.c_str(), initializeResponse.signRequest->rpId.c_str());
            pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Security error: Relying Party ID mismatch.");
            return PAM_SERVICE_ERR;
        }

        auto devices = getDevicesWithWait(pamh, config.debug);
        if (devices.empty())
        {
            pam_syslog(pamh, LOG_ERR, "Timeout waiting for FIDO device insertion.");
            pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Timeout waiting for security key.");
            return PAM_AUTH_ERR;
        }

        auto device = devices[0];
        //device.GetDetails(); // Populate device info for the selected device
        pam_syslog(pamh, LOG_ERR, "Using device: %s", device.toString().c_str());
        auto signRequest = initializeResponse.signRequest.value();
        std::string pin;

        if (signRequest.userVerification != "discouraged")
        {
            if (getPinFromUser(pamh, "Enter your security key PIN: ", pin) != PAM_SUCCESS)
            {
                return PAM_AUTH_ERR;
            }
        }

        pam_prompt(pamh, PAM_TEXT_INFO, NULL, "Touch your security key!");
        FIDOSignResponse signResponse;
        pam_syslog(pamh, LOG_DEBUG, "Getting signature from authenticator...");
        res = device.sign(signRequest, config.url, pin, signResponse);
        if (res != 0)
        {
            pam_syslog(pamh, LOG_ERR, "Signing failed with error %d", res);
            pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Signing failed: %s", fido_strerr(res));
            pamRet = PAM_AUTH_ERR;
        }
        else
        {
            Response response;
            res = privacyidea.validateCheckFIDO(signResponse, signRequest.transaction_id, config.url, response);
            if (res != 0)
            {
                pam_syslog(pamh, LOG_ERR, "Checking failed with error %d", res);
                pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Failed to communicate with privacyIDEA server.");
                pamRet = PAM_AUTH_ERR;
            }
            else
            {
                if (response.authenticationSuccess)
                {
                    pam_syslog(pamh, LOG_INFO, "privacyidea authentication successful");
                    // Get the user from PAM if there is one
                    const char *currentPamUser = nullptr;
                    if (pam_get_user(pamh, &currentPamUser, nullptr) != PAM_SUCCESS || currentPamUser == nullptr)
                    {
                        pam_syslog(pamh, LOG_INFO, "No User from PAM, setting user from server response: %s", response.username.c_str());
                        pam_set_item(pamh, PAM_USER, response.username.c_str());
                        pamRet = PAM_SUCCESS;
                    }
                    else
                    {
                        auto pamUserString = std::string(currentPamUser);
                        if (!pamUserString.empty() && pamUserString != response.username)
                        {
                            pam_syslog(pamh, LOG_ERR, "User mismatch: pam=%s, privacyidea=%s", currentPamUser, response.username.c_str());
                            pamRet = PAM_AUTH_ERR;
                        }
                        else
                        {
                            pamRet = PAM_SUCCESS;
                        }
                    }
                }
                else
                {
                    pam_syslog(pamh, LOG_ERR, "authentication failed");
                    if (!response.errorMessage.empty()) {
                        pam_syslog(pamh, LOG_ERR, "Server error message: %s", response.errorMessage.c_str());
                        pam_prompt(pamh, PAM_ERROR_MSG, NULL, "%s", response.errorMessage.c_str());
                    }
                    pamRet = PAM_AUTH_ERR;
                }
            }
        }
    }
    
    pam_syslog(pamh, LOG_DEBUG, "pam_sm_authenticate returns %s", pam_strerror(pamh, pamRet));
    return pamRet;
}

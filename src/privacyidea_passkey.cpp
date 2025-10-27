#define PAM_SM_AUTH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <fido.h>
#include <unistd.h>    // For geteuid
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
                if (timeout_val >= 0)
                {
                    config.timeout = timeout_val;
                    pam_syslog(pamh, LOG_DEBUG, "Setting timeout=%lds", config.timeout);
                }
                else
                {
                    pam_syslog(pamh, LOG_WARNING, "Ignoring invalid negative timeout value: %s", value.c_str());
                }
            }
            catch (const std::exception &e)
            {
                pam_syslog(pamh, LOG_ERR, "Invalid timeout value: '%s'. Using default. Error: %s", value.c_str(), e.what());
            }
        }
        else if (key == "noPIN")
        {
            config.noPIN = true;
            pam_syslog(pamh, LOG_DEBUG, "Setting noPIN=true (PIN will not be required for offline authentication)");
        }
        else if (key == "offlineExpiry")
        {
            try
            {
                long expiry_val = std::stol(value); // Allow 0 to mean no expiry
                if (expiry_val >= 0)
                {
                    config.offlineExpiry = expiry_val;
                    pam_syslog(pamh, LOG_DEBUG, "Setting offlineExpiry=%ld days", config.offlineExpiry);
                }
                else
                {
                    pam_syslog(pamh, LOG_WARNING, "Ignoring invalid negative offlineExpiry value: %s", value.c_str());
                }
            }
            catch (const std::exception &e)
            {
                pam_syslog(pamh, LOG_ERR, "Invalid offlineExpiry value: '%s'. Using default. Error: %s", value.c_str(), e.what());
            }
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
    pam_syslog(pamh, LOG_DEBUG, "Requesting PIN from user with prompt: %s", prompt.c_str());
    int prompt_ret = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response_ptr, "%s", prompt.c_str());

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
            usleep(500 * 1000); // Check every 500ms
        }
    }

    return devices;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int pamRet = PAM_AUTH_ERR;
    fido_init(0);

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

    PrivacyIDEA privacyidea(pamh, config.url, config.realm, !config.disableSSLVerify, config.offlineFile, config.debug, config.timeout, config.offlineExpiry);

    // Attempt to refresh all offline credentials at the start.
    privacyidea.refillAllOfflineCredentials();

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

            const char *pamUserCStr = nullptr;
            pam_get_user(pamh, &pamUserCStr, nullptr);

            std::string pamUser;
            if (pamUserCStr != nullptr)
            {
                pamUser = pamUserCStr;
            }

            std::vector<OfflineFIDOCredential> credentialsToTry;
            bool usernamelessAttempt = false;

            if (!pamUser.empty())
            {
                pam_syslog(pamh, LOG_INFO, "PAM user '%s' provided. Attempting offline authentication for this user.", pamUser.c_str());
                credentialsToTry = privacyidea.findOfflineCredentialsForUser(pamUser);
            }
            else
            {
                pam_syslog(pamh, LOG_INFO, "No PAM user provided. Attempting usernameless offline authentication using all available offline credentials.");
                credentialsToTry = privacyidea.getAllOfflineCredentials();
                usernamelessAttempt = true;
            }

            if (credentialsToTry.empty())
            {
                pam_syslog(pamh, LOG_ERR, "No offline credentials found for %s.", (pamUser.empty() ? "any user" : pamUser.c_str()));
                return PAM_AUTH_ERR;
            }

            // Filter credentials by RP ID. Only use credentials that match the configured RP ID.
            std::vector<OfflineFIDOCredential> filteredCredentials;
            for (const auto &cred : credentialsToTry)
            {
                if (cred.rpId == config.rpid)
                {
                    filteredCredentials.push_back(cred);
                }
                else
                {
                    pam_syslog(pamh, LOG_WARNING, "Offline credential for serial '%s' (user '%s') has RP ID '%s' which does not match configured RP ID '%s'. Skipping.",
                               cred.serial.c_str(), cred.username.c_str(), cred.rpId.c_str(), config.rpid.c_str());
                }
            }
            credentialsToTry = filteredCredentials; // Use the filtered list

            // If after filtering, no credentials remain, then we can't proceed.
            if (credentialsToTry.empty())
            {
                pam_syslog(pamh, LOG_ERR, "No offline credentials found matching configured RP ID '%s' for %s.", config.rpid.c_str(), (pamUser.empty() ? "any user" : pamUser.c_str()));
                return PAM_AUTH_ERR;
            }

            auto devices = getDevicesWithWait(pamh, config.debug);
            if (devices.empty())
            {
                pam_syslog(pamh, LOG_ERR, "Timeout waiting for FIDO device insertion for offline authentication.");
                pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Timeout waiting for security key.");
                return PAM_AUTH_ERR;
            }

            // Loop through all found devices and try to authenticate
            for (auto &device : devices)
            {
                pam_syslog(pamh, LOG_DEBUG, "Attempting offline authentication with device: %s", device.toString().c_str());
                std::string serialUsed;
                uint32_t newSignCount = 0;
                std::string pin;

                if (!config.noPIN)
                {
                    if (getPinFromUser(pamh, "Enter security key PIN for offline use: ", pin) != PAM_SUCCESS)
                    {
                        // If user cancels PIN entry, stop the whole process.
                        return PAM_AUTH_ERR;
                    }
                }

                pam_prompt(pamh, PAM_TEXT_INFO, NULL, "Touch your security key for offline authentication.");
                res = device.signAndVerifyAssertion(credentialsToTry, "https://" + config.rpid, pin, serialUsed, newSignCount);

                if (res == FIDO_OK)
                {
                    privacyidea.updateSignCount(serialUsed, newSignCount);
                    pam_syslog(pamh, LOG_INFO, "Offline authentication successful for user '%s' with token '%s'.", pamUser.empty() ? "UNKNOWN" : pamUser.c_str(), serialUsed.c_str());
                    pamRet = PAM_SUCCESS;

                    if (usernamelessAttempt)
                    {
                        // If we started usernameless, find the username from the credential used
                        if (auto usedCred = privacyidea.findOfflineCredential(serialUsed))
                        {
                            // Dereference the optional to get the OfflineFIDOCredential object
                            pam_syslog(pamh, LOG_INFO, "User identified as '%s' via credential '%s'.", usedCred->username.c_str(), serialUsed.c_str());
                            pam_set_item(pamh, PAM_USER, usedCred->username.c_str());
                        }
                        else
                        {
                            pam_syslog(pamh, LOG_ERR, "Internal error: Authenticated credential with serial '%s' not found in offline data.", serialUsed.c_str());
                            // This should ideally not happen if updateSignCount succeeded.
                        }
                    }
                    break; // Success, exit the device loop
                }
                else if (res == FIDO_ERR_NO_CREDENTIALS)
                {
                    pam_syslog(pamh, LOG_DEBUG, "No matching credentials found on device %s, trying next.", device.toString().c_str());
                    // Continue to the next device in the loop
                }
                else
                {
                    // Other unrecoverable error, break and report failure
                    pam_syslog(pamh, LOG_ERR, "Offline authentication failed on device %s with unrecoverable error: %s (code: %d)", device.toString().c_str(), fido_strerr(res), res);
                    pamRet = PAM_AUTH_ERR; // Set pamRet to indicate failure
                    break;
                }
            }

            // After the loop, if pamRet is not PAM_SUCCESS, it means all devices failed or an unrecoverable error occurred.
            if (pamRet != PAM_SUCCESS)
            {
                // If the last error was NO_CREDENTIALS, it means no device had the right key.
                if (res == FIDO_ERR_NO_CREDENTIALS)
                {
                    pam_syslog(pamh, LOG_ERR, "No security key with matching credentials found after trying all devices.");
                    pam_prompt(pamh, PAM_ERROR_MSG, NULL, "No security key with matching credentials found.");
                }
                else if (pamRet == PAM_AUTH_ERR)
                { // For other specific errors, the message was already set.
                  // The specific error message was already logged and prompted inside the loop.
                }
                else
                { // Fallback for any other unhandled case
                    pam_syslog(pamh, LOG_ERR, "Offline authentication failed for an unknown reason.");
                    pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Offline authentication failed.");
                }
                pamRet = PAM_AUTH_ERR;
            }
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

        // Loop through all found devices and try to authenticate
        for (auto &device : devices)
        {
            pam_syslog(pamh, LOG_DEBUG, "Attempting online authentication with device: %s", device.toString().c_str());
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
            res = device.sign(signRequest, config.url, pin, signResponse);

            if (res == FIDO_OK)
            {
                Response response;
                int checkRes = privacyidea.validateCheckFIDO(signResponse, signRequest.transaction_id, config.url, response);
                if (checkRes == 0 && response.authenticationSuccess)
                {
                    pam_syslog(pamh, LOG_INFO, "privacyidea authentication successful");
                    // Set the PAM_USER if it's not already set
                    const char *currentPamUser = nullptr;
                    if (pam_get_user(pamh, &currentPamUser, nullptr) != PAM_SUCCESS || currentPamUser == nullptr)
                    {
                        pam_set_item(pamh, PAM_USER, response.username.c_str());
                    }
                    pamRet = PAM_SUCCESS;
                }
                else
                {
                    pam_syslog(pamh, LOG_ERR, "Online authentication check failed.");
                    if (!response.errorMessage.empty())
                    {
                        pam_prompt(pamh, PAM_ERROR_MSG, NULL, "%s", response.errorMessage.c_str());
                    }
                    pamRet = PAM_AUTH_ERR;
                }
                break; // Success, exit the device loop
            }
            else if (res == FIDO_ERR_NO_CREDENTIALS)
            {
                pam_syslog(pamh, LOG_DEBUG, "No matching credentials found on device %s, trying next.", device.toString().c_str());
                // Continue to the next device in the loop
            }
            else
            {
                // Other unrecoverable error, break and report failure
                pam_syslog(pamh, LOG_ERR, "Signing failed on device %s with unrecoverable error: %s (code: %d)", device.toString().c_str(), fido_strerr(res), res);
                pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Signing failed: %s", fido_strerr(res));
                pamRet = PAM_AUTH_ERR; // Set pamRet to indicate failure
                break;
            }
        }
        // After the loop, if pamRet is not PAM_SUCCESS, it means all devices failed or an unrecoverable error occurred.
        if (pamRet != PAM_SUCCESS)
        {
            // If the last error was NO_CREDENTIALS, it means no device had the right key.
            if (res == FIDO_ERR_NO_CREDENTIALS)
            {
                pam_syslog(pamh, LOG_ERR, "No security key with matching credentials found after trying all devices.");
                pam_prompt(pamh, PAM_ERROR_MSG, NULL, "No security key with matching credentials found.");
            }
            else if (pamRet == PAM_AUTH_ERR)
            { // For other specific errors, the message was already set.
              // The specific error message was already logged and prompted inside the loop.
            }
            else
            { // Fallback for any other unhandled case
                pam_syslog(pamh, LOG_ERR, "Online authentication failed for an unknown reason.");
                pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Online authentication failed.");
            }
            pamRet = PAM_AUTH_ERR;
        }
    }

    pam_syslog(pamh, LOG_DEBUG, "pam_sm_authenticate returns %s", pam_strerror(pamh, pamRet));
    return pamRet;
}

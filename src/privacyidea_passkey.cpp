#define PAM_SM_AUTH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <fido.h>
#include <unistd.h> // For geteuid
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
        else
        {
            pam_syslog(pamh, LOG_WARNING, "Unknown argument: %s", tmp.c_str());
        }
    }
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
    if (res != 0)
    {
        pam_syslog(pamh, LOG_ERR, "Getting passkey challenge failed with error %d", res);
        pam_syslog(pamh, LOG_DEBUG, "pam_sm_authenticate returns %s", pam_strerror(pamh, PAM_SERVICE_ERR));
        return PAM_SERVICE_ERR;
    }
    else if (initializeResponse.signRequest)
    {

        // SECURITY: Verify that the RP ID from the server matches the one configured in the PAM module.
        // This is the client-side check that prevents phishing/MitM attacks.
        if (initializeResponse.signRequest->rpId != config.rpid)
        {
            pam_syslog(pamh, LOG_ERR, "RPID mismatch! Expected '%s' but server sent '%s'.", config.rpid.c_str(), initializeResponse.signRequest->rpId.c_str());
            pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Security error: Relying Party ID mismatch.");
            return PAM_SERVICE_ERR;
        }

        auto start = std::chrono::high_resolution_clock::now();
        auto devices = FIDODevice::getDevices(pamh, config.debug);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        pam_syslog(pamh, LOG_DEBUG, "FIDODevice::GetDevices() took %ld ms.", duration.count());

        if (devices.empty())
        {
            pam_syslog(pamh, LOG_ERR, "No device, requesting device insertion from user");
            pam_prompt(pamh, PAM_TEXT_INFO, NULL, "Insert your security key!");
            while (true)
            {
                devices = FIDODevice::getDevices(pamh, config.debug);
                if (!devices.empty())
                {
                    break;
                }
                sleep(1);
            }
        }

        auto device = devices[0];
        //device.GetDetails(); // Populate device info for the selected device
        pam_syslog(pamh, LOG_ERR, "Using device: %s", device.toString().c_str());
        auto signRequest = initializeResponse.signRequest.value();
        std::string pin;

        if (signRequest.user_verification != "discouraged")
        {
            char *response_ptr = nullptr;
            pam_syslog(pamh, LOG_DEBUG, "Requesting PIN...");
            pamRet = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response_ptr, "Enter your security key PIN: ");

            if (pamRet != PAM_SUCCESS || response_ptr == nullptr)
            {
                pam_syslog(pamh, LOG_ERR, "Failed to get PIN from user.");
                if (response_ptr)
                {
                    // pam_prompt documentation says we must free the response
                    memset(response_ptr, 0, pin.length());
                    free(response_ptr);
                }
                pam_syslog(pamh, LOG_DEBUG, "pam_sm_authenticate returns %s", pam_strerror(pamh, PAM_AUTH_ERR));
                return PAM_AUTH_ERR;
            }

            pin = response_ptr;

            // Securely erase and free the memory that held the PIN
            memset(response_ptr, 0, pin.length());
            free(response_ptr);
            response_ptr = nullptr;
        }

        pam_prompt(pamh, PAM_TEXT_INFO, NULL, "Touch your security key!");
        FIDOSignResponse signResponse; // Initialize an empty response object
        pam_syslog(pamh, LOG_DEBUG, "getting signature from authenticator...");
        res = device.Sign(signRequest, config.url, pin, signResponse);
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

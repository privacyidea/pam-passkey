#define PAM_SM_AUTH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <fido.h>
#include <unistd.h>    // For geteuid
#include <curl/curl.h> // For cURL error codes + curl_global_init
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>
#include "privacyidea.h"
#include "config.h"
#include "fido_device.h"
#include "secure_string.h"

extern "C"
{

    PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int /*flags*/, int argc, const char **argv);

    // setcred is conventionally a no-op success for auth-only modules; some
    // applications call it after a successful authentication and expect success.
    PAM_EXTERN int pam_sm_setcred(pam_handle_t * /*pamh*/, int /*flags*/, int /*argc*/, const char ** /*argv*/)
    {
        return PAM_SUCCESS;
    }

    // This module only implements the 'auth' management group. The
    // 'account', 'session' and 'password' groups are intentionally not
    // exported so that misconfiguration (e.g. using this module on an
    // 'account' line) fails loudly instead of silently succeeding.
}

// Build identification string. Lives in the .so's .rodata with a distinctive
// prefix so an admin can identify which build is loaded without source access:
//
//   strings /usr/lib/.../pam_privacyidea_passkey.so | grep PAM_PRIVACYIDEA_BUILD
//
// `volatile` defeats LTO dead-store elimination so the string survives in the
// stripped binary; `used` and default visibility are belt-and-suspenders.
extern "C" __attribute__((used, visibility("default")))
volatile const char pam_privacyidea_build_info[] =
    "PAM_PRIVACYIDEA_BUILD version=" PAM_PRIVACYIDEA_VERSION;

static void getConfig(pam_handle_t *pamh, int argc, const char **argv, Config &config)
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
        }
        else if (key == "rpid")
        {
            config.rpId = value;
        }
        else if (key == "debug")
        {
            config.debug = true;
        }
        else if (key == "nossl" || key == "no_ssl")
        {
            config.disableSslVerify = true;
        }
        else if (key == "realm")
        {
            config.realm = value;
        }
        else if (key == "offlineFile" || key == "offline_file")
        {
            config.offlineFile = value;
        }
        else if (key == "prompt")
        {
            config.promptText = value;
        }
        else if (key == "timeout")
        {
            try
            {
                long timeout_val = std::stol(value);
                if (timeout_val >= 0)
                    config.timeout = timeout_val;
                else
                    pam_syslog(pamh, LOG_WARNING, "Ignoring invalid negative timeout value: %s", value.c_str());
            }
            catch (const std::exception &e)
            {
                pam_syslog(pamh, LOG_ERR, "Invalid timeout value: '%s'. Using default. Error: %s", value.c_str(), e.what());
            }
        }
        else if (key == "noPIN" || key == "no_pin")
        {
            config.noPin = true;
        }
        else if (key == "use_first_pass")
        {
            config.useFirstPass = true;
        }
        else if (key == "try_first_pass")
        {
            config.tryFirstPass = true;
        }
        else if (key == "pass_pin")
        {
            config.passPin = true;
        }
        else if (key == "cacert" || key == "ca_cert")
        {
            config.caCertPath = value;
        }
        else if (key == "keyInsertTimeout" || key == "key_insert_timeout")
        {
            try
            {
                long t = std::stol(value);
                if (t >= 0)
                    config.keyInsertTimeout = t;
                else
                    pam_syslog(pamh, LOG_WARNING, "Ignoring negative %s: %s", key.c_str(), value.c_str());
            }
            catch (const std::exception &e)
            {
                pam_syslog(pamh, LOG_ERR, "Invalid %s: '%s'. Using default. Error: %s", key.c_str(), value.c_str(), e.what());
            }
        }
        else if (key == "offlineExpiry" || key == "offline_expiry")
        {
            try
            {
                long expiry_val = std::stol(value); // Allow 0 to mean no expiry
                if (expiry_val >= 0)
                    config.offlineExpiry = expiry_val;
                else
                    pam_syslog(pamh, LOG_WARNING, "Ignoring invalid negative %s value: %s", key.c_str(), value.c_str());
            }
            catch (const std::exception &e)
            {
                pam_syslog(pamh, LOG_ERR, "Invalid %s value: '%s'. Using default. Error: %s", key.c_str(), value.c_str(), e.what());
            }
        }
        else
        {
            pam_syslog(pamh, LOG_WARNING, "Unknown argument: %s", tmp.c_str());
        }
    }
}

static int getPinFromUser(pam_handle_t *pamh, const std::string &prompt, SecureString &outPin)
{
    char *response_ptr = nullptr;
    int prompt_ret = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response_ptr, "%s", prompt.c_str());

    if (prompt_ret != PAM_SUCCESS || response_ptr == nullptr)
    {
        pam_syslog(pamh, LOG_ERR, "Failed to get PIN from user (prompt result: %d).", prompt_ret);
        if (response_ptr != nullptr)
        {
            // PAM's C API hands us a malloc'd buffer; we have to free() it.
            free(response_ptr); // NOLINT(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
        }
        return PAM_AUTH_ERR;
    }

    size_t len = strlen(response_ptr);
    outPin.assign(response_ptr, len);

    // Scrub and free the buffer returned by libpam.
    OPENSSL_cleanse(response_ptr, len);
    free(response_ptr); // NOLINT(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)

    return PAM_SUCCESS;
}

// Resolve the PIN to use for FIDO user verification, honoring use_first_pass /
// try_first_pass / pass_pin from the module configuration.
static int resolvePin(pam_handle_t *pamh, const Config &config, const std::string &prompt, SecureString &outPin)
{
    // Check for an existing PAM_AUTHTOK if either *_first_pass flag is set.
    if (config.useFirstPass || config.tryFirstPass)
    {
        const void *item = nullptr;
        if (pam_get_item(pamh, PAM_AUTHTOK, &item) == PAM_SUCCESS && item != nullptr)
        {
            const char *tok = static_cast<const char *>(item);
            outPin.assign(tok, strlen(tok));
        }
        else if (config.useFirstPass)
        {
            pam_syslog(pamh, LOG_ERR, "use_first_pass set but no PAM_AUTHTOK available.");
            return PAM_AUTH_ERR;
        }
    }

    if (outPin.empty())
    {
        if (getPinFromUser(pamh, prompt, outPin) != PAM_SUCCESS)
        {
            return PAM_AUTH_ERR;
        }

        // Empty input at the PIN prompt is treated as "skip me" — return
        // PAM_AUTHINFO_UNAVAIL so the surrounding PAM stack can fall through
        // to another authentication method.
        if (outPin.empty())
        {
            pam_syslog(pamh, LOG_INFO, "Empty PIN entered, falling through to next PAM module.");
            return PAM_AUTHINFO_UNAVAIL;
        }

        if (config.passPin)
        {
            // pam_set_item copies the string internally; PAM also scrubs PAM_AUTHTOK
            // when the handle is destroyed, so this does not defeat the SecureString.
            if (pam_set_item(pamh, PAM_AUTHTOK, outPin.c_str()) != PAM_SUCCESS)
            {
                pam_syslog(pamh, LOG_WARNING, "Failed to set PAM_AUTHTOK for pass_pin.");
            }
        }
    }

    return PAM_SUCCESS;
}

// Set PAM_USER after a usernameless authentication, refusing usernames that
// would either bypass our root carve-out or override a username the calling
// application already established. A successful FIDO assertion only proves
// possession of a private key plus (optionally) the device PIN — it must not
// be allowed to elevate to an arbitrary account via the stored `username`
// field in the offline file, which could be tampered with.
static bool setPamUserAfterUsernamelessAuth(pam_handle_t *pamh, const std::string &originalUser, const std::string &authenticatedUser)
{
    if (authenticatedUser.empty())
    {
        pam_syslog(pamh, LOG_ERR, "Refusing to set PAM_USER to empty string after successful assertion.");
        return false;
    }
    // Reject NUL bytes and control characters BEFORE any equality comparison
    // against "root" or originalUser. PAM's pam_set_item(PAM_USER, c_str)
    // truncates at the first NUL, so a string like "root\0nobody" would
    // compare unequal to "root" here but be stored in PAM as literally "root"
    // — bypassing the explicit root carve-out. Newlines/CR similarly let an
    // attacker forge log lines and headers downstream.
    for (unsigned char c : authenticatedUser)
    {
        if (c == 0 || c < 0x20 || c == 0x7f)
        {
            pam_syslog(pamh, LOG_ERR, "Refusing to set PAM_USER: username contains NUL or control character (0x%02x).", c);
            return false;
        }
    }
    // Cap length defensively. 255 matches LOGIN_NAME_MAX-1 on Linux and
    // accommodates federated/IdP-style usernames (e.g. "first.last@long.subdomain.example.com")
    // while still bounding the worst-case allocation an attacker can drive
    // through pam_set_item / downstream NSS lookups.
    if (authenticatedUser.size() > 255)
    {
        pam_syslog(pamh, LOG_ERR, "Refusing to set PAM_USER: username is %zu bytes (max 255).", authenticatedUser.size());
        return false;
    }
    if (authenticatedUser == "root")
    {
        pam_syslog(pamh, LOG_ERR, "Refusing to set PAM_USER to 'root' after successful assertion.");
        return false;
    }
    if (!originalUser.empty() && originalUser != authenticatedUser)
    {
        pam_syslog(pamh, LOG_ERR, "Refusing to change PAM_USER from '%s' to '%s' after successful assertion.",
                   originalUser.c_str(), authenticatedUser.c_str());
        return false;
    }
    if (pam_set_item(pamh, PAM_USER, authenticatedUser.c_str()) != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_ERR, "pam_set_item(PAM_USER, '%s') failed.", authenticatedUser.c_str());
        return false;
    }
    return true;
}

// Race a signing operation across every connected FIDO device in parallel.
// The user touches whichever key they want; whichever device returns FIDO_OK
// first wins. The losing devices are unblocked via fido_dev_cancel so their
// worker threads return promptly with FIDO_ERR_RX (or similar) and the PAM
// call can complete.
//
// `worker(deviceIdx)` is invoked from one thread per device and is expected to
// drive the operation (sign / signAndVerifyAssertion) against
// devices[deviceIdx] using its open handle. Each worker is responsible for
// writing its own output slot before returning.
//
// Returns the index of the winning device, or -1 if no device succeeded.
// `outResult` receives the FIDO_OK / error code that ultimately decided the
// outcome (the winner's, or — if all failed — a representative error,
// preferring non-NO_CREDENTIALS so callers can distinguish "user has no
// matching credential" from "user just didn't touch any key").
static int parallelDeviceRace(
    pam_handle_t *pamh,
    std::vector<FIDODevice> &devices,
    const std::function<int(size_t)> &worker,
    int &outResult)
{
    (void)pamh; // Reserved for future per-orchestrator logging.
    outResult = FIDO_ERR_INTERNAL;
    if (devices.empty())
        return -1;

    // Open every candidate device up front so cancelDevice() can target them
    // from another thread mid-flight. Devices that fail to open are simply
    // excluded from the race.
    std::vector<size_t> openIdxs;
    openIdxs.reserve(devices.size());
    for (size_t i = 0; i < devices.size(); ++i)
    {
        if (devices[i].openDevice() == FIDO_OK)
            openIdxs.push_back(i);
    }
    if (openIdxs.empty())
        return -1;

    std::mutex mu;
    std::condition_variable cv;
    int winnerIdx = -1;
    size_t completed = 0;
    std::vector<int> threadResults(devices.size(), FIDO_ERR_INTERNAL);

    std::vector<std::thread> threads;
    threads.reserve(openIdxs.size());
    for (size_t idx : openIdxs)
    {
        threads.emplace_back([&, idx]() {
            int res = worker(idx);
            std::lock_guard<std::mutex> lk(mu);
            threadResults[idx] = res;
            ++completed;
            if (res == FIDO_OK && winnerIdx < 0)
            {
                winnerIdx = static_cast<int>(idx);
                // Unblock every other in-flight worker. fido_dev_cancel is
                // documented thread-safe wrt a concurrent fido_dev_get_assert.
                for (size_t other : openIdxs)
                {
                    if (other != idx)
                        devices[other].cancelDevice();
                }
            }
            cv.notify_all();
        });
    }

    {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait(lk, [&]() { return winnerIdx >= 0 || completed == openIdxs.size(); });
    }
    for (auto &t : threads)
        t.join();
    for (size_t idx : openIdxs)
        devices[idx].closeDevice();

    if (winnerIdx >= 0)
    {
        outResult = FIDO_OK;
        return winnerIdx;
    }
    // No winner: pick the most informative error among the workers, preferring
    // anything other than NO_CREDENTIALS so the caller can distinguish "key
    // doesn't hold this credential" from a real failure.
    outResult = FIDO_ERR_NO_CREDENTIALS;
    for (size_t idx : openIdxs)
    {
        if (threadResults[idx] != FIDO_ERR_NO_CREDENTIALS && threadResults[idx] != FIDO_OK)
        {
            outResult = threadResults[idx];
            break;
        }
    }
    return -1;
}

static std::vector<FIDODevice> getDevicesWithWait(pam_handle_t *pamh, long timeoutSeconds)
{
    auto devices = FIDODevice::getDevices(pamh);

    if (devices.empty() && timeoutSeconds > 0)
    {
        pam_syslog(pamh, LOG_INFO, "No FIDO device found. Prompting user for insertion with a %ld-second timeout.", timeoutSeconds);
        pam_prompt(pamh, PAM_TEXT_INFO, nullptr, "Please insert your security key.");

        const auto timeout = std::chrono::seconds(timeoutSeconds);
        auto startTime = std::chrono::steady_clock::now();

        while (std::chrono::steady_clock::now() - startTime < timeout)
        {
            devices = FIDODevice::getDevices(pamh);
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

static int pam_sm_authenticate_impl(pam_handle_t *pamh, int argc, const char **argv)
{
    int pamRet = PAM_AUTH_ERR;

    // One-shot init for the lifetime of the loaded module. PAM modules may be
    // invoked many times per process (sshd is a notable example) and calling
    // openlog / fido_init on every authentication is wasteful and changes
    // the syslog ident globally each time.
    static std::once_flag init_once;
    std::call_once(init_once, [pamh] {
        // FIDO_DISABLE_U2F_FALLBACK: this module is FIDO2/Passkey only. A
        // legacy U2F authenticator cannot satisfy a passkey assertion anyway,
        // and the U2F fallback path in libfido2 has historically been the
        // source of AppID-handling subtleties we don't want to expose.
        fido_init(FIDO_DISABLE_U2F_FALLBACK);
        // libcurl docs are explicit that curl_easy_init's implicit-init path
        // is not thread-safe; PAM modules can be loaded into multi-threaded
        // daemons (sshd is one), so do the global init here under the
        // call_once mutex. No matching curl_global_cleanup: the module stays
        // resident for the host process's lifetime. A non-zero return here
        // means the TLS/LDAP backend failed to initialize and subsequent
        // curl_easy_init calls are documented as undefined — log loudly.
        const CURLcode curlInit = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (curlInit != CURLE_OK)
            pam_syslog(pamh, LOG_ERR, "curl_global_init failed: %d (%s)", curlInit, curl_easy_strerror(curlInit));
        openlog("pam_privacyidea_passkey", LOG_PID | LOG_CONS, LOG_AUTH);
    });

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
    if (argc == 0 || argv == nullptr)
    {
        pam_syslog(pamh, LOG_ERR, "No url specified!");
        return PAM_SERVICE_ERR;
    }
    Config config;
    getConfig(pamh, argc, argv, config);

    if (config.rpId.empty())
    {
        pam_syslog(pamh, LOG_ERR, "Required 'rpid' configuration option is missing!");
        return PAM_SERVICE_ERR;
    }
    if (config.url.empty())
    {
        // Without this guard, cURL returns CURLE_URL_MALFORMAT — which is not
        // in the network-error allowlist — so the module would return
        // PAM_AUTH_ERR without ever attempting offline. Fail loudly instead.
        pam_syslog(pamh, LOG_ERR, "Required 'url' configuration option is missing!");
        return PAM_SERVICE_ERR;
    }

    PrivacyIDEA privacyidea(pamh, config.url, config.realm, !config.disableSslVerify, config.offlineFile, config.debug, config.timeout, config.offlineExpiry, config.caCertPath, config.rpId);

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
            // A non-PAM_SUCCESS return from pam_get_user (e.g. a broken
            // conversation function) must not be silently converted into
            // "match every credential on the box" via the usernameless path.
            const int pamUserRet = pam_get_user(pamh, &pamUserCStr, nullptr);

            std::string pamUser;
            if (pamUserRet == PAM_SUCCESS && pamUserCStr != nullptr)
            {
                pamUser = pamUserCStr;
            }
            else if (pamUserRet != PAM_SUCCESS)
            {
                pam_syslog(pamh, LOG_ERR, "pam_get_user failed for offline auth: %s. Refusing to fall through to usernameless mode.",
                           pam_strerror(pamh, pamUserRet));
                return PAM_AUTH_ERR;
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
                if (cred.rpId == config.rpId)
                {
                    filteredCredentials.push_back(cred);
                }
                else
                {
                    pam_syslog(pamh, LOG_WARNING, "Offline credential for serial '%s' (user '%s') has RP ID '%s' which does not match configured RP ID '%s'. Skipping.",
                               cred.serial.c_str(), cred.username.c_str(), cred.rpId.c_str(), config.rpId.c_str());
                }
            }
            credentialsToTry = filteredCredentials; // Use the filtered list

            // If after filtering, no credentials remain, then we can't proceed.
            if (credentialsToTry.empty())
            {
                pam_syslog(pamh, LOG_ERR, "No offline credentials found matching configured RP ID '%s' for %s.", config.rpId.c_str(), (pamUser.empty() ? "any user" : pamUser.c_str()));
                return PAM_AUTH_ERR;
            }

            auto devices = getDevicesWithWait(pamh, config.keyInsertTimeout);
            if (devices.empty())
            {
                pam_syslog(pamh, LOG_ERR, "Timeout waiting for FIDO device insertion for offline authentication.");
                pam_prompt(pamh, PAM_ERROR_MSG, nullptr, "Timeout waiting for security key.");
                // Return PAM_AUTHINFO_UNAVAIL so the stack can fall through to another auth method.
                return PAM_AUTHINFO_UNAVAIL;
            }

            // Prompt for the PIN once, outside the device loop, so the user is not
            // asked again for every connected device.
            SecureString pin;
            if (!config.noPin)
            {
                int pinRes = resolvePin(pamh, config, "Enter security key PIN for offline use: ", pin);
                if (pinRes != PAM_SUCCESS)
                {
                    // Propagate PAM_AUTHINFO_UNAVAIL (empty PIN → user wants to skip)
                    // or PAM_AUTH_ERR (prompt cancelled / use_first_pass failed).
                    return pinRes;
                }
            }

            // Race every connected device in parallel: the user touches
            // whichever key they want and whichever device returns OK first
            // wins. Losing devices are unblocked via fido_dev_cancel so the
            // PAM call can complete promptly.
            {
                const std::string offlineTouchPrompt = config.promptText.empty()
                    ? std::string("Touch your security key for offline authentication.")
                    : config.promptText;
                pam_prompt(pamh, PAM_TEXT_INFO, nullptr, "%s", offlineTouchPrompt.c_str());
            }
            std::vector<std::string> serials(devices.size());
            std::vector<uint32_t> sigcounts(devices.size(), 0);
            int raceRes = FIDO_ERR_INTERNAL;
            const int winner = parallelDeviceRace(pamh, devices,
                [&](size_t i) {
                    return devices[i].signAndVerifyAssertionOnOpenDevice(
                        credentialsToTry,
                        config.rpId,
                        "https://" + config.rpId,
                        pin.empty() ? nullptr : pin.c_str(),
                        !config.noPin,
                        serials[i],
                        sigcounts[i]);
                },
                raceRes);

            if (winner >= 0)
            {
                const std::string &serialUsed = serials[winner];
                const uint32_t newSignCount = sigcounts[winner];
                privacyidea.updateSignCount(serialUsed, newSignCount);
                pam_syslog(pamh, LOG_INFO, "Offline authentication successful for user '%s' with token '%s'.", pamUser.empty() ? "UNKNOWN" : pamUser.c_str(), serialUsed.c_str());
                pamRet = PAM_SUCCESS;

                if (usernamelessAttempt)
                {
                    if (auto usedCred = privacyidea.findOfflineCredential(serialUsed))
                    {
                        pam_syslog(pamh, LOG_INFO, "User identified as '%s' via credential '%s'.", usedCred->username.c_str(), serialUsed.c_str());
                        if (!setPamUserAfterUsernamelessAuth(pamh, pamUser, usedCred->username))
                        {
                            pamRet = PAM_AUTH_ERR;
                        }
                    }
                    else
                    {
                        pam_syslog(pamh, LOG_ERR, "Internal error: Authenticated credential with serial '%s' not found in offline data.", serialUsed.c_str());
                        pamRet = PAM_AUTH_ERR;
                    }
                }
            }
            else
            {
                res = raceRes;
                pamRet = PAM_AUTH_ERR;
                if (raceRes == FIDO_ERR_NO_CREDENTIALS)
                    pam_syslog(pamh, LOG_DEBUG, "No matching credentials found on any device.");
                else
                    pam_syslog(pamh, LOG_ERR, "Offline authentication failed across all devices: %s (code: %d)", fido_strerr(raceRes), raceRes);
            }

            // After the loop, if pamRet is not PAM_SUCCESS, it means all devices failed or an unrecoverable error occurred.
            if (pamRet != PAM_SUCCESS)
            {
                // If the last error was NO_CREDENTIALS, it means no device had the right key.
                if (res == FIDO_ERR_NO_CREDENTIALS)
                {
                    pam_syslog(pamh, LOG_ERR, "No security key with matching credentials found after trying all devices.");
                    pam_prompt(pamh, PAM_ERROR_MSG, nullptr, "No security key with matching credentials found.");
                }
                else if (pamRet == PAM_AUTH_ERR)
                { // For other specific errors, the message was already set.
                  // The specific error message was already logged and prompted inside the loop.
                }
                else
                { // Fallback for any other unhandled case
                    pam_syslog(pamh, LOG_ERR, "Offline authentication failed for an unknown reason.");
                    pam_prompt(pamh, PAM_ERROR_MSG, nullptr, "Offline authentication failed.");
                }
                pamRet = PAM_AUTH_ERR;
            }
        }
    }
    else if (initializeResponse.signRequest)
    {

        // Compare the RP ID from privacyIDEA with the one configured for this module
        if (initializeResponse.signRequest->rpId != config.rpId)
        {
            pam_syslog(pamh, LOG_ERR, "RP ID mismatch! Expected '%s' but server sent '%s'.", config.rpId.c_str(), initializeResponse.signRequest->rpId.c_str());
            pam_prompt(pamh, PAM_ERROR_MSG, nullptr, "Security error: Relying Party ID mismatch.");
            return PAM_SERVICE_ERR;
        }
        // Refuse to proceed with an empty challenge or transaction_id. A
        // standards-compliant server never sends these empty; if we see one,
        // the response was malformed in a way that survived parseResponse.
        // Signing over an empty challenge would let the device produce a
        // signature that any future verifier of this client would accept as
        // fresh, defeating the whole point of the challenge.
        if (initializeResponse.signRequest->challenge.empty() ||
            initializeResponse.signRequest->transaction_id.empty())
        {
            pam_syslog(pamh, LOG_ERR, "Server sent an empty challenge or transaction_id; refusing to sign.");
            return PAM_AUTH_ERR;
        }

        auto devices = getDevicesWithWait(pamh, config.keyInsertTimeout);
        if (devices.empty())
        {
            pam_syslog(pamh, LOG_ERR, "Timeout waiting for FIDO device insertion.");
            pam_prompt(pamh, PAM_ERROR_MSG, nullptr, "Timeout waiting for security key.");
            // Return PAM_AUTHINFO_UNAVAIL so the stack can fall through to another auth method.
            return PAM_AUTHINFO_UNAVAIL;
        }

        auto signRequest = initializeResponse.signRequest.value();

        // Prompt for the PIN once, outside the device loop, so the user is not
        // asked again for every connected device.
        SecureString pin;
        if (signRequest.userVerification != "discouraged")
        {
            int pinRes = resolvePin(pamh, config, "Enter your security key PIN: ", pin);
            if (pinRes != PAM_SUCCESS)
            {
                // Propagate PAM_AUTHINFO_UNAVAIL or PAM_AUTH_ERR.
                return pinRes;
            }
        }

        // Prompt precedence: explicit `prompt=` config option > server-provided
        // signRequest.message > built-in fallback.
        std::string touchPrompt = "Touch your security key!";
        if (!signRequest.message.empty())
            touchPrompt = signRequest.message;
        if (!config.promptText.empty())
            touchPrompt = config.promptText;
        pam_prompt(pamh, PAM_TEXT_INFO, nullptr, "%s", touchPrompt.c_str());

        // WebAuthn origin is "https://<rpId>" — derived from the (server-
        // validated) RP ID, not from the privacyIDEA server URL. The same
        // value is sent as the HTTP Origin header on /validate/check below
        // so the server can match clientData.origin to the request origin.
        const std::string origin = "https://" + signRequest.rpId;

        // Race every connected device in parallel; whichever the user touches
        // first wins. Losing devices are cancelled to unblock their workers.
        std::vector<FIDOSignResponse> signResponses(devices.size());
        int raceRes = FIDO_ERR_INTERNAL;
        const int winner = parallelDeviceRace(pamh, devices,
            [&](size_t i) {
                return devices[i].signOnOpenDevice(signRequest, origin, pin.empty() ? nullptr : pin.c_str(), signResponses[i]);
            },
            raceRes);

        if (winner >= 0)
        {
            Response response;
            int checkRes = privacyidea.validateCheckFIDO(signResponses[winner], signRequest.transaction_id, origin, response);
            if (checkRes == 0 && response.authenticationSuccess)
            {
                pam_syslog(pamh, LOG_INFO, "privacyidea authentication successful");
                const void *currentUser = nullptr;
                std::string originalUser;
                if (pam_get_item(pamh, PAM_USER, &currentUser) == PAM_SUCCESS && currentUser != nullptr)
                    originalUser = static_cast<const char *>(currentUser);

                if (originalUser.empty() && !response.username.empty())
                {
                    if (!setPamUserAfterUsernamelessAuth(pamh, originalUser, response.username))
                    {
                        pamRet = PAM_AUTH_ERR;
                    }
                    else
                    {
                        pamRet = PAM_SUCCESS;
                    }
                }
                else
                {
                    pamRet = PAM_SUCCESS;
                }
            }
            else
            {
                pam_syslog(pamh, LOG_ERR, "Online authentication check failed.");
                if (!response.errorMessage.empty())
                    pam_prompt(pamh, PAM_ERROR_MSG, nullptr, "%s", response.errorMessage.c_str());
                pamRet = PAM_AUTH_ERR;
            }
        }
        else
        {
            res = raceRes;
            pamRet = PAM_AUTH_ERR;
            if (raceRes == FIDO_ERR_NO_CREDENTIALS)
            {
                pam_syslog(pamh, LOG_DEBUG, "No matching credentials found on any device.");
            }
            else
            {
                pam_syslog(pamh, LOG_ERR, "Signing failed across all devices: %s (code: %d)", fido_strerr(raceRes), raceRes);
                pam_prompt(pamh, PAM_ERROR_MSG, nullptr, "Signing failed: %s", fido_strerr(raceRes));
            }
        }
        // After the loop, if pamRet is not PAM_SUCCESS, it means all devices failed or an unrecoverable error occurred.
        if (pamRet != PAM_SUCCESS)
        {
            // If the last error was NO_CREDENTIALS, it means no device had the right key.
            if (res == FIDO_ERR_NO_CREDENTIALS)
            {
                pam_syslog(pamh, LOG_ERR, "No security key with matching credentials found after trying all devices.");
                pam_prompt(pamh, PAM_ERROR_MSG, nullptr, "No security key with matching credentials found.");
            }
            else if (pamRet == PAM_AUTH_ERR)
            { // For other specific errors, the message was already set.
              // The specific error message was already logged and prompted inside the loop.
            }
            else
            { // Fallback for any other unhandled case
                pam_syslog(pamh, LOG_ERR, "Online authentication failed for an unknown reason.");
                pam_prompt(pamh, PAM_ERROR_MSG, nullptr, "Online authentication failed.");
            }
            pamRet = PAM_AUTH_ERR;
        }
    }

    return pamRet;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int /*flags*/, int argc, const char **argv)
{
    // C++ exceptions crossing the extern "C" boundary into libpam (and from
    // there into sshd/login/lightdm) are undefined behavior. Contain everything
    // here and translate to PAM error codes.
    try
    {
        return pam_sm_authenticate_impl(pamh, argc, argv);
    }
    catch (const std::exception &e)
    {
        pam_syslog(pamh, LOG_ERR, "Unhandled exception in pam_sm_authenticate: %s", e.what());
        return PAM_AUTH_ERR;
    }
    catch (...)
    {
        pam_syslog(pamh, LOG_ERR, "Unhandled non-standard exception in pam_sm_authenticate");
        return PAM_AUTH_ERR;
    }
}

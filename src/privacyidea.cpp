#include "privacyidea.h"
#include <cstring>
#include <errno.h>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <syslog.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "json.hpp"
#include "convert.h"

using namespace std;
using json = nlohmann::json;

// This allows nlohmann::json to automatically convert JSON to and from the OfflineFIDOCredential struct.
void from_json(const json &j, OfflineFIDOCredential &cred)
{
    j.at("pubKey").get_to(cred.public_key_hex);
    j.at("username").get_to(cred.username);
    j.at("rpId").get_to(cred.rpId); // rpId is now part of the offline file
    j.at("credentialId").get_to(cred.credId);
    j.at("serial").get_to(cred.serial);
    j.at("refilltoken").get_to(cred.refilltoken);
    j.at("sign_count").get_to(cred.sign_count);
    j.at("expiry_timestamp").get_to(cred.expiry_timestamp); // Now a string
}

void to_json(json &j, const OfflineFIDOCredential &cred)
{
    j = json{{"pubKey", cred.public_key_hex},
             {"username", cred.username},
             {"credentialId", cred.credId},
             {"refilltoken", cred.refilltoken},
             {"serial", cred.serial},
             {"rpId", cred.rpId}, // rpId is now part of the offline file
             {"sign_count", cred.sign_count},
             {"expiry_timestamp", cred.expiry_timestamp}};
}

PrivacyIDEA::PrivacyIDEA(pam_handle_t *pamh, std::string baseURL, std::string realm, bool sslVerify, std::string offlineFile, bool debug, long timeout, long offlineExpiryDays)
{
    this->pamh = pamh;
    this->baseURL = baseURL;
    this->sslVerify = sslVerify;
    this->debug = debug;
    this->timeout = timeout;
    this->realm = realm;
    this->offlineExpirySeconds = offlineExpiryDays * 24 * 60 * 60; // Convert days to seconds

    if (!offlineFile.empty())
    {
        this->offlineFile = offlineFile;
    }

    string content = readAll(offlineFile);
    if (!content.empty())
    {
        try
        {
            offlineJson = json::parse(content);
            if (offlineJson.contains("fido_offline"))
            {
                // This will use the from_json function defined above
                offlineJson.at("fido_offline").get_to(offlineData);
            }
        }
        catch (const std::exception &e)
        {
            // A parse error indicates a corrupted file, which is a warning.
            pam_syslog(pamh, LOG_WARNING, "Unable to parse offline data file '%s': %s", offlineFile.c_str(), e.what());
        }
    }
}

PrivacyIDEA::~PrivacyIDEA()
{
    // Only attempt to write if there's actual offline data to save.
    // offlineJson might be empty if the file was malformed, but offlineData could still be populated.
    if (!offlineData.empty())
    {
        offlineJson["fido_offline"] = offlineData;
        writeAll(offlineFile, offlineJson.dump(4));
    }
}

std::string getMachineId()
{
    std::string machineId;
    std::ifstream idFile;

    // 1. Try /etc/machine-id (standard for systemd)
    idFile.open("/etc/machine-id");
    if (idFile.is_open() && std::getline(idFile, machineId) && !machineId.empty())
    {
        idFile.close();
        return machineId;
    }

    // 2. Try /var/lib/dbus/machine-id (D-Bus machine ID)
    idFile.open("/var/lib/dbus/machine-id");
    if (idFile.is_open() && std::getline(idFile, machineId) && !machineId.empty())
    {
        idFile.close();
        return machineId;
    }

    // 3. Try DMI/SMBIOS product UUID as a hardware-bound fallback
    idFile.open("/sys/class/dmi/id/product_uuid");
    if (idFile.is_open() && std::getline(idFile, machineId) && !machineId.empty())
    {
        idFile.close();
        return machineId;
    }

    return ""; // Return empty if no ID could be found
}

int PrivacyIDEA::validateInitializePasskey(Response &response)
{
    map<string, string> parameters = {{"type", "passkey"}};

    string r;
    int res = sendRequest(baseURL + "/validate/initialize", parameters, {}, r, false); // Use GET
    if (res != 0)
    {
        pam_syslog(pamh, LOG_ERR, "Failed to send /validate/initialize request. Curl error: %d (%s)", res, curl_easy_strerror((CURLcode)res));
        return res;
    }

    return parseResponse(r, response);
}

size_t writeCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

int PrivacyIDEA::validateCheck(const string &user, const string &pass, const string &transactionID,
                               Response &response)
{
    int retval = 0;
    string strResponse;
    map<string, string> param{make_pair("user", user), make_pair("pass", pass)};

    if (!transactionID.empty())
    {
        param.emplace("transaction_id", transactionID);
    }

    if (!realm.empty())
    {
        param.emplace("realm", realm);
    }

    map<string, string> headers;

    retval = sendRequest(baseURL + "/validate/check", param, headers, strResponse);
    if (retval != 0)
    {
        // The request failed. Log a descriptive error and return immediately.
        pam_syslog(pamh, LOG_ERR, "validateCheck: The request to the server failed with cURL error: %d (%s)", retval, curl_easy_strerror((CURLcode)retval));
        return retval;
    }

    retval = parseResponse(strResponse, response);
    if (retval != 0)
    {
        pam_syslog(pamh, LOG_ERR, "validateCheck: Unable to parse the response from the privacyIDEA server. Error %d", retval);
    }

    return retval;
}

int PrivacyIDEA::sendRequest(const std::string &url, const std::map<std::string, std::string> &parameters,
                             const std::map<std::string, std::string> &headers,
                             std::string &response, bool postRequest)
{
    // RAII for CURL handle
    struct CurlDeleter
    {
        void operator()(CURL *curl) const
        {
            if (curl)
                curl_easy_cleanup(curl);
        }
    };
    using unique_curl_t = std::unique_ptr<CURL, CurlDeleter>;

    // RAII for curl_slist
    struct CurlSlistDeleter
    {
        void operator()(struct curl_slist *slist) const
        {
            if (slist)
                curl_slist_free_all(slist);
        }
    };
    using unique_slist_t = std::unique_ptr<struct curl_slist, CurlSlistDeleter>;

    unique_curl_t curl(curl_easy_init());
    if (!curl)
    {
        return CURLE_FAILED_INIT;
    }

    CURLcode res = CURLE_OK;
    string readBuffer;
    string postData;

    if (debug)
    {
        pam_syslog(pamh, LOG_DEBUG, "Sending request to %s with parameters:", url.c_str());
    }

    // Efficiently build the parameter string
    if (!parameters.empty())
    {
        auto it = parameters.begin();
        postData.append(it->first).append("=").append(Convert::UrlEncode(it->second));
        if (debug)
            pam_syslog(pamh, LOG_DEBUG, "%s=%s", it->first.c_str(), (it->first == "pass" ? "********" : it->second.c_str()));

        for (++it; it != parameters.end(); ++it)
        {
            postData.append("&").append(it->first).append("=").append(Convert::UrlEncode(it->second));
            if (debug)
                pam_syslog(pamh, LOG_DEBUG, "%s=%s", it->first.c_str(), (it->first == "pass" ? "********" : it->second.c_str()));
        }
    }

    if (postRequest)
    {
        curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, postData.c_str());
    }
    else
    {
        // GET request
        std::string fullUrl = url;
        if (!postData.empty())
        {
            fullUrl.append("?").append(postData);
        }
        curl_easy_setopt(curl.get(), CURLOPT_URL, fullUrl.c_str());
    }

    struct curl_slist *slist_raw = nullptr;
    for (const auto &header : headers)
    {
        string headerString = header.first + ": " + header.second;
        slist_raw = curl_slist_append(slist_raw, headerString.c_str());
    }
    unique_slist_t headers_list(slist_raw);

    std::string ua = PAM_PRIVACYIDEA_USERAGENT;
    std::string machineId = getMachineId();
    if (!machineId.empty())
    {
        // This is required for offline to be able to identify the machine and refilltoken in the server
        ua.append(" ComputerName/").append(machineId);
    }

    slist_raw = curl_slist_append(headers_list.get(), ("User-Agent: " + ua).c_str());
    headers_list.release(); // The new list owns the old one
    headers_list.reset(slist_raw);

    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers_list.get());

    if (!sslVerify)
    {
        curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 0L);
    }

    if (timeout > 0)
    {
        curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, timeout);
    }

    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &readBuffer);

    res = curl_easy_perform(curl.get());

    if (res == CURLE_OK)
    {
        response = readBuffer;
    }

    return (int)res;
}

int PrivacyIDEA::validateCheckFIDO(const FIDOSignResponse &signResponse, const std::string &transactionId, const std::string &origin, Response &response, const std::string &user)
{
    std::map<std::string, std::string> parameters = {
        {"transaction_id", transactionId}};

    // Add FIDO parameters, each member of the response is a parameter
    parameters.try_emplace("credentialid", signResponse.credentialid);
    parameters.try_emplace("clientdata", signResponse.clientdata);
    parameters.try_emplace("signaturedata", signResponse.signaturedata);
    parameters.try_emplace("authenticatordata", signResponse.authenticatordata);
    parameters.try_emplace("userHandle", signResponse.userHandle);

    if (!user.empty())
    {
        parameters.try_emplace("user", user);
    }

    std::map<std::string, std::string> headers = {
        {"Origin", origin}};

    std::string strResponse;
    int res = sendRequest(baseURL + "/validate/check", parameters, headers, strResponse);

    if (res != CURLE_OK)
    {
        pam_syslog(pamh, LOG_ERR, "validateCheckFIDO: The request to the server failed with cURL error: %d (%s)", res, curl_easy_strerror((CURLcode)res));
        return res;
    }

    return parseResponse(strResponse, response);
}

std::string PrivacyIDEA::readAll(std::string file)
{
    std::ifstream inFile(offlineFile);
    if (!inFile)
    { // It's a warning if the file doesn't exist, not a hard error.
        pam_syslog(pamh, LOG_WARNING, "Unable to open offline file '%s'. Error: %d %s", offlineFile.c_str(), errno, strerror(errno));
    }
    std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    return content;
}

void PrivacyIDEA::writeAll(std::string file, std::string content)
{
    std::ofstream outFile(file, std::ios::trunc);
    if (!outFile) // This is a critical error, as data won't be persisted.
    {
        pam_syslog(pamh, LOG_ERR, "Unable to open offline file '%s' for writing. Error: %d %s", file.c_str(), errno, strerror(errno));
    }

    outFile << content;
    outFile.close();
}

int PrivacyIDEA::parseResponse(const std::string &input, Response &out)
{
    if (debug)
        pam_syslog(pamh, LOG_DEBUG, "%s", input.c_str());

    json jResponse;
    try
    {
        jResponse = json::parse(input);
    }
    catch (const json::parse_error &e)
    {
        pam_syslog(pamh, LOG_ERR, "Failed to parse server response: %s", input.c_str());
        return 1;
    }

    if (jResponse.contains("result") && jResponse["result"].contains("value") && jResponse["result"].contains("authentication"))
    {
        bool v = jResponse["result"]["value"].get<bool>();
        auto authentication = jResponse["result"]["authentication"].get<std::string>();
        out.authenticationSuccess = v && authentication == "ACCEPT";
    }

    if (jResponse.contains("result") && jResponse["result"].contains("error"))
    {
        out.errorMessage = jResponse["result"]["error"]["message"].get<std::string>();
        out.errorCode = jResponse["result"]["error"]["code"].get<int>();
    }

    if (jResponse.contains("detail"))
    {
        auto jDetail = jResponse["detail"];
        if (jDetail.contains("passkey") && jDetail["passkey"].is_object())
        {
            try {
                FIDOSignRequest data;
                const auto &passkey = jDetail.at("passkey");
                passkey.at("challenge").get_to(data.challenge);
                passkey.at("rpId").get_to(data.rpId);
                passkey.at("transaction_id").get_to(data.transaction_id);
                passkey.at("user_verification").get_to(data.userVerification);

                // message is optional
                if (passkey.contains("message")) {
                    passkey.at("message").get_to(data.message);
                }
                out.signRequest = data;
            } catch (const json::exception& e) {
                pam_syslog(pamh, LOG_ERR, "Failed to parse passkey challenge from server response: %s", e.what());
            }
        }

        if (jDetail.contains("username"))
        {
            out.username = jDetail["username"].get<std::string>();
        }
    }

    // After a successful online authentication, the server may send offline credentials
    if (jResponse.contains("auth_items") && jResponse["auth_items"].is_object())
    {
        const auto &authItems = jResponse["auth_items"];
        if (authItems.contains("offline") && authItems["offline"].is_array())
        {
            pam_syslog(pamh, LOG_DEBUG, "Found offline credentials in server response.");
            for (const auto &offlineItem : authItems["offline"])
            {
                if (offlineItem.contains("response") && offlineItem["response"].is_object() &&
                    offlineItem.contains("user") && offlineItem["user"].is_string() &&
                    offlineItem.contains("serial") && offlineItem["serial"].is_string())
                {
                    const auto &offlineResponse = offlineItem["response"];
                    // All FIDO-specific data, including rpId, is inside the 'response' object.
                    if (offlineResponse.contains("pubKey") && offlineResponse.contains("credentialId") &&
                        offlineResponse.contains("rpId") &&
                        offlineItem.contains("refilltoken")) // Check for refilltoken
                    {
                        std::string user = offlineItem["user"].get<std::string>();
                        std::string serial = offlineItem["serial"].get<std::string>();
                        std::string rpId = offlineResponse["rpId"].get<std::string>(); // Extract rpId from the correct location
                        std::string pubKey = offlineResponse["pubKey"].get<std::string>();
                        std::string credId = offlineResponse["credentialId"].get<std::string>();
                        std::string refillToken = offlineItem["refilltoken"].get<std::string>();

                        pam_syslog(pamh, LOG_INFO, "Storing offline credential for user '%s', serial '%s'.", user.c_str(), serial.c_str());

                        // Find if a credential with this serial already exists and update it, otherwise add a new one.
                        auto it = std::find_if(offlineData.begin(), offlineData.end(),
                                               [&serial](const OfflineFIDOCredential &cred)
                                               { return cred.serial == serial; });

                        if (it != offlineData.end())
                        {
                            it->public_key_hex = pubKey;
                            it->credId = credId;
                            it->username = user;
                            it->rpId = rpId; // Update rpId
                            it->refilltoken = refillToken;
                            if (offlineExpirySeconds > 0)
                            {
                                it->expiry_timestamp = Convert::timeTToIso8601(time(nullptr) + offlineExpirySeconds);
                            }
                            // Keep the signcount
                        }
                        else
                        {
                            std::string expiryStr = (offlineExpirySeconds > 0) ? Convert::timeTToIso8601(time(nullptr) + offlineExpirySeconds) : "";
                            offlineData.push_back({pubKey, user, rpId, credId, serial, refillToken, 0, expiryStr});
                        }
                    }
                }
            }
        }
    }

    return 0;
}

OfflineFIDOCredential *PrivacyIDEA::_getMutableOfflineCredential(const std::string &serial)
{
    for (auto &cred : offlineData)
    {
        if (cred.serial == serial)
        {
            return &cred;
        }
    }
    return nullptr;
}

void PrivacyIDEA::updateSignCount(const std::string &serial, uint32_t newSignCount)
{
    OfflineFIDOCredential *cred = _getMutableOfflineCredential(serial);
    if (cred)
    {
        cred->sign_count = newSignCount;
        pam_syslog(pamh, LOG_DEBUG, "Updated signature count for serial '%s' to %u.", serial.c_str(), newSignCount);
    }
    else
    {
        pam_syslog(pamh, LOG_ERR, "Could not update signature count: failed to find credential with serial '%s'.", serial.c_str());
    }
}

int PrivacyIDEA::offlineRefillFIDO(OfflineFIDOCredential &cred)
{
    if (debug)
    {
        pam_syslog(pamh, LOG_DEBUG, "Attempting FIDO offline refill for user '%s' with serial '%s'.", cred.username.c_str(), cred.serial.c_str());
    }

    if (cred.refilltoken.empty())
    {
        pam_syslog(pamh, LOG_DEBUG, "FIDO credential with serial '%s' has no refill token, skipping refill.", cred.serial.c_str());
        return 0; // Not an error, just nothing to refill
    }

    // The server's /validate/offlinerefill endpoint expects 'pass', 'refilltoken', 'serial'.
    // For FIDO, 'pass' is not applicable, so we send an empty string.
    map<string, string> parameters =
        {
            {"pass", ""}, // Empty password for FIDO refill
            {"refilltoken", cred.refilltoken},
            {"serial", cred.serial}};
    map<string, string> headers;
    string response;

    int retval = sendRequest(baseURL + "/validate/offlinerefill", parameters, headers, response);
    pam_syslog(pamh, LOG_DEBUG, "/validate/offlinerefill: %s", response.c_str());
    if (retval != 0)
    {
        pam_syslog(pamh, LOG_DEBUG, "FIDO offline refill request failed for serial '%s'. Curl error: %d", cred.serial.c_str(), retval);
        return retval;
    }

    json j;
    try
    {
        j = json::parse(response);
    }
    catch (const json::parse_error &e)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to parse FIDO refill response for serial '%s': %s", cred.serial.c_str(), e.what());
        return 1;
    }

    // Check for an error response from the server
    if (j.contains("result") && j["result"].contains("error") && j["result"]["error"].is_object())
    {
        const auto &error = j["result"]["error"];
        if (error.contains("code") && error["code"].get<int>() == 905)
        {
            pam_syslog(pamh, LOG_WARNING, "FIDO offline refill for serial '%s' failed with error 905. The server indicates the token is invalid. Removing local offline credential.", cred.serial.c_str());
            return 905; // Special return code to signal deletion
        }
    }

    // Check for a successful response containing a new refill token
    if (j.contains("result") && j["result"].contains("value") && j["result"]["value"].get<bool>() == true &&
        j.contains("auth_items") && j["auth_items"].contains("offline") && j["auth_items"]["offline"].is_array() &&
        j["auth_items"]["offline"].size() > 0 && j["auth_items"]["offline"][0].contains("refilltoken"))
    {
        // Successfully validated, save the new refill token
        cred.refilltoken = j["auth_items"]["offline"][0]["refilltoken"].get<std::string>();
        // Also refresh the expiry timestamp if configured
        if (offlineExpirySeconds > 0)
        {
            cred.expiry_timestamp = Convert::timeTToIso8601(time(nullptr) + offlineExpirySeconds);
        }
        pam_syslog(pamh, LOG_DEBUG, "FIDO offline refill completed for serial '%s', new refill token received.", cred.serial.c_str());
    }
    else
    {
        // The response was not an error 905, but it also wasn't a successful refill.
        // This could mean the token is still valid but no new refill token was issued, or the response is malformed.
        pam_syslog(pamh, LOG_WARNING, "FIDO offline refill for serial '%s' did not result in a new refill token. The credential might still be usable offline until it expires.", cred.serial.c_str());
    }
    return 0;
}

void PrivacyIDEA::refillAllOfflineCredentials()
{
    for (auto it = offlineData.begin(); it != offlineData.end();)
    {
        // First, check for client-side expiry
        time_t currentExpiry = Convert::iso8601ToTimeT(it->expiry_timestamp);
        if (!it->expiry_timestamp.empty() && currentExpiry != 0 && currentExpiry < time(nullptr))
        {
            pam_syslog(pamh, LOG_WARNING, "Offline credential for serial '%s' (user '%s') has expired. Removing.", it->serial.c_str(), it->username.c_str());
            it = offlineData.erase(it);
            continue; // Continue to the next iteration
        }

        if (!it->refilltoken.empty())
        {
            if (offlineRefillFIDO(*it) == 905)
            {
                // The refill function returned the special code for deletion.
                it = offlineData.erase(it);
            }
            else
            {
                ++it;
            }
        }
        else
        {
            pam_syslog(pamh, LOG_WARNING, "Offline credential for serial '%s' (user '%s') has no refill token and cannot be validated. Removing.", it->serial.c_str(), it->username.c_str());
            it = offlineData.erase(it);
        }
    }
}

std::vector<OfflineFIDOCredential> PrivacyIDEA::findOfflineCredentialsForUser(const std::string &username) const
{
    std::vector<OfflineFIDOCredential> userCredentials;
    for (const auto &cred : offlineData)
    {
        if (cred.username == username)
        {
            userCredentials.push_back(cred);
        }
    }
    return userCredentials;
}

std::optional<OfflineFIDOCredential> PrivacyIDEA::findOfflineCredential(const std::string &serial) const
{
    for (const auto &cred : offlineData)
    {
        if (cred.serial == serial)
        {
            return cred; // Return a copy wrapped in optional
        }
    }
    return std::nullopt; // Not found
}

std::vector<OfflineFIDOCredential> PrivacyIDEA::getAllOfflineCredentials() const
{
    return offlineData;
}
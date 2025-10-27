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
void from_json(const json& j, OfflineFIDOCredential& cred) {
    j.at("pubKey").get_to(cred.public_key_hex);
    j.at("username").get_to(cred.username);
    // rpId is not part of the offline file, it is determined during offline auth
    j.at("credentialId").get_to(cred.credId);
    j.at("serial").get_to(cred.serial);
    j.at("sign_count").get_to(cred.sign_count);
}

void to_json(json& j, const OfflineFIDOCredential& cred) {
    j = json{{"pubKey", cred.public_key_hex},
             {"username", cred.username},
             {"credentialId", cred.credId},
             {"serial", cred.serial},
             {"sign_count", cred.sign_count}};
}

PrivacyIDEA::PrivacyIDEA(pam_handle_t *pamh, std::string baseURL, std::string realm, bool sslVerify, std::string offlineFile, bool debug, long timeout)
{
    this->pamh = pamh;
    this->baseURL = baseURL;
    this->sslVerify = sslVerify;
    this->debug = debug;
    this->timeout = timeout;
    this->realm = realm;

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
            // TODO keep this debug, because having the file is not required
            pam_syslog(pamh, LOG_DEBUG, "Unable to load offline data: %s", e.what());
        }
    }
}

PrivacyIDEA::~PrivacyIDEA()
{
    if (!offlineJson.empty())
    {
        offlineJson["fido_offline"] = offlineData;
        writeAll(offlineFile, offlineJson.dump(4));
    }
}

std::string getMachineId()
{
    std::ifstream machineIdFile("/etc/machine-id");
    if (machineIdFile.is_open())
    {
        std::string machineId;
        if (std::getline(machineIdFile, machineId))
        {
            return machineId;
        }
    }
    return "";
}

int PrivacyIDEA::validateInitializePasskey(Response &response)
{
    map<string, string> parameters = {{"type", "passkey"}};

    string r;
    int res = sendRequest(baseURL + "/validate/initialize", parameters, {}, r, false); // Use GET
    if (res != 0)
    {
        pam_syslog(pamh, LOG_ERR, "Failed to send /validate/initialize request. Curl error: %d", res);
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
        // Do not abort in this case, offline authentication is still be possible
        // TODO remove the log as it is expected in some cases?
        pam_syslog(pamh, LOG_ERR, "Unable to send request to the privacyIDEA server. Error %d\n", retval);
    }
    retval = parseResponse(strResponse, response);
    if (retval != 0)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to parse the response from the privacyIDEA server. Response: %s\n Error %d\n",
                   strResponse.c_str(), retval);
    }
    return retval;
}

int PrivacyIDEA::sendRequest(const std::string &url, const std::map<std::string, std::string> &parameters,
                             const std::map<std::string, std::string> &headers,
                             std::string &response, bool postRequest)
{
    CURL *curl;
    CURLcode res = CURLE_OK;
    string readBuffer;

    curl = curl_easy_init();
    if (curl)
    {
        string postData;
        if (debug)
        {
            pam_syslog(pamh, LOG_DEBUG, "Sending request to %s with parameters:", url.c_str());
        }

        for (const auto &param : parameters)
        {
            string tmp = param.first + "=" + Convert::UrlEncode(param.second) + "&";
            postData += tmp;
            if (debug)
            {
                if (param.first == "pass")
                {
                    pam_syslog(pamh, LOG_DEBUG, "pass=%zu digits", param.second.size());
                }
                else
                {
                    pam_syslog(pamh, LOG_DEBUG, "%s", tmp.substr(0, tmp.length() - 1).c_str());
                }
            }
        }
        postData = postData.substr(0, postData.length() - 1); // Remove the trailing '&'

        if (postRequest)
        {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
        }
        else
        {
            // GET request
            curl_easy_setopt(curl, CURLOPT_URL, (url + "?" + postData).c_str());
        }

        struct curl_slist *headers_list = nullptr;
        for (const auto &header : headers)
        {
            string headerString = header.first + ": " + header.second;
            headers_list = curl_slist_append(headers_list, headerString.c_str());
        }

        std::string ua = string(PAM_PRIVACYIDEA_USERAGENT);
        std::string machineId = getMachineId();
        if (!machineId.empty())
        {
            // This is required for offline to be able to identify the machine and refilltoken in the server
            ua = ua + " ComputerName/" + machineId;
        }

        headers_list = curl_slist_append(headers_list, ("User-Agent: " + ua).c_str());

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers_list);

        if (!sslVerify)
        {
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
        }

        if (timeout > 0)
        {
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
        }

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl);

        curl_slist_free_all(headers_list);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK)
        {
            response = readBuffer;
        }
    }
    else
    {
        res = CURLE_FAILED_INIT;
    }

    return (int)res;
}

int PrivacyIDEA::offlineRefill(const std::string &user, const std::string &lastOTP, const std::string &serial)
{
    if (debug)
    {
        pam_syslog(pamh, LOG_DEBUG, "Attempting offline refill for user %s with token %s", user.c_str(), serial.c_str());
    }

    if (!offlineJson.contains("offline") || !offlineJson["offline"].is_array())
    {
        return OFFLINE_FILE_WRONG_FORMAT;
    }

    // This part seems to handle a different kind of offline data (OTP-based).
    // It is left as-is, operating on the raw offlineJson object.
    for (auto &item : offlineJson["offline"])
    {
        if (!item.contains("serial") || item["serial"].get<std::string>() != serial) {
            continue;
        }

        map<string, string> parameters =
            {
                {"pass", lastOTP},
                {"refilltoken", item["refilltoken"].get<std::string>()},
                {"serial", serial}};
        map<string, string> headers;
        string response;
        auto retval = sendRequest(baseURL + "/validate/offlinerefill", parameters, headers, response);
        if (debug)
        {
            pam_syslog(pamh, LOG_DEBUG, "%s", response.c_str());
        }
        if (retval != 0)
        {
            // TODO might be expected when the machine is offline, leave it at debug
            if (debug)
            {
                pam_syslog(pamh, LOG_DEBUG, "%s", "Unable to refill offline values");
            }
            break;
        }

        json j;
        try
        {
            j = json::parse(response);
        }
        catch (const json::parse_error &e)
        {
            pam_syslog(pamh, LOG_ERR, "Unable parse refill response!");
            return 1;
        }

        if (j.contains("auth_items") && j["auth_items"].contains("offline") && j["auth_items"]["offline"].is_array() && j["auth_items"]["offline"].size() > 0 && j["auth_items"]["offline"][0].contains("refilltoken") && j["auth_items"]["offline"][0].contains("response"))
        {
            item["refilltoken"] = j["auth_items"]["offline"][0]["refilltoken"];
            item["response"].update(j["auth_items"]["offline"][0]["response"]);
            if (debug)
            {
                pam_syslog(pamh, LOG_DEBUG, "Offline refill completed, added %zu new values.\n", j["auth_items"]["offline"][0]["response"].size());
            }
        }
        else
        {
            pam_syslog(pamh, LOG_ERR, "Unable to update offline data because refill response is malformed:\n%s", j.dump(4).c_str());
        }
    }
    return 0;
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

    return parseResponse(strResponse, response);
}

std::string PrivacyIDEA::readAll(std::string file)
{
    std::ifstream inFile(offlineFile);
    if (!inFile)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to open offline file. Error: %d %s", errno, strerror(errno));
    }
    std::string content((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    return content;
}

void PrivacyIDEA::writeAll(std::string file, std::string content)
{
    std::ofstream outFile(file, std::ios::trunc);
    if (!outFile)
    {
        pam_syslog(pamh, LOG_DEBUG, "Unable to open offline file. Error: %d %s", errno, strerror(errno));
        // TODO do not return error here?
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
            FIDOSignRequest data;
            const auto &passkey = jResponse["detail"]["passkey"];
            if (passkey.contains("challenge"))
                data.challenge = passkey["challenge"].get<std::string>();
            if (passkey.contains("message"))
                data.message = passkey["message"].get<std::string>();
            if (passkey.contains("rpId"))
                data.rpId = passkey["rpId"].get<std::string>();
            if (passkey.contains("transaction_id"))
                data.transaction_id = passkey["transaction_id"].get<std::string>();
            if (passkey.contains("user_verification"))
                data.userVerification = passkey["user_verification"].get<std::string>();
            out.signRequest = data;
        }

        if (jDetail.contains("username"))
        {
            out.username = jDetail["username"].get<std::string>();
        }
    }

    // After a successful online authentication, the server may send offline credentials
    if (jResponse.contains("auth_items") && jResponse["auth_items"].is_object())
    {
        const auto& authItems = jResponse["auth_items"];
        if (authItems.contains("offline") && authItems["offline"].is_array())
        {
            pam_syslog(pamh, LOG_DEBUG, "Found offline credentials in server response.");
            for (const auto& offlineItem : authItems["offline"])
            {
                if (offlineItem.contains("response") && offlineItem["response"].is_object() &&
                    offlineItem.contains("user") && offlineItem["user"].is_string() &&
                    offlineItem.contains("serial") && offlineItem["serial"].is_string())
                {
                    const auto& offlineResponse = offlineItem["response"];
                    if (offlineResponse.contains("pubKey") && offlineResponse.contains("credentialId"))
                    {
                        std::string user = offlineItem["user"].get<std::string>();
                        std::string serial = offlineItem["serial"].get<std::string>();
                        std::string pubKey = offlineResponse["pubKey"].get<std::string>();
                        std::string credId = offlineResponse["credentialId"].get<std::string>();

                        pam_syslog(pamh, LOG_INFO, "Storing offline credential for user '%s', serial '%s'.", user.c_str(), serial.c_str());

                        // Find if a credential with this serial already exists and update it, otherwise add a new one.
                        auto it = std::find_if(offlineData.begin(), offlineData.end(),
                                               [&serial](const OfflineFIDOCredential& cred) { return cred.serial == serial; });

                        if (it != offlineData.end()) {
                            it->public_key_hex = pubKey;
                            it->credId = credId;
                            it->username = user;
                            // Keep the signcount
                        } else {
                            offlineData.push_back({pubKey, user, "", credId, serial, 0});
                        }
                    }
                }
            }
        }
    }

    return 0;
}

OfflineFIDOCredential* PrivacyIDEA::_getMutableOfflineCredential(const std::string& serial)
{
    for (auto& cred : offlineData)
    {
        if (cred.serial == serial) {
            return &cred;
        }
    }
    return nullptr;
}

void PrivacyIDEA::updateSignCount(const std::string& serial, uint32_t newSignCount)
{
    OfflineFIDOCredential* cred = _getMutableOfflineCredential(serial);
    if (cred) {
        cred->sign_count = newSignCount;
        pam_syslog(pamh, LOG_DEBUG, "Updated signature count for serial '%s' to %u.", serial.c_str(), newSignCount);
    } else {
        pam_syslog(pamh, LOG_ERR, "Could not update signature count: failed to find credential with serial '%s'.", serial.c_str());
    }
}

std::vector<OfflineFIDOCredential> PrivacyIDEA::findOfflineCredentialsForUser(const std::string& username) const
{
    std::vector<OfflineFIDOCredential> userCredentials;
    for (const auto& cred : offlineData)
    {
        if (cred.username == username)
        {
            userCredentials.push_back(cred);
        }
    }
    return userCredentials;
}

std::optional<OfflineFIDOCredential> PrivacyIDEA::findOfflineCredential(const std::string& serial) const
{
    for (const auto& cred : offlineData)
    {
        if (cred.serial == serial) {
            return cred; // Return a copy wrapped in optional
        }
    }
    return std::nullopt; // Not found
}

std::vector<OfflineFIDOCredential> PrivacyIDEA::getAllOfflineCredentials() const
{
    return offlineData;
}
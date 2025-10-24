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

using namespace std;
using json = nlohmann::json;

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
            offlineData = json::parse(content);
        }
        catch (const json::parse_error &e)
        {
            // TODO keep this debug, because having the file is not required
            pam_syslog(pamh, LOG_DEBUG, "Unable to load offline data: %s", e.what());
        }
    }
}

PrivacyIDEA::~PrivacyIDEA()
{
    if (!offlineData.empty())
    {
        writeAll(offlineFile, offlineData.dump(4));
    }
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

std::string urlEncode(const std::string &input)
{
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (auto c : input)
    {
        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            escaped << c;
        }
        // Any other characters are percent-encoded
        else
        {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int((unsigned char)c);
            escaped << std::nouppercase;
        }
    }

    return escaped.str();
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
    map<string, string> param{
        make_pair("user", user),
        make_pair("pass", pass)};

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
        // return PAM_AUTH_ERR;
    }
    retval = parseResponse(strResponse, response);
    if (retval != 0)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to parse the response from the privacyIDEA server. Response: %s\n Error %d\n",
                   strResponse.c_str(), retval);
        // return PAM_AUTH_ERR;
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
            string tmp = param.first + "=" + urlEncode(param.second) + "&";
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
        headers_list = curl_slist_append(headers_list, ("User-Agent: " + string(PAM_PRIVACYIDEA_USERAGENT)).c_str());

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

    if (!offlineData.contains("offline") || !offlineData["offline"].is_array())
    {
        return OFFLINE_FILE_WRONG_FORMAT;
    }

    for (auto &item : offlineData["offline"])
    {
        if (item.contains("serial") && item["serial"].get<std::string>() == serial)
        {
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

std::string PrivacyIDEA::base64Encode(const unsigned char *data, size_t length)
{
    size_t encoded_len = 4 * ((length + 2) / 3);
    std::string encoded_string(encoded_len, '\0');
    int final_len = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&encoded_string[0]), data, length);
    if (final_len < 0)
    {
        // Handle error, maybe log it
        return "";
    }
    encoded_string.resize(final_len);
    return encoded_string;
}

std::vector<unsigned char> PrivacyIDEA::base64Decode(const std::string &encoded_string)
{
    size_t decoded_len = (encoded_string.length() / 4) * 3; // Max possible length
    std::vector<unsigned char> decoded_data(decoded_len);

    int final_len = EVP_DecodeBlock(decoded_data.data(),
                                    reinterpret_cast<const unsigned char *>(encoded_string.c_str()),
                                    encoded_string.length());
    if (final_len < 0)
    {
        // Handle error, maybe log it
        return {};
    }
    decoded_data.resize(final_len);
    return decoded_data;
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
                data.user_verification = passkey["user_verification"].get<std::string>();
            out.signRequest = data;
        }

        if (jDetail.contains("username"))
        {
            out.username = jDetail["username"].get<std::string>();
        }
    }

    return 0;
}
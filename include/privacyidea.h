#ifndef PAM_PRIVACYIDEA_PRIVACYIDEA_H
#define PAM_PRIVACYIDEA_PRIVACYIDEA_H

#include <string>
#include <map>
#include <security/pam_ext.h>
#include "response.h"
#include "json.hpp"
#include "fido_sign_response.h"
#include "offline_fido_credential.h"

#define PAM_PRIVACYIDEA_USERAGENT "pam-passkey/1.0.0"

#define OFFLINE_SUCCESS 0
#define OFFLINE_FAIL 1
#define OFFLINE_FILE_MISSING 2
#define OFFLINE_FILE_ACCESS_FAIL 3
#define OFFLINE_FILE_PARSE_FAIL 4
#define OFFLINE_FILE_WRONG_FORMAT 5
#define OFFLINE_USER_NOT_FOUND 6
#define OFFLINE_NO_DATA 10
#define OFFLINE_NO_OTPS_LEFT 11

class PrivacyIDEA
{
public:
    PrivacyIDEA(pam_handle_t *pamh, std::string baseURL, std::string realm, bool sslVerify, std::string offlineFile, bool debug, long timeout);

    ~PrivacyIDEA();

    int validateInitializePasskey(Response &response);

    int validateCheck(const std::string &user, const std::string &pass, const std::string &transactionID, Response &response);

    int sendRequest(const std::string &url, const std::map<std::string, std::string> &parameters, const std::map<std::string, std::string> &headers,
                    std::string &response, bool postRequest = true);

    int parseResponse(const std::string &input, Response &out);

    int offlineRefill(const std::string &user, const std::string &lastOTP, const std::string &serial);

    int validateCheckFIDO(const FIDOSignResponse &signResponse, const std::string &transactionId, const std::string &origin, Response &response, const std::string &user = "");

    std::vector<OfflineFIDOCredential> findOfflineCredentialsForUser(const std::string &username) const;

    std::optional<OfflineFIDOCredential> findOfflineCredential(const std::string& serial) const;

    std::vector<OfflineFIDOCredential> getAllOfflineCredentials() const;

    void updateSignCount(const std::string& serial, uint32_t newSignCount);

private:
    pam_handle_t *pamh; // for syslog
    bool debug = false;

    std::string baseURL;
    bool sslVerify;
    std::string realm;
    long timeout = 0;

    std::string offlineFile = "/etc/privacyidea/pam.txt";
    nlohmann::json offlineJson;
    std::vector<OfflineFIDOCredential> offlineData;

    std::string readAll(std::string file);
    // Internal helper to get a mutable pointer for updates
    OfflineFIDOCredential* _getMutableOfflineCredential(const std::string& serial);

    void writeAll(std::string file, std::string content);
};

#endif // PAM_PRIVACYIDEA_PRIVACYIDEA_H
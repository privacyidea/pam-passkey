#ifndef PRIVACYIDEA_PAM_CONFIG_H
#define PRIVACYIDEA_PAM_CONFIG_H

#include <string>

struct Config
{
    std::string url;
    std::string rpId;
    bool disableSslVerify = false;
    bool debug = false;
    std::string realm;
    long timeout = 0; // Timeout in seconds for network requests. 0 means no timeout.
    std::string promptText;
    std::string offlineFile = "/etc/privacyidea/fido-offline-credentials.txt";
    bool noPin = false;
    long offlineExpiry = 30; // Expiry time in days for offline credentials. 0 means no expiry.
    // PIN propagation through the PAM stack:
    //   useFirstPass: take PAM_AUTHTOK from a previous module as the PIN; never prompt.
    //   tryFirstPass: take PAM_AUTHTOK if present; otherwise prompt the user.
    //   passPin:      after a successful prompt, store the PIN as PAM_AUTHTOK so later modules can reuse it.
    bool useFirstPass = false;
    bool tryFirstPass = false;
    bool passPin = false;
    // Seconds to wait for a FIDO device to be inserted before giving up.
    long keyInsertTimeout = 30;
    // Path to a CA bundle / certificate to verify the privacyIDEA server's TLS
    // certificate against. When empty, libcurl uses the system trust store.
    std::string caCertPath;
};

#endif // PRIVACYIDEA_PAM_CONFIG_H
#ifndef PRIVACYIDEA_PAM_CONFIG_H
#define PRIVACYIDEA_PAM_CONFIG_H

#include <string>

struct Config
{
    std::string url;
    std::string rpid;
    bool disableSSLVerify = false;
    bool debug = false;
    std::string realm;
    long timeout = 0; // Timeout in seconds for network requests. 0 means no timeout.
    std::string promptText;
    std::string offlineFile;
    bool noPIN = false;
};

#endif //PRIVACYIDEA_PAM_CONFIG_H
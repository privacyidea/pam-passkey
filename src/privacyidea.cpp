#include "privacyidea.h"
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
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
#include "convert.h"

using json = nlohmann::json;

// On-disk schema version for the offline file. Bumped when the layout changes
// in a way that an older module would mis-parse. Version 0 (or missing key) is
// treated as the pre-versioning legacy layout and is accepted for backwards
// compatibility.
constexpr int OFFLINE_FILE_SCHEMA_VERSION = 1;

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
    j.at("expiry_timestamp").get_to(cred.expiry_timestamp); // Now a std::string
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

PrivacyIDEA::PrivacyIDEA(pam_handle_t *pamh, std::string baseURL, std::string realm, bool sslVerify, std::string offlineFile, bool debug, long timeout, long offlineExpiryDays, std::string caCertPath, std::string rpId)
{
    this->pamh = pamh;
    this->baseURL = baseURL;
    this->sslVerify = sslVerify;
    this->caCertPath = caCertPath;
    this->debug = debug;
    this->timeout = timeout;
    this->realm = realm;
    this->configuredRpId = rpId;
    this->offlineExpirySeconds = offlineExpiryDays * 24 * 60 * 60; // Convert days to seconds

    if (!offlineFile.empty())
    {
        this->offlineFile = offlineFile;
    }

    // Reads do not need to hold any lock: writeAtomically uses rename(2), so
    // a reader sees either the complete old file or the complete new file.
    // The exclusive lock is taken only during the write at destruction time;
    // see writeAtomically().
    std::string content = readAll(this->offlineFile);
    if (!content.empty())
    {
        try
        {
            offlineJson = json::parse(content);
        }
        catch (const std::exception &e)
        {
            pam_syslog(pamh, LOG_WARNING, "Unable to parse offline data file '%s': %s", this->offlineFile.c_str(), e.what());
        }

        if (offlineJson.is_object())
        {
            int diskVersion = 0;
            if (offlineJson.contains("schema_version") && offlineJson["schema_version"].is_number_integer())
                diskVersion = offlineJson["schema_version"].get<int>();
            if (diskVersion > OFFLINE_FILE_SCHEMA_VERSION)
            {
                pam_syslog(pamh, LOG_WARNING, "Offline file '%s' uses schema_version %d but this module only understands up to %d. Treating credentials as unreadable.",
                           this->offlineFile.c_str(), diskVersion, OFFLINE_FILE_SCHEMA_VERSION);
                offlineJson = json::object();
            }
        }
        if (offlineJson.is_object() && offlineJson.contains("fido_offline") && offlineJson["fido_offline"].is_array())
        {
            // Iterate manually so a single corrupted entry (e.g. from a partial
            // write or a schema-incompatible record left by an older version)
            // does not throw out of the load and discard every other stored
            // credential.
            for (const auto &entry : offlineJson["fido_offline"])
            {
                try
                {
                    OfflineFIDOCredential cred;
                    from_json(entry, cred);
                    offlineData.push_back(std::move(cred));
                }
                catch (const std::exception &e)
                {
                    pam_syslog(pamh, LOG_WARNING, "Skipping malformed offline credential entry in '%s': %s", this->offlineFile.c_str(), e.what());
                }
            }
        }
    }
}

PrivacyIDEA::~PrivacyIDEA()
{
    // Only write back when the in-memory offline data was actually modified
    // (server refill, sign-count update, expiry/refill-token eviction, etc.).
    // Wrap in try/catch because json::dump and the underlying allocations can
    // throw bad_alloc. Destructors must never propagate exceptions: if this
    // ran during stack unwinding for an in-flight throw, a second exception
    // would call std::terminate and kill the host daemon.
    try
    {
        if (offlineDataDirty)
        {
            offlineJson["schema_version"] = OFFLINE_FILE_SCHEMA_VERSION;
            offlineJson["fido_offline"] = offlineData;
            writeAtomically(offlineFile, offlineJson.dump(4));
        }
    }
    catch (const std::exception &e)
    {
        pam_syslog(pamh, LOG_ERR, "Suppressed exception while persisting offline file: %s", e.what());
    }
    catch (...)
    {
        pam_syslog(pamh, LOG_ERR, "Suppressed unknown exception while persisting offline file.");
    }
}

// std::getline strips '\n' but not '\r'. A CRLF-saved /etc/machine-id (or
// product_uuid shipped that way in a container image) would otherwise leak
// the '\r' into the User-Agent header, which libcurl rejects. Tabs and
// trailing spaces are stripped too — machine-id values are documented as
// trimmed identifiers, never legitimately containing trailing whitespace.
static void stripTrailingWhitespace(std::string &s)
{
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
}

std::string getMachineId()
{
    std::string machineId;
    std::ifstream idFile;

    // 1. Try /etc/machine-id (standard for systemd)
    idFile.open("/etc/machine-id");
    if (idFile.is_open() && std::getline(idFile, machineId))
    {
        idFile.close();
        stripTrailingWhitespace(machineId);
        if (!machineId.empty())
            return machineId;
    }

    // 2. Try /var/lib/dbus/machine-id (D-Bus machine ID)
    idFile.open("/var/lib/dbus/machine-id");
    if (idFile.is_open() && std::getline(idFile, machineId))
    {
        idFile.close();
        stripTrailingWhitespace(machineId);
        if (!machineId.empty())
            return machineId;
    }

    // 3. Try DMI/SMBIOS product UUID as a hardware-bound fallback
    idFile.open("/sys/class/dmi/id/product_uuid");
    if (idFile.is_open() && std::getline(idFile, machineId))
    {
        idFile.close();
        stripTrailingWhitespace(machineId);
        if (!machineId.empty())
            return machineId;
    }

    return ""; // Return empty if no ID could be found
}

int PrivacyIDEA::validateInitializePasskey(Response &response)
{
    std::map<std::string, std::string> parameters = {{"type", "passkey"}};

    std::string r;
    int res = sendRequest(baseURL + "/validate/initialize", parameters, {}, r, false); // Use GET
    if (res != 0)
    {
        pam_syslog(pamh, LOG_ERR, "Failed to send /validate/initialize request. Curl error: %d (%s)", res, curl_easy_strerror((CURLcode)res));
        return res;
    }

    return parseResponse(r, response);
}

// Cap any single response at 16 MiB. Real privacyIDEA replies are a few KiB at
// most; this limit only fires when something is wrong (or hostile) on the wire.
// Returning a short count tells libcurl to abort the transfer with
// CURLE_WRITE_ERROR — better than letting a runaway server OOM the host (sshd,
// login, lightdm) the PAM module is loaded into.
constexpr size_t MAX_RESPONSE_BYTES = 16ULL * 1024 * 1024;

static size_t writeCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    const size_t chunk = size * nmemb;
    auto *out = static_cast<std::string *>(userp);
    if (out->size() + chunk > MAX_RESPONSE_BYTES)
        return 0; // Abort transfer.
    out->append(static_cast<char *>(contents), chunk);
    return chunk;
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
    std::string readBuffer;
    std::string postData;

    if (debug)
        pam_syslog(pamh, LOG_DEBUG, "Sending request to %s with parameters:", url.c_str());

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
        std::string headerString = header.first + ": " + header.second;
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
    // The new list owns the old one; release ownership from the unique_ptr.
    headers_list.release(); // NOLINT(bugprone-unused-return-value)
    headers_list.reset(slist_raw);

    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers_list.get());

    if (!sslVerify)
    {
        curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 0L);
    }
    else if (!caCertPath.empty())
    {
        // Use the admin-supplied CA bundle / cert instead of the system trust store.
        curl_easy_setopt(curl.get(), CURLOPT_CAINFO, caCertPath.c_str());
    }

    if (timeout > 0)
    {
        curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, timeout);
    }

    // Hardening:
    //  - NOSIGNAL: avoid SIGALRM-based DNS timeouts. PAM modules run inside
    //    sshd/login/lightdm where signal-driven control flow is unsafe.
    //  - FOLLOWLOCATION=0: do not chase redirects to arbitrary hosts.
    //  - REDIR_PROTOCOLS_STR: even though FOLLOWLOCATION is off, set the
    //    redirect-protocol allowlist defensively in case a future maintainer
    //    enables redirects.
    //  - MAXFILESIZE_LARGE: belt-and-suspenders alongside writeCallback's cap.
    curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl.get(), CURLOPT_REDIR_PROTOCOLS_STR, sslVerify ? "https" : "https,http");
    curl_easy_setopt(curl.get(), CURLOPT_MAXFILESIZE_LARGE, static_cast<curl_off_t>(MAX_RESPONSE_BYTES));

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

    if (!realm.empty())
    {
        parameters.try_emplace("realm", realm);
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

std::string PrivacyIDEA::readAll(const std::string &file)
{
    std::ifstream inFile(file);
    if (!inFile)
    { // It's a warning if the file doesn't exist, not a hard error.
        char strerr_buf[128];
        pam_syslog(pamh, LOG_WARNING, "Unable to open offline file '%s'. Error: %d %s", file.c_str(), errno, strerror_r(errno, strerr_buf, sizeof(strerr_buf)));
    }
    return {std::istreambuf_iterator<char>(inFile), std::istreambuf_iterator<char>()};
}

// Ensure the parent directory of `file` exists, creating it with 0700 if it
// doesn't. On a fresh install with no /etc/privacyidea/ directory this is
// the only thing standing between the first successful online auth and a
// "silently failed to persist" scenario that breaks all future offline auth.
static void ensureParentDir(pam_handle_t *pamh, const std::string &file)
{
    const auto lastSlash = file.find_last_of('/');
    if (lastSlash == std::string::npos || lastSlash == 0)
        return; // No parent component, or root-level — nothing to create.
    const std::string fullDir = file.substr(0, lastSlash);

    // mkdir -p semantics: walk each '/'-separated component and create it if
    // missing. Without this, configuring a non-default path like
    // /var/lib/privacyidea/sub/dir/x.json on a fresh install would silently
    // fail to persist offline credentials.
    char strerr_buf[128];
    std::string acc;
    acc.reserve(fullDir.size());
    size_t pos = 0;
    while (pos <= fullDir.size())
    {
        const size_t next = fullDir.find('/', pos);
        const size_t end = (next == std::string::npos) ? fullDir.size() : next;
        acc.assign(fullDir, 0, end);
        if (!acc.empty())
        {
            struct stat st{};
            if (::stat(acc.c_str(), &st) != 0)
            {
                if (errno != ENOENT)
                {
                    pam_syslog(pamh, LOG_WARNING, "stat('%s'): %d %s", acc.c_str(), errno, strerror_r(errno, strerr_buf, sizeof(strerr_buf)));
                    return;
                }
                if (::mkdir(acc.c_str(), 0700) != 0 && errno != EEXIST)
                {
                    pam_syslog(pamh, LOG_WARNING, "mkdir('%s', 0700): %d %s", acc.c_str(), errno, strerror_r(errno, strerr_buf, sizeof(strerr_buf)));
                    return;
                }
            }
        }
        if (next == std::string::npos)
            break;
        pos = next + 1;
    }
}

bool PrivacyIDEA::writeAtomically(const std::string &file, const std::string &content)
{
    ensureParentDir(pamh, file);
    // Stage to <file>.tmp with exclusive creation, write everything, fsync, then
    // rename over the target. A crash, signal, or OOM at any point before the
    // rename leaves the original file intact. Without this, a truncated/empty
    // offline file can erase every stored credential — and since the FIDO key
    // may be the user's only auth method (lightdm/login), that can lock them
    // out of the machine.
    const std::string tmp = file + ".tmp";
    const std::string lockPath = file + ".lock";
    char strerr_buf[128];

    // Serialize concurrent writers via a sidecar .lock file. flock on a
    // sidecar (rather than on `file` itself) keeps the lock identity stable
    // across the rename — flock on the target would be released the moment
    // the underlying inode changes. The lock is acquired briefly here only,
    // NOT for the whole PAM call: a stuck PIN prompt must not block every
    // other concurrent sudo/login on the box.
    //
    // The sidecar is intentionally not unlinked. unlink-while-holding-flock
    // is racy (a second writer that opened the same path between our unlink
    // and close would hold a lock on a now-orphan inode), and in steady-state
    // operation the same inode is reused forever — there is no resource leak,
    // just one empty file per configured offlineFile path.
    int lockFd = ::open(lockPath.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lockFd < 0)
    {
        pam_syslog(pamh, LOG_WARNING, "Unable to create write lock '%s'. Error: %d %s. Skipping offline persistence.",
                   lockPath.c_str(), errno, strerror_r(errno, strerr_buf, sizeof(strerr_buf)));
        return false;
    }
    if (::flock(lockFd, LOCK_EX) != 0)
    {
        pam_syslog(pamh, LOG_WARNING, "flock('%s') failed: %d %s. Skipping offline persistence.",
                   lockPath.c_str(), errno, strerror_r(errno, strerr_buf, sizeof(strerr_buf)));
        ::close(lockFd);
        return false;
    }

    struct LockGuard
    {
        int fd;
        ~LockGuard() { if (fd >= 0) ::close(fd); }
    } lockGuard{lockFd};

    // Best-effort: clean up any stale .tmp left by a previous crashed write.
    ::unlink(tmp.c_str());

    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        pam_syslog(pamh, LOG_ERR, "Unable to create temporary offline file '%s'. Error: %d %s", tmp.c_str(), errno, strerror_r(errno, strerr_buf, sizeof(strerr_buf)));
        return false;
    }

    // Force 0600 even if a permissive umask would have given us something wider.
    if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0)
    {
        pam_syslog(pamh, LOG_WARNING, "fchmod 0600 on '%s' failed: %d %s", tmp.c_str(), errno, strerror_r(errno, strerr_buf, sizeof(strerr_buf)));
    }

    const char *buf = content.data();
    size_t remaining = content.size();
    while (remaining > 0)
    {
        ssize_t n = ::write(fd, buf, remaining);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            pam_syslog(pamh, LOG_ERR, "write() to '%s' failed: %d %s", tmp.c_str(), errno, strerror_r(errno, strerr_buf, sizeof(strerr_buf)));
            ::close(fd);
            ::unlink(tmp.c_str());
            return false;
        }
        buf += n;
        remaining -= static_cast<size_t>(n);
    }

    if (::fsync(fd) != 0)
    {
        pam_syslog(pamh, LOG_WARNING, "fsync('%s') failed: %d %s", tmp.c_str(), errno, strerror_r(errno, strerr_buf, sizeof(strerr_buf)));
    }
    if (::close(fd) != 0)
    {
        pam_syslog(pamh, LOG_ERR, "close('%s') failed: %d %s", tmp.c_str(), errno, strerror_r(errno, strerr_buf, sizeof(strerr_buf)));
        ::unlink(tmp.c_str());
        return false;
    }

    if (::rename(tmp.c_str(), file.c_str()) != 0)
    {
        pam_syslog(pamh, LOG_ERR, "rename('%s' -> '%s') failed: %d %s", tmp.c_str(), file.c_str(), errno, strerror_r(errno, strerr_buf, sizeof(strerr_buf)));
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
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

    // Wrap the rest in a broad catch — a malformed-but-parseable response that
    // has the right shape but wrong types (e.g. result.value being an integer
    // instead of a bool, or result.error.message missing) would otherwise let a
    // json::type_error propagate out of pam_sm_authenticate, which would be
    // undefined behavior at the C linkage boundary.
    try
    {
        if (jResponse.contains("result") && jResponse["result"].is_object())
        {
            const auto &result = jResponse["result"];
            if (result.contains("value") && result["value"].is_boolean() &&
                result.contains("authentication") && result["authentication"].is_string())
            {
                bool v = result["value"].get<bool>();
                auto authentication = result["authentication"].get<std::string>();
                out.authenticationSuccess = v && authentication == "ACCEPT";
            }

            if (result.contains("error") && result["error"].is_object())
            {
                const auto &error = result["error"];
                if (error.contains("message") && error["message"].is_string())
                    out.errorMessage = error["message"].get<std::string>();
                if (error.contains("code") && error["code"].is_number_integer())
                    out.errorCode = error["code"].get<int>();
            }
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

        if (jDetail.contains("username") && jDetail["username"].is_string())
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

                        // Reject any server-shipped offline credential whose rpId
                        // does not match the locally-configured value. The offline
                        // verifier later sets fido_assert_set_rp from this stored
                        // rpId, so accepting a mismatched value here would let a
                        // hostile/misconfigured server seed credentials that
                        // operate under a different RP.
                        if (!configuredRpId.empty() && rpId != configuredRpId)
                        {
                            pam_syslog(pamh, LOG_WARNING,
                                "Refusing offline credential for serial '%s' (user '%s'): server rpId '%s' does not match configured rpId '%s'.",
                                serial.c_str(), user.c_str(), rpId.c_str(), configuredRpId.c_str());
                            continue;
                        }

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
                        offlineDataDirty = true;
                    }
                }
            }
        }
    }
    }
    catch (const json::exception &e)
    {
        pam_syslog(pamh, LOG_ERR, "Type error while extracting server response fields: %s", e.what());
        return 1;
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
        offlineDataDirty = true;
    }
    else
    {
        pam_syslog(pamh, LOG_ERR, "Could not update signature count: failed to find credential with serial '%s'.", serial.c_str());
    }
}

int PrivacyIDEA::offlineRefillFIDO(OfflineFIDOCredential &cred)
{
    if (debug)
        pam_syslog(pamh, LOG_DEBUG, "Attempting FIDO offline refill for user '%s' with serial '%s'.", cred.username.c_str(), cred.serial.c_str());

    if (cred.refilltoken.empty())
        return 0;

    std::map<std::string, std::string> parameters =
        {
            {"pass", ""},
            {"refilltoken", cred.refilltoken},
            {"serial", cred.serial}
        };

    std::map<std::string, std::string> headers;
    std::string response;

    int retval = sendRequest(baseURL + "/validate/offlinerefill", parameters, headers, response);
    if (debug)
        pam_syslog(pamh, LOG_DEBUG, "/validate/offlinerefill: %s", response.c_str());
    if (retval != 0)
    {
        pam_syslog(pamh, LOG_ERR, "FIDO offline refill request failed for serial '%s'. Curl error: %d", cred.serial.c_str(), retval);
        return retval;
    }

    return parseOfflineRefillResponse(response, cred);
}

int PrivacyIDEA::parseOfflineRefillResponse(const std::string &body, OfflineFIDOCredential &cred)
{
    json j;
    try
    {
        j = json::parse(body);
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
        !j["auth_items"]["offline"].empty() && j["auth_items"]["offline"][0].contains("refilltoken"))
    {
        // Successfully validated, save the new refill token
        cred.refilltoken = j["auth_items"]["offline"][0]["refilltoken"].get<std::string>();
        // Also refresh the expiry timestamp if configured
        if (offlineExpirySeconds > 0)
        {
            cred.expiry_timestamp = Convert::timeTToIso8601(time(nullptr) + offlineExpirySeconds);
        }
        offlineDataDirty = true;
    }
    else
    {
        // The response parsed cleanly but was neither a 905 nor a successful refill.
        // Under the server-side `hide_specific_error_message_for_offline_refill`
        // policy, genuine errors (invalid refilltoken, disabled token, wrong OTP,
        // unknown serial, detached binding) all surface here as code 401
        // "Failed offline token refill". We deliberately do NOT treat that as a
        // deletion signal — the safer interpretation is "keep the credential
        // until it expires or until a definitive 905 arrives."
        pam_syslog(pamh, LOG_WARNING, "FIDO offline refill for serial '%s' did not return a new refill token. The credential will remain usable offline until it expires.", cred.serial.c_str());
    }
    return 0;
}

void PrivacyIDEA::refillAllOfflineCredentials()
{
    for (auto it = offlineData.begin(); it != offlineData.end();)
    {
        // First, check for client-side expiry. iso8601ToTimeT returns:
        //   0          → no expiry configured (string was empty)
        //  (time_t)-1  → corrupt timestamp; fail closed (treat as expired)
        //  any other   → parsed UNIX time, compare against now.
        time_t currentExpiry = Convert::iso8601ToTimeT(it->expiry_timestamp);
        const bool expiryConfigured = !it->expiry_timestamp.empty();
        const bool corruptTimestamp = expiryConfigured && currentExpiry == static_cast<time_t>(-1);
        const bool elapsed = expiryConfigured && currentExpiry > 0 && currentExpiry < time(nullptr);
        if (corruptTimestamp || elapsed)
        {
            pam_syslog(pamh, LOG_WARNING, "Offline credential for serial '%s' (user '%s') %s. Removing.",
                       it->serial.c_str(), it->username.c_str(),
                       corruptTimestamp ? "has an unparseable expiry timestamp" : "has expired");
            it = offlineData.erase(it);
            offlineDataDirty = true;
            continue; // Continue to the next iteration
        }

        if (!it->refilltoken.empty())
        {
            if (offlineRefillFIDO(*it) == 905)
            {
                // The refill function returned the special code for deletion.
                it = offlineData.erase(it);
                offlineDataDirty = true;
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
            offlineDataDirty = true;
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
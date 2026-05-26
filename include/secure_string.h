#ifndef PRIVACYIDEA_PAM_SECURE_STRING_H
#define PRIVACYIDEA_PAM_SECURE_STRING_H

#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <openssl/crypto.h>

// A small RAII string wrapper that scrubs its backing buffer on destruction
// using OPENSSL_cleanse, which the compiler is not allowed to elide.
// Intended for short-lived sensitive material (FIDO PINs). Not copyable.
class SecureString
{
public:
    SecureString() = default;

    explicit SecureString(const char *s)
    {
        if (s)
        {
            buf_.assign(s, s + std::strlen(s));
        }
    }

    SecureString(const SecureString &) = delete;
    SecureString &operator=(const SecureString &) = delete;

    SecureString(SecureString &&other) noexcept : buf_(std::move(other.buf_))
    {
        other.cleanse();
    }

    SecureString &operator=(SecureString &&other) noexcept
    {
        if (this != &other)
        {
            cleanse();
            buf_ = std::move(other.buf_);
            other.cleanse();
        }
        return *this;
    }

    ~SecureString() { cleanse(); }

    void assign(const char *s, std::size_t len)
    {
        cleanse();
        if (s && len > 0)
        {
            buf_.assign(s, s + len);
        }
    }

    bool empty() const noexcept { return buf_.empty(); }
    std::size_t size() const noexcept { return buf_.size(); }

    // Returns a NUL-terminated view of the data. The returned pointer is
    // valid until the next non-const operation on this object.
    const char *c_str()
    {
        if (buf_.empty() || buf_.back() != '\0')
        {
            buf_.push_back('\0');
        }
        return buf_.data();
    }

private:
    void cleanse() noexcept
    {
        if (!buf_.empty())
        {
            OPENSSL_cleanse(buf_.data(), buf_.size());
            buf_.clear();
        }
    }

    std::vector<char> buf_;
};

#endif // PRIVACYIDEA_PAM_SECURE_STRING_H

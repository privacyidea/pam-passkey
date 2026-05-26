// Stubs for libpam symbols used by the project source files. Linking the test
// binaries against this stub instead of libpam avoids needing a real PAM
// context (which would require a host application). Only the symbols actually
// referenced by the compiled-in production code need to be defined here.

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <cstdarg>

extern "C"
{
    void pam_syslog(const pam_handle_t *, int, const char *, ...) noexcept
    {
        // No-op: tests don't care about log output. Variadic args ignored.
    }
}

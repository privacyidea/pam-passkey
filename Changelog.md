# 1.1.0 2026-07-03

## Improvements
- **Parallel device polling.** When multiple security keys are connected at the same time, the module now talks to them in parallel — whichever key you touch first is the one used. Previously the user had to touch a specific key chosen by the module.
- The offline credential file path now defaults to `/etc/privacyidea/fido-offline-credentials.txt` when `offlineFile` is not set. The parent directory is created automatically (mode 0700) if it does not exist.
- The `prompt=` configuration option is honored for the offline touch prompt in addition to the online one.
- The compiled module embeds a discoverable version marker: `strings pam_privacyidea_passkey.so | grep PAM_PRIVACYIDEA_BUILD` reports the build version. The User-Agent string and the marker are now driven from a single source (the CMake project version).
- Verbose `debug` logging now covers the offline refill endpoint as well as the main `/validate/check` and `/validate/initialize` flows.

## Hardening
- C++ exceptions are caught at the PAM ABI boundary and translated to PAM error codes, so allocation failures and other unexpected throws cannot escape into the host daemon (sshd, lightdm, login, sudo).
- Offline file writes are atomic.
- The offline file format now carries a `schema_version` key. Files written by a future module version are refused at load time rather than silently mis-parsed. Individual malformed entries are skipped without discarding the rest of the file.
- After a usernameless authentication, the username is validated before being set in the PAM context: NUL and control characters are rejected, `root` is refused, an already-set `PAM_USER` cannot be overridden, and length is capped at 255 bytes.
- The offline signing path enforces the `userVerification` authData flag when a PIN was required, and cross-checks the stored RP ID against the configured `rpid` at sign time.
- Server-supplied offline credentials whose RP ID does not match the locally configured one are rejected at ingest.
- Corrupt offline expiry timestamps are treated as expired instead of silently disabling the expiry check on that credential.
- libcurl is configured defensively: `NOSIGNAL=1` (no SIGALRM interference inside multi-threaded PAM consumers), redirects disabled, redirect protocols restricted, and the response body capped at 16 MiB. `curl_global_init` runs once under a mutex.
- libfido2 is initialized with `FIDO_DISABLE_U2F_FALLBACK`, only FIDO2/Passkey credentials are accepted.
- A failure from `RAND_bytes` (no kernel entropy) now refuses to sign instead of producing an empty challenge.
- `url` is required and validated at startup, misspelled URLs fail loudly rather than as a confusing later auth error.

## Compatibility
- Only ES256 (COSE alg `-7`) credentials are usable offline. Tokens registered with `rsassa-pkcs1v1_5` or `rsassa-pss` continue to work online.

---

# 1.0.0 2026-03-26
## Features

- FIDO2/Passkey (WebAuthn) authentication.
- Online authentication against a privacyIDEA server.
- Offline authentication using locally stored credentials, including signature counter protection against replay attacks.
- Support for multiple connected FIDO devices.
- PIN-based user verification for both online and offline modes.
- Usernameless offline authentication.

### See the [readme](https://github.com/privacyidea/pam-passkey?tab=readme-ov-file#configuration) for configuration
# pam_privacyidea_passkey

A PAM module for authenticating with FIDO2/Passkey credentials against a privacyIDEA server. It supports both online and offline authentication.
This module does not work with Ubuntu 22, as it requires libfido2 in version 1.13.0 or higher.

## Features

- FIDO2/Passkey (WebAuthn) authentication.
- Online authentication against a privacyIDEA server.
- Offline authentication using locally stored credentials, with replay protection against signature reuse. **Only ES256 credentials work offline** — tokens registered with RSA-based algorithms authenticate online only. In practice this affects very few authenticators; YubiKey, Solokey, and platform passkey defaults are all ES256.
- Support for multiple connected FIDO devices: when several security keys are plugged in at once, the module talks to them all in parallel and uses whichever one you touch first.
- PIN-based user verification for both online and offline modes.
- Usernameless offline authentication.

## Configuration

The module is configured by adding it to your PAM stack (e.g., in `/etc/pam.d/sudo` or `/etc/pam.d/common-auth`). Configuration options are passed as arguments on the same line.

**Example for `/etc/pam.d/sudo`:**
```
auth sufficient pam_privacyidea_passkey.so url=[https://your.privacyidea.server](https://your.privacyidea.server) rpid=your.rpid.com debug
```

### Options

Here is a list of all available configuration options:

| Option | Description | Required | Example |
|---|---|---|---|
| `url` | The base URL of your privacyIDEA server. | **Yes** (for online auth) | `url=https://privacyidea.example.com` |
| `rpid` | The Relying Party ID for your FIDO2 credentials. Must match the RP ID configured in privacyIDEA. | **Yes** | `rpid=example.com` |
| `debug` | Enables verbose debug logging to syslog. | No | `debug` |
| `nossl` (alias: `no_ssl`) | Disables SSL certificate verification for requests to the privacyIDEA server. **Use with caution, only for testing.** | No | `nossl` |
| `cacert` (alias: `ca_cert`) | Path to a CA bundle or certificate to verify the privacyIDEA server's TLS certificate against. Useful in on-prem deployments with a private CA when you do not want to install the CA in the system trust store. Ignored if `nossl` is set. | No | `cacert=/etc/privacyidea/ca.pem` |
| `realm` | The privacyIDEA realm to authenticate against. If not specified, the default realm is used. | No | `realm=my_realm` |
| `offlineFile` (alias: `offline_file`) | The path to the file used to store offline credentials. Defaults to `/etc/privacyidea/fido-offline-credentials.txt`. The directory must be writable by the user running the authentication process if offline data needs to be updated. | No | `offlineFile=/var/lib/privacyidea/offline.json` |
| `timeout` | The timeout in seconds for network requests to the privacyIDEA server. A value of `0` means no timeout. | No | `timeout=10` |
| `noPIN` (alias: `no_pin`) | Disables the requirement for a PIN during offline authentication. By default, a PIN is required for offline use. PIN requirement for online authentication is managed by the `webauthn_user_verification_requirement` policy in privacyIDEA. | No | `noPIN` |
| `offlineExpiry` (alias: `offline_expiry`) | The validity period for offline credentials in **days**. After this period, the credential must be refreshed online. Defaults to `30` days. A value of `0` disables expiry. | No | `offlineExpiry=90` |
| `keyInsertTimeout` (alias: `key_insert_timeout`) | Seconds to wait for a FIDO device to be plugged in before giving up. Defaults to `30`. On timeout the module returns `PAM_AUTHINFO_UNAVAIL` so the PAM stack can fall through to another authentication method. | No | `keyInsertTimeout=15` |
| `use_first_pass` | Use the authentication token from a previous PAM module (`PAM_AUTHTOK`) as the FIDO PIN. Do not prompt the user. If no token is available, authentication fails. | No | `use_first_pass` |
| `try_first_pass` | Use `PAM_AUTHTOK` from a previous module as the FIDO PIN if available; otherwise prompt the user. | No | `try_first_pass` |
| `pass_pin` | After a successful PIN prompt, store the PIN as `PAM_AUTHTOK` so subsequent modules in the stack can reuse it. Only effective when the PIN was prompted (not when reused from a previous module). | No | `pass_pin` |
| `prompt` | Custom text shown when asking the user to touch their security key. Overrides any per-token message sent by the server (e.g. via the `passkey_challenge_text` policy). | No | `prompt="Touch your YubiKey"` |

## Skipping FIDO Authentication

There are two ways to skip this module and let the PAM stack fall through to another authentication method (such as a password):

1. **Don't insert a security key.** If no FIDO device is plugged in, the module waits `keyInsertTimeout` seconds and then returns `PAM_AUTHINFO_UNAVAIL`.
2. **Submit an empty PIN.** If the PIN prompt appears and you press Enter without typing a PIN, the module returns `PAM_AUTHINFO_UNAVAIL`.

In both cases, configure the PAM stack so that `authinfo_unavail` falls through, e.g.:

```
auth [success=done authinfo_unavail=ignore default=bad] pam_privacyidea_passkey.so url=... rpid=...
auth required pam_unix.so
```

A timeout on the PIN prompt itself is intentionally not implemented; the two mechanisms above are the supported ways to skip.

## Usernameless Online Authentication

The module also supports usernameless **online** authentication: if no username is supplied to PAM, the security key selects a discoverable credential, privacyIDEA identifies the user from it, and the resulting username is propagated to the rest of the PAM stack.

---

## Offline Authentication

To use offline authentication, you must first provision the offline credentials from the privacyIDEA server.

### Online / Offline Precedence
The module always tries online authentication first. Offline mode is used only when the privacyIDEA server cannot be reached at all — for example, when the network is down or DNS fails. Any actual response from the server (including a rejection) is treated as authoritative; the module does not silently fall back to offline data in that case. The presence of an offline credential file alone does not change this; it exists purely as a fallback when the server is unreachable.

While online, the module also refreshes stored offline credentials in the background so they stay in sync with the server even when the user is authenticating online.

### Provisioning Offline Credentials
An offline credential is created by performing at least one successful **online** authentication with a FIDO token that has been configured for offline use on its token detail page in privacyIDEA. During that online login the necessary credential data is sent to the module and stored locally in the file specified by `offlineFile`. Only ES256 credentials are usable offline; see the [Features](#features) section.

### Usernameless Offline Authentication
If no username is supplied to PAM (for example at a display manager's login screen), the module attempts usernameless offline authentication against all stored offline credentials and identifies the user from whichever credential signs successfully.

If a username is supplied, only that user's offline credentials are tried.

### Multiple Credentials per Key

If your security key holds more than one account for the same server (for example several privacyIDEA users registered on the same key), here is how the module picks one:

- **When a username is supplied to PAM** (the normal case for `sudo`, `login`, `sshd`): no ambiguity. Online, the server tells the key which credential to use. Offline, the module only considers credentials stored for that user.
- **In usernameless mode** (for example some display managers at the login screen): the key picks one itself, usually the most recently used account. This module deliberately does not show a "choose an account" menu, because such a prompt would render unreliably across the many programs that use PAM. If you need to sign in as a specific account, log in with that username instead of relying on usernameless mode.

## Build and Installation

### 1. Prerequisites
You will need a C++ compiler and the development headers for several libraries. On Debian/Ubuntu-based systems, you can install them with the following command:

```bash
sudo apt install build-essential cmake pkg-config libfido2-dev libcbor-dev libcurl4-openssl-dev libssl-dev nlohmann-json3-dev libpam0g-dev
```

This will install:
* `build-essential`: Provides a C++ compiler (like g++) and other essential tools.
* `cmake`: The build system generator.
* `pkg-config`: Used by CMake to find libraries.
* `libfido2-dev`: For FIDO2 device communication.
* `libcbor-dev`: Required by `libfido2` for CBOR data handling.
* `libcurl4-openssl-dev`: For making HTTP requests to the privacyIDEA server.
* `libssl-dev`: Required for cryptographic functions.
* `nlohmann-json3-dev`: For parsing JSON responses from the server.
* `libpam0g-dev`: For interfacing with the PAM stack.

### 2. Build
```bash
mkdir build
cd build
cmake ..
make
```

### 3. Install
```bash
sudo make install
```
This will typically install the `pam_privacyidea_passkey.so` module to `/lib/x86_64-linux-gnu/security/` or a similar PAM module directory, depending on your system.

---


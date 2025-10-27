# pam_privacyidea_passkey

A PAM module for authenticating with FIDO2/Passkey credentials against a privacyIDEA server. It supports both online and offline authentication.

## Features

- FIDO2/Passkey (WebAuthn) authentication.
- Online authentication against a privacyIDEA server.
- Offline authentication using locally stored credentials, including signature counter protection against replay attacks.
- Support for multiple connected FIDO devices.
- PIN-based user verification for both online and offline modes.
- Usernameless offline authentication.

## Configuration

The module is configured by adding it to your PAM stack (e.g., in `/etc/pam.d/sudo` or `/etc/pam.d/common-auth`). Configuration options are passed as arguments on the same line.

**Example for `/etc/pam.d/sudo`:**
```
auth sufficient pam_privacyidea_passkey.so url=https://your.privacyidea.server rpid=your.rpid.com debug
```

### Options

Here is a list of all available configuration options:

| Option | Description | Required | Example |
|---|---|---|---|
| `url` | The base URL of your privacyIDEA server. | **Yes** (for online auth) | `url=https://privacyidea.example.com` |
| `rpid` | The Relying Party ID for your FIDO2 credentials. This must match the RP ID configured in privacyIDEA. | **Yes** | `rpid=example.com` |
| `debug` | Enables verbose debug logging to syslog. | No | `debug` |
| `nossl` | Disables SSL certificate verification for requests to the privacyIDEA server. **Use with caution, only for testing.** | No | `nossl` |
| `realm` | The privacyIDEA realm to authenticate against. If not specified, the default realm is used. | No | `realm=my_realm` |
| `offlineFile` | The path to the file used to store offline credentials. Defaults to `/etc/privacyidea/fido-offline-credentials.txt`. The directory must be writable by the user running the authentication process if offline data needs to be updated. | No | `offlineFile=/var/lib/privacyidea/offline.json` |
| `timeout` | The timeout in seconds for network requests to the privacyIDEA server. A value of `0` means no timeout. | No | `timeout=10` |
| `noPIN` | Disables the requirement for a PIN during offline authentication. By default, a PIN is required for offline use. PIN requirement for online authentication is managed by the `webauthn_user_verification_requirement` policy in privacyIDEA. | No | `noPIN` |
| `offlineExpiry` | The validity period for offline credentials in **days**. After this period, the credential must be refreshed online. Defaults to `30` days. A value of `0` disables expiry. | No | `offlineExpiry=90` |

---

## Offline Authentication

To use offline authentication, you must first provision the offline credentials from the privacyIDEA server.

### Provisioning Offline Credentials
An offline credential is created by performing at least one successful **online** authentication with a FIDO token that has been configured for offline use in your privacyIDEA policies. During this successful online login, the necessary credential data (public key, credential ID, etc.) is sent to the PAM module and stored locally in the file specified by the `offlineFile` option.

### Usernameless Offline Authentication
If the PAM stack does not provide a username (e.g., during a pre-login authentication scenario like `lightdm`), the module will attempt a usernameless offline authentication. It will use all available offline credentials and, upon successful authentication with a security key, will identify the user from the credential that was used. The identified username is then set in the PAM context (`PAM_USER`).

If a username is provided by the PAM stack, the module will only attempt to use the offline credentials associated with that specific user.

## Build and Installation

To build and install `pam_privacyidea_passkey`, follow these steps:

1.  **Prerequisites**:
    You will need a C++ compiler and the development headers for several libraries. On Debian/Ubuntu-based systems, you can install them with the following command:

    ```bash
    sudo apt install build-essential cmake libfido2-dev libcurl4-openssl-dev nlohmann-json3-dev libpam0g-dev
    ```

    This will install:
    *   `build-essential`: Provides a C++ compiler (like g++) and other essential tools.
    *   `cmake`: The build system generator.
    *   `libfido2-dev`: For FIDO2 device communication.
    *   `libcurl4-openssl-dev`: For making HTTP requests to the privacyIDEA server.
    *   `nlohmann-json3-dev`: For parsing JSON responses from the server.
    *   `libpam0g-dev`: For interfacing with the PAM stack.

2.  **Build**:
    ```bash
    mkdir build
    cd build
    cmake ..
    make
    ```

3.  **Install**:
    ```bash
    sudo make install
    ```
    This will typically install the `pam_privacyidea_passkey.so` module to `/lib/x86_64-linux-gnu/security/` or a similar PAM module directory, depending on your system.
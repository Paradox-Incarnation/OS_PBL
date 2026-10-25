# Security design

## Model

The trusted computing base is the SecureOS process, its OpenSSL library, and the operating-system account that owns `data`. The user database stores `username|role|salt|scrypt-derived-password`. The first local registration becomes Admin; there is no shipped administrator password. Only Admin can change another account’s role, and an Admin cannot change their own role through the interface.

Every sensitive service asks `allowed(role, action)`. Thus bypassing a hidden menu item is not enough to bypass policy. User-controlled filenames are rejected unless they are a simple single filename. Encryption stores no key in the project; its GCM tag authenticates the encrypted bytes.

## Threats addressed

- Database exposure does not reveal plaintext passwords and each salt is unique.
- Brute force is made more expensive by scrypt and short-term failed-login limiting.
- Viewers cannot mutate files or elevate privileges.
- `..`, separators, and absolute paths cannot target arbitrary files.
- AES-GCM rejects modified ciphertext and incorrect keys.

## Boundaries and limitations

This application cannot stop an attacker who controls the OS account or modifies its files. Audit logs are append-only by convention, not cryptographically protected. Role permissions are application policy and do not create native filesystem ACLs. Password text is visible while entered because portable hidden-password input is outside this small C++17 implementation. Use a terminal/account you trust. The demo key workflow is deliberately explicit: a real deployment needs OS-keystore integration and key recovery policy.

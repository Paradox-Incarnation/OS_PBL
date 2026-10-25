# SecureOS

SecureOS is a C++17 terminal security simulator for learning authentication, role-based access control, audit logging, and authenticated file encryption. It is a user-space teaching project, not a real operating system or a replacement for Windows/Linux security.

## Problem and objectives

Small programs often trust anyone who opens them and store data without protection. SecureOS demonstrates how a program can verify a user, decide what the user may do, and protect a file even if copied. It avoids plaintext password storage, enforces roles inside sensitive operations, rejects unsafe filenames, and detects modified encrypted data.

Authentication is checking a student ID; access control is allowing only library staff into the archive; encryption is putting a document in a locked tamper-evident box.

## Features

- First registered account becomes Admin without a default password; later registrations are Viewers.
- Passwords use OpenSSL `EVP_PBE_scrypt` with a fresh random 16-byte salt. No plaintext or plain SHA-256 passwords are stored.
- Login failures are recorded and five failures per username are rate-limited for the current run.
- Admin, Editor, and Viewer roles, enforced in the service functions.
- Application-managed `data/files`; path traversal and absolute paths are rejected.
- AES-256-GCM encryption with random keys, nonces, and authentication tags. Wrong keys and altered ciphertext fail safely.
- Timestamped audit events never include passwords, keys, or file contents.

## Technologies and structure

OpenSSL 3 provides scrypt, cryptographically secure random bytes, and AES-GCM. CMake builds the project.

```
src/       program modules and terminal UI
include/   public class headers
tests/     automated security checks
docs/      beginner explanations and viva preparation
data/      created at runtime; users, logs, managed files (ignored)
```

## Install, build, and run

Install CMake, a C++17 compiler, and OpenSSL development files. On the supplied MSYS2/MinGW environment:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH=C:/msys64/mingw64
cmake --build build
ctest --test-dir build --output-on-failure
.\build\secureos.exe
```

If the executable cannot find `libcrypto-3-x64.dll`, add `C:\msys64\mingw64\bin` to `PATH` for that shell.

## First use and menu flow

1. Start SecureOS and choose Register. The first account is safely made Admin.
2. Log in, then use File Manager to create a managed text file.
3. Admin may use User Management to give a registered account the Editor role.
4. Encrypt a file and copy the displayed 64-character key to a password manager or other secure location.
5. Decrypt only after supplying that key. SecureOS intentionally does not save encryption keys.

Example: `admin` creates `notes.txt`, encrypts it as `notes.sos`, and receives a key. Decrypting `notes.sos` with a different key is rejected. Viewer can read managed files but cannot create, edit, delete, encrypt, decrypt, view logs, or manage users.

## Main code guide

- `auth.cpp`: user database, salted scrypt verification, registration, password changes, and roles.
- `access_control.cpp`: the central role/action policy.
- `file_manager.cpp`: safe managed-file operations.
- `encryption.cpp`: the `SOS1 | nonce | tag | ciphertext` AES-GCM file format.
- `audit_log.cpp`: append-only local event log.
- `ui.cpp`: validated `getline` menus; EOF exits cleanly.

Authentication decides who is calling; access control decides what they may do; encryption protects the bytes after they leave the application. Together they reduce unauthorized use, accidental privilege escalation, path traversal, password disclosure, and undetected ciphertext tampering.

## Key management and limitations

The AES key appears once and is not written beside the encrypted file. For a classroom demo, save it in a password manager or protected removable device. Losing it means losing the file. A production system would use an OS key store, per-user key wrapping, secure backups, persistent lockout, file-level ACLs, protected audit storage, hidden password input, and MFA. Local `data/audit.log` is useful for learning but is not tamper-proof.

## Tests

`tests/test_secureos.cpp` tests successful/failed login, password changes, role restrictions, denied role changes, traversal rejection, AES-GCM round trip, wrong-key rejection, and audit secrecy. Run with CTest above.

## Viva questions

See [docs/VIVA_QUESTIONS.md](docs/VIVA_QUESTIONS.md), [docs/PROJECT_EXPLANATION.md](docs/PROJECT_EXPLANATION.md), and [docs/SECURITY_DESIGN.md](docs/SECURITY_DESIGN.md).

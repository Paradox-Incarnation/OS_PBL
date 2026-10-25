# SecureOS project explanation

SecureOS starts in `main.cpp`, which calls the terminal UI. The UI creates one audit logger, authentication service, file manager, and encryption service, all using the runtime `data` folder. A user registers, logs in, and receives a `User` object containing a trusted role loaded from the application database.

When someone types a password, SecureOS combines it with that user’s random salt and passes it to scrypt. It compares the resulting derived value with the stored derived value using a constant-time comparison. The original password is never saved.

Before a file action, the file manager checks both the role and filename. A filename must be only one simple name, so `../secret` and `C:\secret` cannot leave `data/files`. Before encryption, AES-GCM creates a fresh random key and nonce. The file starts with `SOS1`, then nonce, authentication tag, and ciphertext. AES-GCM will refuse to decrypt altered data.

The application records an event after important actions. The event records who and what happened, not the secret content involved. This makes it easier to explain security incidents without creating another secret leak.

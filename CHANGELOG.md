# Changelog

## Unreleased
- Fixed: tag counter now starts at a random value on every probe, so a reloaded module no longer receives the board's cached replies from the previous session.
- `bbcrypt enc|dec` refuses input over 192 KiB (one AF_ALG request must fit the socket send buffer) instead of hanging.
- Added: GCM (`gcm-aes-bbcrypto`), asynchronous hashes (`sha1/sha256/hmac-sha256-async-bbcrypto`), eleven demos, deploy scripts for other machines, repo-wide formatter, lint targets, CI, LICENSE (GPL-2.0).

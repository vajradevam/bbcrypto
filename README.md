# bbcrypto - USB crypto accelerator for the kernel crypto API

A BeagleBone Black plugged into the laptop's USB port executes crypto requests for the laptop.
The laptop kernel module registers algorithms with the crypto API; every operation is sent over a
USB bulk pipe to `bbcryptod` on the board, which runs it through the board's own kernel via AF_ALG
(on the AM335x that is the hardware: `omap-sha256`, `cbc-aes-omap`, ...).

| algorithm        | driver name (use with AF_ALG bind) | API |
|------------------|-------------------------------------|-----|
| sha1             | `sha1-bbcrypto`                     | shash (synchronous) |
| sha256           | `sha256-bbcrypto`                   | shash |
| hmac(sha256)     | `hmac-sha256-bbcrypto`              | shash |
| sha1, sha256, hmac(sha256) | `sha1-async-bbcrypto`, `sha256-async-bbcrypto`, `hmac-sha256-async-bbcrypto` | **ahash** (asynchronous; same board sessions) |
| ecb/cbc/ctr(aes) | `ecb-aes-bbcrypto` / `cbc-aes-bbcrypto` / `ctr-aes-bbcrypto` | skcipher, **asynchronous** |
| gcm(aes)         | `gcm-aes-bbcrypto`                  | **aead**, asynchronous, one command per request (aad + data <= 32 KiB) |

Registered at priority 50 (module parameter `prio`), so nothing uses them unless asked by driver
name or `prio` is raised above the in-kernel implementations.

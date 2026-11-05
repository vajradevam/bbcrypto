/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bbcrypto wire protocol, shared by the laptop kernel module and the board daemon.
 *
 * Transport: one vendor-specific USB interface (class 0xff / subclass 0x5c / protocol 1)
 * with one bulk-OUT (host->board) and one bulk-IN (board->host) endpoint.
 * One request = one bulk transfer = struct bbc_req + key + iv + data.
 * One response = one bulk transfer = struct bbc_resp + iv + data.
 * Up to `window` requests are in flight; each carries a tag and the reply echoes it, so the host
 * matches replies by tag. The board keeps recent replies: a repeated tag (host retry) is answered
 * from that cache instead of being executed again.
 * If a message length is an exact multiple of 512 one pad byte is appended so the
 * transfer always ends in a short packet (no zero-length packets are needed).
 * All integers are little-endian.
 */
#ifndef BBC_PROTO_H
#define BBC_PROTO_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef __le32 bbc_u32;
typedef __le16 bbc_u16;
#else
#include <stdint.h>
typedef uint32_t bbc_u32;
typedef uint16_t bbc_u16;
#endif

#define BBC_MAGIC 0x43434242u /* "BBCC" */
#define BBC_USB_CLASS 0xff
#define BBC_USB_SUBCLASS 0x5c
#define BBC_USB_PROTO 1

#define BBC_MAX_DATA (32 * 1024) /* max payload bytes per request */
#define BBC_MAX_KEY 128
#define BBC_MAX_IV 16
#define BBC_MAX_MSG (BBC_MAX_DATA + BBC_MAX_KEY + BBC_MAX_IV + 64)

enum bbc_op {
	BBC_OP_PING = 0,    /* data echoed back */
	BBC_OP_HASH_NEW,    /* alg(+key for hmac) -> id */
	BBC_OP_HASH_UPDATE, /* id, data */
	BBC_OP_HASH_FINAL,  /* id, optional data -> digest; frees id */
	BBC_OP_HASH_CLONE,  /* id -> new id with the same state */
	BBC_OP_HASH_FREE,   /* id */
	BBC_OP_CIPHER,	    /* alg, key, iv, data (flags&1 = decrypt) -> new iv + data */
	BBC_OP_INFO,	    /* -> text describing the board's algorithm drivers */
	BBC_OP_AEAD, /* alg, key, iv, data = aad||text(||tag) -> aad||text(||tag); stateless */
};

enum bbc_alg {
	BBC_ALG_SHA1 = 1,
	BBC_ALG_SHA256,
	BBC_ALG_HMAC_SHA256,
	BBC_ALG_ECB_AES,
	BBC_ALG_CBC_AES,
	BBC_ALG_CTR_AES,
	BBC_ALG_GCM_AES,
};

#define BBC_F_DECRYPT 1 /* BBC_OP_CIPHER */
/*
 * BBC_OP_AEAD: id = assoc length, flags bits 8..15 = tag length, flags&1 = decrypt.
 * Request data is aad||plaintext (encrypt) or aad||ciphertext||tag (decrypt); the reply data is
 * aad||ciphertext||tag or aad||plaintext. A failed tag check returns -EBADMSG (-74).
 */
#define BBC_F_TAGSHIFT 8
#define BBC_F_ONESHOT 2 /* BBC_OP_HASH_NEW: key+data in, digest out, no session */

struct bbc_req {
	bbc_u32 magic;
	bbc_u32 tag;
	bbc_u16 op;
	bbc_u16 flags;
	bbc_u32 id;
	bbc_u32 alg;
	bbc_u32 keylen;
	bbc_u32 ivlen;
	bbc_u32 datalen;
} __attribute__((packed)); /* 32 bytes, then key, iv, data */

struct bbc_resp {
	bbc_u32 magic;
	bbc_u32 tag;
	bbc_u32 status; /* 0 or negative errno */
	bbc_u32 id;
	bbc_u32 ivlen;
	bbc_u32 datalen;
} __attribute__((packed)); /* 24 bytes, then iv, data */

#endif

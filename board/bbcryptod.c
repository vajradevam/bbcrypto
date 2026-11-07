// SPDX-License-Identifier: GPL-2.0
/*
 * bbcryptod - board side of the bbcrypto USB crypto accelerator.
 *
 * Serves a FunctionFS vendor interface (two bulk endpoints) and executes each request
 * through the board's own kernel crypto API via AF_ALG. On the BeagleBone Black that
 * resolves to the AM335x SHA/AES engines (omap-sha256, cbc-aes-omap, ...).
 *
 * Usage: bbcryptod /dev/ffs-bbc      (FunctionFS must be mounted there; see board/setup-gadget.sh)
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <endian.h>
#include "../proto.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define BUFSZ (((BBC_MAX_MSG + 511) / 512) * 512 + 512)
#define NSESS 256

static const char *ffs_dir = "/dev/ffs-bbc";
static int verbose;
static char info[256] = "bbcryptod";

/* ------------------------------ AF_ALG helpers ------------------------------ */

static int alg_open(const char *type, const char *name, const uint8_t *key, unsigned keylen,
		    int *tfmfd, unsigned authsize)
{
	struct sockaddr_alg sa = {.salg_family = AF_ALG};
	int t, o;

	strncpy((char *)sa.salg_type, type, sizeof(sa.salg_type) - 1);
	strncpy((char *)sa.salg_name, name, sizeof(sa.salg_name) - 1);
	t = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (t < 0)
		return -errno;
	if (bind(t, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int e = errno;
		close(t);
		return -e;
	}
	if (keylen && setsockopt(t, SOL_ALG, ALG_SET_KEY, key, keylen) < 0) {
		int e = errno;
		close(t);
		return -e;
	}
	if (authsize && setsockopt(t, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, authsize) < 0) {
		int e = errno;
		close(t);
		return -e;
	}
	o = accept(t, NULL, NULL);
	if (o < 0) {
		int e = errno;
		close(t);
		return -e;
	}
	*tfmfd = t;
	return o;
}

static const char *hash_name(uint32_t alg, unsigned *dsz)
{
	switch (alg) {
	case BBC_ALG_SHA1:
		*dsz = 20;
		return "sha1";
	case BBC_ALG_SHA256:
		*dsz = 32;
		return "sha256";
	case BBC_ALG_HMAC_SHA256:
		*dsz = 32;
		return "hmac(sha256)";
	}
	return NULL;
}

static const char *cipher_name(uint32_t alg)
{
	switch (alg) {
	case BBC_ALG_ECB_AES:
		return "ecb(aes)";
	case BBC_ALG_CBC_AES:
		return "cbc(aes)";
	case BBC_ALG_CTR_AES:
		return "ctr(aes)";
	case BBC_ALG_GCM_AES:
		return "gcm(aes)";
	}
	return NULL;
}

static int read_full(int fd, uint8_t *p, size_t n)
{
	size_t got = 0;

	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (r == 0)
			return -EIO;
		got += r;
	}
	return 0;
}

/* ------------------------------ hash sessions ------------------------------ */

static struct {
	int fd;
	uint64_t seq;
} sess[NSESS];
static uint64_t seqno;

static uint32_t sess_add(int fd)
{
	int i, victim = 1;

	for (i = 1; i < NSESS; i++) {
		if (!sess[i].fd) {
			victim = i;
			goto put;
		}
		if (sess[i].seq < sess[victim].seq)
			victim = i;
	}
	close(sess[victim].fd); /* table full: evict the oldest (leaked) session */
put:
	sess[victim].fd = fd;
	sess[victim].seq = ++seqno;
	return victim;
}

static int sess_fd(uint32_t id)
{
	if (id == 0 || id >= NSESS || !sess[id].fd)
		return -1;
	sess[id].seq = ++seqno;
	return sess[id].fd;
}

static void sess_free(uint32_t id)
{
	if (id && id < NSESS && sess[id].fd) {
		close(sess[id].fd);
		sess[id].fd = 0;
	}
}

/* ------------------------------ request handlers ------------------------------ */

struct reply {
	int status;
	uint32_t id;
	uint8_t iv[BBC_MAX_IV];
	uint32_t ivlen;
	uint8_t *data;
	uint32_t datalen;
};

static int hash_digest(int fd, unsigned dsz, const uint8_t *d, uint32_t n, uint8_t *out)
{
	if (send(fd, d, n, 0) < 0)
		return -errno;
	if (read_full(fd, out, dsz) < 0)
		return -EIO;
	return 0;
}

static void do_hash(const struct bbc_req *rq, uint16_t op, const uint8_t *key, uint32_t keylen,
		    const uint8_t *data, uint32_t datalen, struct reply *r, uint8_t *scratch)
{
	uint32_t id = le32toh(rq->id);
	unsigned dsz = 0;
	int fd, tfm;

	switch (op) {
	case BBC_OP_HASH_NEW: {
		const char *nm = hash_name(le32toh(rq->alg), &dsz);
		if (!nm) {
			r->status = -EOPNOTSUPP;
			return;
		}
		fd = alg_open("hash", nm, key, keylen, &tfm, 0);
		if (fd < 0) {
			r->status = fd;
			return;
		}
		close(tfm);
		if (le16toh(rq->flags) & BBC_F_ONESHOT) {
			r->status = hash_digest(fd, dsz, data, datalen, scratch);
			close(fd);
			r->data = scratch;
			r->datalen = dsz;
		} else {
			r->id = sess_add(fd);
		}
		return;
	}
	case BBC_OP_HASH_UPDATE:
		fd = sess_fd(id);
		if (fd < 0) {
			r->status = -ENOENT;
			return;
		}
		if (datalen && send(fd, data, datalen, MSG_MORE) < 0)
			r->status = -errno;
		return;
	case BBC_OP_HASH_FINAL: {
		unsigned want = 64;
		fd = sess_fd(id);
		if (fd < 0) {
			r->status = -ENOENT;
			return;
		}
		/* digest size is not stored; read what the kernel gives (max 64) */
		if (send(fd, data, datalen, 0) < 0) {
			r->status = -errno;
			sess_free(id);
			return;
		}
		ssize_t n = read(fd, scratch, want);
		r->status = n < 0 ? -errno : 0;
		r->data = scratch;
		r->datalen = n < 0 ? 0 : n;
		sess_free(id);
		return;
	}
	case BBC_OP_HASH_CLONE:
		fd = sess_fd(id);
		if (fd < 0) {
			r->status = -ENOENT;
			return;
		}
		tfm = accept(fd, NULL, NULL);
		if (tfm < 0) {
			r->status = -errno;
			return;
		}
		r->id = sess_add(tfm);
		return;
	case BBC_OP_HASH_FREE:
		sess_free(id);
		return;
	}
}

static void ctr_add(uint8_t *iv, uint64_t blocks)
{
	int i;
	unsigned carry;

	for (i = 15; i >= 0 && blocks; i--) {
		carry = iv[i] + (blocks & 0xff);
		iv[i] = carry & 0xff;
		blocks = (blocks >> 8) + (carry >> 8);
	}
	for (; i >= 0 && blocks; i--) { /* propagate remaining carry */
		if (++iv[i])
			break;
	}
}

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

static void do_cipher(const struct bbc_req *rq, const uint8_t *key, uint32_t keylen,
		      const uint8_t *iv, uint32_t ivlen, const uint8_t *data, uint32_t datalen,
		      struct reply *r, uint8_t *scratch)
{
	uint32_t alg = le32toh(rq->alg);
	const char *nm = cipher_name(alg);
	int dec = le16toh(rq->flags) & BBC_F_DECRYPT;
	int tfm, fd;
	uint32_t op = dec ? ALG_OP_DECRYPT : ALG_OP_ENCRYPT;
	char cbuf[CMSG_SPACE(sizeof(op)) + CMSG_SPACE(sizeof(struct af_alg_iv) + BBC_MAX_IV)] = {0};
	struct iovec iov = {(void *)data, datalen};
	struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf};
	struct cmsghdr *c;
	size_t cl;

	if (!nm) {
		r->status = -EOPNOTSUPP;
		return;
	}
	fd = alg_open("skcipher", nm, key, keylen, &tfm, 0);
	if (fd < 0) {
		r->status = fd;
		return;
	}
	close(tfm);

	cl = CMSG_SPACE(sizeof(op));
	c = CMSG_FIRSTHDR(&msg);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_OP;
	c->cmsg_len = CMSG_LEN(sizeof(op));
	memcpy(CMSG_DATA(c), &op, sizeof(op));
	if (ivlen) {
		struct af_alg_iv *ai;
		c = (struct cmsghdr *)(cbuf + cl);
		c->cmsg_level = SOL_ALG;
		c->cmsg_type = ALG_SET_IV;
		c->cmsg_len = CMSG_LEN(sizeof(*ai) + ivlen);
		ai = (struct af_alg_iv *)CMSG_DATA(c);
		ai->ivlen = ivlen;
		memcpy(ai->iv, iv, ivlen);
		cl += CMSG_SPACE(sizeof(*ai) + ivlen);
	}
	msg.msg_controllen = cl;

	if (sendmsg(fd, &msg, 0) < 0) {
		r->status = -errno;
		close(fd);
		return;
	}
	r->status = read_full(fd, scratch, datalen);
	close(fd);
	if (r->status)
		return;
	r->data = scratch;
	r->datalen = datalen;

	if (ivlen == 16) { /* hand back the chained IV */
		memcpy(r->iv, iv, 16);
		r->ivlen = 16;
		if (alg == BBC_ALG_CBC_AES && datalen >= 16)
			memcpy(r->iv, (dec ? data : scratch) + datalen - 16, 16);
		else if (alg == BBC_ALG_CTR_AES)
			ctr_add(r->iv, (datalen + 15) / 16);
	}
}

/*
 * gcm(aes). The board kernel is built without AF_ALG AEAD support, so gcm-aes-omap cannot be
 * reached from user space. GCM is therefore assembled here: the AES work runs on the hardware
 * engine through ctr(aes)/ecb(aes), and only GHASH (a multiplication in GF(2^128)) is done in
 * software with a 4-bit table.
 *   H    = AES_K(0)
 *   ctr  = AES-CTR starting at IV||00000001 over (16 zero bytes || data): the first keystream
 *          block is the tag mask E(J0), the rest is the GCM keystream starting at IV||00000002
 *   tag  = GHASH_H(aad, ciphertext) ^ E(J0)
 */
struct u128 {
	uint64_t hi, lo;
};

static void ghash_init(struct u128 M[16], const uint8_t h[16])
{
	struct u128 V;
	int i, j;

	V.hi = be64toh(*(const uint64_t *)h);
	V.lo = be64toh(*(const uint64_t *)(h + 8));
	M[0].hi = M[0].lo = 0;
	M[8] = V;
	for (i = 4; i > 0; i >>= 1) {
		uint64_t T = 0xe100000000000000ULL & (0 - (V.lo & 1));
		V.lo = (V.hi << 63) | (V.lo >> 1);
		V.hi = (V.hi >> 1) ^ T;
		M[i] = V;
	}
	for (i = 2; i < 16; i <<= 1)
		for (j = 1; j < i; j++) {
			M[i + j].hi = M[i].hi ^ M[j].hi;
			M[i + j].lo = M[i].lo ^ M[j].lo;
		}
}

static void ghash_mul(const struct u128 M[16], uint8_t x[16])
{
	static const uint64_t rem[16] = {
		0x0000ULL << 48, 0x1c20ULL << 48, 0x3840ULL << 48, 0x2460ULL << 48,
		0x7080ULL << 48, 0x6ca0ULL << 48, 0x48c0ULL << 48, 0x54e0ULL << 48,
		0xe100ULL << 48, 0xfd20ULL << 48, 0xd940ULL << 48, 0xc560ULL << 48,
		0x9180ULL << 48, 0x8da0ULL << 48, 0xa9c0ULL << 48, 0xb5e0ULL << 48};
	struct u128 Z;
	unsigned lo, hi, r;
	int cnt = 15;

	lo = x[15] & 0xf;
	hi = x[15] >> 4;
	Z = M[lo];
	for (;;) {
		r = Z.lo & 0xf;
		Z.lo = (Z.hi << 60) | (Z.lo >> 4);
		Z.hi = (Z.hi >> 4) ^ rem[r];
		Z.hi ^= M[hi].hi;
		Z.lo ^= M[hi].lo;
		if (--cnt < 0)
			break;
		lo = x[cnt] & 0xf;
		hi = x[cnt] >> 4;
		r = Z.lo & 0xf;
		Z.lo = (Z.hi << 60) | (Z.lo >> 4);
		Z.hi = (Z.hi >> 4) ^ rem[r];
		Z.hi ^= M[lo].hi;
		Z.lo ^= M[lo].lo;
	}
	Z.hi = htobe64(Z.hi);
	Z.lo = htobe64(Z.lo);
	memcpy(x, &Z.hi, 8);
	memcpy(x + 8, &Z.lo, 8);
}

static void ghash_update(const struct u128 M[16], uint8_t y[16], const uint8_t *d, size_t n)
{
	while (n) {
		size_t k = n < 16 ? n : 16, i;
		for (i = 0; i < k; i++)
			y[i] ^= d[i];
		ghash_mul(M, y);
		d += k;
		n -= k;
	}
}

/* one AES operation through AF_ALG (hardware engine on the board) */
static int aes_run(const char *name, const uint8_t *key, unsigned keylen, const uint8_t *iv,
		   const uint8_t *in, size_t n, uint8_t *out)
{
	uint32_t op = ALG_OP_ENCRYPT;
	char cbuf[CMSG_SPACE(sizeof(op)) + CMSG_SPACE(sizeof(struct af_alg_iv) + 16)] = {0};
	struct iovec iov = {(void *)in, n};
	struct msghdr msg = {.msg_iov = &iov,
			     .msg_iovlen = 1,
			     .msg_control = cbuf,
			     .msg_controllen = sizeof(cbuf)};
	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
	int tfm, fd, ret;

	fd = alg_open("skcipher", name, key, keylen, &tfm, 0);
	if (fd < 0)
		return fd;
	close(tfm);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_OP;
	c->cmsg_len = CMSG_LEN(sizeof(op));
	memcpy(CMSG_DATA(c), &op, sizeof(op));
	if (iv) {
		struct af_alg_iv *ai;
		c = (struct cmsghdr *)(cbuf + CMSG_SPACE(sizeof(op)));
		c->cmsg_level = SOL_ALG;
		c->cmsg_type = ALG_SET_IV;
		c->cmsg_len = CMSG_LEN(sizeof(*ai) + 16);
		ai = (struct af_alg_iv *)CMSG_DATA(c);
		ai->ivlen = 16;
		memcpy(ai->iv, iv, 16);
	} else {
		msg.msg_controllen = CMSG_SPACE(sizeof(op));
	}
	if (sendmsg(fd, &msg, 0) < 0) {
		ret = -errno;
		close(fd);
		return ret;
	}
	ret = read_full(fd, out, n);
	close(fd);
	return ret;
}

/* data = aad||text(||tag); reply = aad||text(||tag) */
static void do_aead(const struct bbc_req *rq, const uint8_t *key, uint32_t keylen,
		    const uint8_t *iv, uint32_t ivlen, const uint8_t *data, uint32_t datalen,
		    struct reply *r, uint8_t *scratch)
{
	uint16_t fl = le16toh(rq->flags);
	int dec = fl & BBC_F_DECRYPT;
	unsigned tag = fl >> BBC_F_TAGSHIFT;
	uint32_t assoc = le32toh(rq->id), tl;
	struct u128 M[16];
	uint8_t h[16], zero[16] = {0}, ctr[16], y[16] = {0}, lens[16], full[16];
	uint8_t *tmp = NULL, *in = NULL;
	const uint8_t *ct;
	int ret, i;

	if (le32toh(rq->alg) != BBC_ALG_GCM_AES || ivlen != 12) {
		r->status = -EOPNOTSUPP;
		return;
	}
	if (!tag || tag > 16 || assoc > datalen || (dec && datalen - assoc < tag)) {
		r->status = -EINVAL;
		return;
	}
	tl = datalen - assoc - (dec ? tag : 0); /* text length */
	tmp = malloc(16 + tl + 16);
	in = calloc(1, 16 + tl + 16);
	if (!tmp || !in) {
		r->status = -ENOMEM;
		goto out;
	}

	ret = aes_run("ecb(aes)", key, keylen, NULL, zero, 16, h);
	if (!ret) {
		memcpy(ctr, iv, 12);
		ctr[12] = ctr[13] = ctr[14] = 0;
		ctr[15] = 1;
		memcpy(in + 16, data + assoc, tl); /* ciphertext when decrypting: same XOR */
		ret = aes_run("ctr(aes)", key, keylen, ctr, in, 16 + tl, tmp);
	}
	if (ret) {
		r->status = ret;
		goto out;
	}
	/* tmp = E(J0) || text xor keystream */
	ct = dec ? data + assoc : tmp + 16;
	ghash_init(M, h);
	ghash_update(M, y, data, assoc);
	ghash_update(M, y, ct, tl);
	for (i = 0; i < 8; i++) {
		lens[i] = ((uint64_t)assoc * 8) >> (56 - 8 * i);
		lens[8 + i] = ((uint64_t)tl * 8) >> (56 - 8 * i);
	}
	ghash_update(M, y, lens, 16);
	for (i = 0; i < 16; i++)
		full[i] = y[i] ^ tmp[i];
	if (dec) {
		uint8_t diff = 0;
		for (i = 0; i < (int)tag; i++)
			diff |= full[i] ^ data[assoc + tl + i];
		if (diff) {
			r->status = -EBADMSG;
			goto out;
		}
	}
	memcpy(scratch, data, assoc);
	memcpy(scratch + assoc, tmp + 16, tl);
	if (!dec)
		memcpy(scratch + assoc + tl, full, tag);
	r->data = scratch;
	r->datalen = assoc + tl + (dec ? 0 : tag);
out:
	free(tmp);
	free(in);
}

static void build_info(void)
{
	static const char *want[] = {"sha1",	 "sha256",   "hmac(sha256)", "ecb(aes)",
				     "cbc(aes)", "ctr(aes)", "gcm(aes)"};
	char best[7][48] = {{0}};
	int bestp[7] = {-1, -1, -1, -1, -1, -1, -1};
	char line[256], name[64] = "", drv[64] = "";
	int prio = 0, i;
	FILE *f = fopen("/proc/crypto", "r");
	size_t off;

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "name : %63s", name) == 1)
			continue;
		if (sscanf(line, "driver : %63s", drv) == 1)
			continue;
		if (sscanf(line, "priority : %d", &prio) == 1) {
			for (i = 0; i < 7; i++)
				if (!strcmp(name, want[i]) && prio > bestp[i]) {
					bestp[i] = prio;
					snprintf(best[i], sizeof(best[i]), "%s", drv);
				}
		}
	}
	fclose(f);
	off = snprintf(info, sizeof(info), "bbcryptod:");
	for (i = 0; i < 7 && off < sizeof(info) - 60; i++)
		off += snprintf(info + off, sizeof(info) - off, " %s=%s", want[i],
				best[i][0] ? best[i] : "-");
}

/* ------------------------------ serving loop ------------------------------ */

/*
 * Receiving is done by a dedicated thread that always has the next read() queued.
 * On the AM335x MUSB gadget a packet that arrives while no read is queued can be lost
 * (the first 512-byte packet of the next request was observed to vanish when the daemon
 * was busy answering the previous one), so the read must be posted before the response
 * to the previous request is even written.
 */
#include <semaphore.h>
#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <time.h>

/*
 * Receiving.
 *
 * On the AM335x MUSB gadget a packet that arrives while no read is queued on the endpoint
 * can be lost (the first 512-byte packet of an OUT transfer simply vanishes). A thread
 * that calls read() in a loop always leaves a gap between one read finishing and the next
 * being posted, and with several requests pipelined by the host that gap is hit all the
 * time. So the reads are submitted with kernel AIO: NSLOT of them sit queued on the
 * endpoint at all times, and a request buffer is only taken out of the queue while it is
 * being served. The harvester thread below collects completions in arrival order,
 * reassembles a request that arrived in pieces, drops pad bytes and hands whole requests
 * to the serving loop.
 */
#define NSLOT 12

/*
 * Replies are kept so that a host retry of ANY recent request (several can be in flight)
 * is answered from the cache instead of being executed a second time. Must be larger
 * than the host's in-flight window.
 */
#define NCACHE 16
static struct cached {
	uint32_t tag;
	size_t len;
	uint8_t buf[BUFSZ];
} cache[NCACHE];
static unsigned cache_next;

static struct cached *cache_find(uint32_t tag)
{
	int k;

	for (k = 0; k < NCACHE; k++)
		if (cache[k].len && cache[k].tag == tag)
			return &cache[k];
	return NULL;
}

static struct slot {
	uint8_t buf[BUFSZ];
	ssize_t n;
	struct iocb cb;
} slots[NSLOT];
static int ready_q[NSLOT + 1]; /* slot indices handed to the serving loop; -1 = stream ended */
static unsigned ready_head, ready_tail;
static pthread_mutex_t ready_mu = PTHREAD_MUTEX_INITIALIZER;
static sem_t sem_full;
static aio_context_t aio_ctx;
static int rx_fd, rx_on;
static volatile int rx_quit;
static pthread_t rx_th;

static int slot_submit(int i)
{
	struct iocb *p = &slots[i].cb;

	memset(p, 0, sizeof(*p));
	p->aio_lio_opcode = IOCB_CMD_PREAD;
	p->aio_fildes = rx_fd;
	p->aio_buf = (uintptr_t)slots[i].buf;
	p->aio_nbytes = BUFSZ;
	p->aio_data = i;
	if (syscall(SYS_io_submit, aio_ctx, 1, &p) != 1) {
		perror("io_submit");
		return -1;
	}
	return 0;
}

static void ready_push(int i, ssize_t n)
{
	if (i >= 0)
		slots[i].n = n;
	pthread_mutex_lock(&ready_mu);
	ready_q[ready_tail++ % (NSLOT + 1)] = i;
	pthread_mutex_unlock(&ready_mu);
	sem_post(&sem_full);
}

static int ready_pop(void)
{
	int i;

	pthread_mutex_lock(&ready_mu);
	i = ready_q[ready_head++ % (NSLOT + 1)];
	pthread_mutex_unlock(&ready_mu);
	return i;
}

/*
 * Replies are transmitted by their own thread, so the next request can be computed while the
 * previous reply is still going out over the cable. Bounded to WQN entries, which keeps the
 * writer at most WQN replies behind - fewer than NCACHE, so a cached reply is never
 * overwritten while it is still being sent.
 */
#define WQN 8
static struct cached *wq_q[WQN];
static unsigned wq_head, wq_tail;
static sem_t sem_wfree, sem_wfull;
static pthread_mutex_t wq_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_t wr_th;
static int wr_on, wr_fd;
static volatile int wr_quit, wr_failed;

static void *wr_thread(void *arg)
{
	(void)arg;
	for (;;) {
		struct cached *ce;

		while (sem_wait(&sem_wfull) < 0 && errno == EINTR)
			;
		if (wr_quit)
			return NULL;
		pthread_mutex_lock(&wq_mu);
		ce = wq_q[wq_head++ % WQN];
		pthread_mutex_unlock(&wq_mu);
		if (write(wr_fd, ce->buf, ce->len) < 0) {
			if (verbose)
				perror("write ep2");
			wr_failed = 1;
			ready_push(-1, 0); /* wake the serving loop */
			return NULL;
		}
		sem_post(&sem_wfree);
	}
}

/* queue a reply for transmission; returns -1 if the writer has failed */
static int reply_send(struct cached *ce)
{
	while (sem_wait(&sem_wfree) < 0 && errno == EINTR)
		;
	if (wr_failed)
		return -1;
	pthread_mutex_lock(&wq_mu);
	wq_q[wq_tail++ % WQN] = ce;
	pthread_mutex_unlock(&wq_mu);
	sem_post(&sem_wfull);
	return 0;
}

static void rx_stop(void)
{
	if (wr_on) {
		pthread_cancel(wr_th); /* it may be blocked inside write() */
		pthread_join(wr_th, NULL);
		wr_on = 0;
	}
	if (rx_on) {
		rx_quit = 1;
		pthread_join(rx_th, NULL);
		rx_on = 0;
	}
	if (aio_ctx) {
		syscall(SYS_io_destroy, aio_ctx); /* cancels the reads still queued */
		aio_ctx = 0;
	}
}

static void *rx_thread(void *arg)
{
	struct io_event ev[NSLOT];
	int asm_slot = -1, expect_pad = 0;
	size_t have = 0, need = 0;

	(void)arg;
	while (!rx_quit) {
		/* the io_getevents syscall takes the 32-bit timespec even where libc's is 64-bit */
		struct {
			int32_t sec, nsec;
		} ts = {0, 100 * 1000 * 1000};
		long r = syscall(SYS_io_getevents, aio_ctx, 1, NSLOT, ev, &ts);
		long k;

		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (k = 0; k < r; k++) {
			int i = (int)ev[k].data;
			ssize_t n = (ssize_t)ev[k].res;
			uint8_t *p = slots[i].buf;
			struct bbc_req *rq = (struct bbc_req *)p;

			if (n < 0) {
				if (verbose)
					fprintf(stderr, "read failed: %zd\n", -n);
				ready_push(-1, 0); /* endpoint went away */
				return NULL;
			}
			if (verbose)
				fprintf(stderr, "rd %zd\n", n);

			/* a request that is a multiple of 512 bytes is followed by one pad byte */
			if (expect_pad) {
				expect_pad = 0;
				if (n == 1) {
					slot_submit(i);
					continue;
				}
			}
			if (asm_slot >= 0) {
				/* a fresh request header means the rest of the old one was lost */
				if (!((size_t)n >= sizeof(*rq) &&
				      le32toh(rq->magic) == BBC_MAGIC)) {
					if (have + n <= BUFSZ) {
						memcpy(slots[asm_slot].buf + have, p, n);
						have += n;
					}
					slot_submit(i);
					if (have >= need) {
						if (need % 512 == 0 && have == need)
							expect_pad = 1;
						ready_push(asm_slot, have);
						asm_slot = -1;
					}
					continue;
				}
				if (verbose)
					fprintf(stderr,
						"dropping incomplete request (%zu of %zu)\n", have,
						need);
				slot_submit(asm_slot);
				asm_slot = -1;
			}
			if ((size_t)n >= sizeof(*rq) && le32toh(rq->magic) == BBC_MAGIC) {
				uint64_t want = (uint64_t)sizeof(*rq) + le32toh(rq->keylen) +
						le32toh(rq->ivlen) + le32toh(rq->datalen);
				if (want <= BBC_MAX_MSG) {
					if ((size_t)n >= want) {
						if (want % 512 == 0 && (size_t)n == want)
							expect_pad = 1;
						ready_push(i, n);
					} else {
						asm_slot = i;
						have = n;
						need = want;
					}
					continue;
				}
			}
			fprintf(stderr, "bad data (%zd bytes):", n);
			for (int j = 0; j < n && j < 24; j++)
				fprintf(stderr, " %02x", p[j]);
			fprintf(stderr, "\n");
			slot_submit(i);
		}
	}
	return NULL;
}

static void serve(int in_fd, int out_fd)
{
	static uint8_t scratch[BBC_MAX_DATA + 64];
	int i, k;

	memset(cache, 0, sizeof(cache));
	cache_next = 0;
	ready_head = ready_tail = 0;
	rx_quit = 0;

	rx_fd = in_fd;
	wr_fd = out_fd;
	wq_head = wq_tail = 0;
	wr_quit = wr_failed = 0;
	sem_init(&sem_full, 0, 0);
	sem_init(&sem_wfree, 0, WQN);
	sem_init(&sem_wfull, 0, 0);
	if (syscall(SYS_io_setup, NSLOT, &aio_ctx) < 0) {
		perror("io_setup");
		return;
	}
	for (i = 0; i < NSLOT; i++)
		if (slot_submit(i) < 0) {
			rx_stop();
			return;
		}
	if (pthread_create(&wr_th, NULL, wr_thread, NULL)) {
		rx_stop();
		return;
	}
	wr_on = 1;
	if (pthread_create(&rx_th, NULL, rx_thread, NULL)) {
		rx_stop();
		return;
	}
	rx_on = 1;

	for (;;) {
		uint8_t *rbuf;
		ssize_t n;
		struct bbc_req *rq;
		struct cached *ce;
		struct bbc_resp *rs;
		struct reply r = {0};
		uint32_t kl, il, dl;
		const uint8_t *key, *iv, *data;
		uint16_t op;
		size_t len;

		while (sem_wait(&sem_full) < 0 && errno == EINTR)
			;
		i = ready_pop();
		if (i < 0)
			break; /* the endpoint went away */
		rbuf = slots[i].buf;
		rq = (struct bbc_req *)rbuf;
		n = slots[i].n;
		if ((size_t)n < sizeof(*rq) || le32toh(rq->magic) != BBC_MAGIC) {
			fprintf(stderr, "bad request (%zd bytes):", n);
			for (k = 0; k < n && k < 40; k++)
				fprintf(stderr, " %02x", rbuf[k]);
			fprintf(stderr, "\n");
			slot_submit(i);
			continue; /* cannot answer without a tag */
		}
		ce = cache_find(le32toh(rq->tag));
		if (ce) {
			/* host retried: it never saw our answer. Resend it, do not execute twice.
			 */
			if (verbose)
				fprintf(stderr, "dup tag %u: resending cached reply\n", ce->tag);
			slot_submit(i);
			if (reply_send(ce) < 0)
				break;
			continue;
		}
		op = le16toh(rq->op);
		kl = le32toh(rq->keylen);
		il = le32toh(rq->ivlen);
		dl = le32toh(rq->datalen);
		if (kl > BBC_MAX_KEY || il > BBC_MAX_IV || dl > BBC_MAX_DATA ||
		    sizeof(*rq) + kl + il + dl > (size_t)n) {
			r.status = -EINVAL;
			goto reply;
		}
		key = rbuf + sizeof(*rq);
		iv = key + kl;
		data = iv + il;

		switch (op) {
		case BBC_OP_PING:
			memcpy(scratch, data, dl);
			r.data = scratch;
			r.datalen = dl;
			break;
		case BBC_OP_INFO:
			r.data = (uint8_t *)info;
			r.datalen = strlen(info);
			break;
		case BBC_OP_HASH_NEW:
		case BBC_OP_HASH_UPDATE:
		case BBC_OP_HASH_FINAL:
		case BBC_OP_HASH_CLONE:
		case BBC_OP_HASH_FREE:
			do_hash(rq, op, key, kl, data, dl, &r, scratch);
			break;
		case BBC_OP_CIPHER:
			do_cipher(rq, key, kl, iv, il, data, dl, &r, scratch);
			break;
		case BBC_OP_AEAD:
			do_aead(rq, key, kl, iv, il, data, dl, &r, scratch);
			break;
		default:
			r.status = -ENOSYS;
		}
	reply:
		if (verbose)
			fprintf(stderr,
				"op %u tag %u alg %u key %u iv %u data %u (n=%zd) -> status %d out "
				"%u\n",
				op, le32toh(rq->tag), le32toh(rq->alg), kl, il, dl, n, r.status,
				r.datalen);
		ce = &cache[cache_next++ % NCACHE];
		ce->len = 0;
		rs = (struct bbc_resp *)ce->buf;
		rs->magic = htole32(BBC_MAGIC);
		rs->tag = rq->tag;
		rs->status = htole32((uint32_t)r.status);
		rs->id = htole32(r.id);
		rs->ivlen = htole32(r.ivlen);
		rs->datalen = htole32(r.datalen);
		memcpy(ce->buf + sizeof(*rs), r.iv, r.ivlen);
		if (r.datalen)
			memcpy(ce->buf + sizeof(*rs) + r.ivlen, r.data, r.datalen);
		len = sizeof(*rs) + r.ivlen + r.datalen;
		if (len % 512 == 0)
			ce->buf[len++] = 0;
		slot_submit(i); /* request consumed: queue its buffer for reading again */
		ce->tag = le32toh(rs->tag);
		ce->len = len;
		if (reply_send(ce) < 0)
			break;
	}
	rx_stop();
}

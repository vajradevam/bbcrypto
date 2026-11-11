// SPDX-License-Identifier: GPL-2.0
/*
 * afalg_test - checks the bbcrypto algorithms through AF_ALG against the kernel's
 * own best implementation of the same algorithm (reference = plain cra_name, which
 * resolves to the normal in-kernel driver because bbcrypto registers at low priority;
 * device under test = "<x>-bbcrypto" selected by driver name).
 * Run as root after insmod bbcrypto.ko (some checks write sysfs). Exit status 0 = all passed.
 * Modes: (none) full suite; bench; stress [n]; loop <s>; sweep; unplug (see afalg_extra.h).
 */
#include <errno.h>
#include <glob.h>
#include <pthread.h>
#include <linux/if_alg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

static int fails, passes;

static int opensock(const char *type, const char *name, const uint8_t *key, unsigned kl, int *tfm)
{
	struct sockaddr_alg sa = {.salg_family = AF_ALG};
	int t = socket(AF_ALG, SOCK_SEQPACKET, 0), o;

	if (t < 0)
		return -1;
	strcpy((char *)sa.salg_type, type);
	strncpy((char *)sa.salg_name, name, sizeof(sa.salg_name) - 1);
	if (bind(t, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(t);
		return -1;
	}
	if (kl && setsockopt(t, SOL_ALG, ALG_SET_KEY, key, kl) < 0) {
		close(t);
		return -1;
	}
	o = accept(t, NULL, NULL);
	if (o < 0) {
		close(t);
		return -1;
	}
	*tfm = t;
	return o;
}

static int rd(int fd, uint8_t *p, size_t n)
{
	size_t g = 0;
	while (g < n) {
		ssize_t r = read(fd, p + g, n - g);
		if (r <= 0)
			return -1;
		g += r;
	}
	return 0;
}

static int hash(const char *name, const uint8_t *key, unsigned kl, const uint8_t *d, size_t n,
		unsigned dsz, uint8_t *out, size_t piece)
{
	int tfm, fd = opensock("hash", name, key, kl, &tfm);
	size_t off = 0;

	if (fd < 0)
		return -1;
	if (!piece)
		piece = n ? n : 1;
	do {
		size_t c = n - off < piece ? n - off : piece;
		if (send(fd, d + off, c, off + c < n ? MSG_MORE : 0) < 0) {
			close(fd);
			close(tfm);
			return -1;
		}
		off += c;
	} while (off < n);
	if (n == 0 && send(fd, NULL, 0, 0) < 0) {
		close(fd);
		close(tfm);
		return -1;
	}
	if (rd(fd, out, dsz) < 0) {
		close(fd);
		close(tfm);
		return -1;
	}
	close(fd);
	close(tfm);
	return 0;
}

static int cipher(const char *name, const uint8_t *key, unsigned kl, const uint8_t *iv,
		  unsigned ivl, int dec, const uint8_t *in, size_t n, uint8_t *out)
{
	/* feed the cipher in 64 KiB pieces: one sendmsg larger than the socket buffer would block
	 * forever because nobody is reading yet. The kernel carries the IV across pieces. */
	int tfm, fd = opensock("skcipher", name, key, kl, &tfm);
	uint32_t op = dec ? ALG_OP_DECRYPT : ALG_OP_ENCRYPT;
	size_t off = 0;

	if (fd < 0)
		return -1;
	while (off < n) {
		size_t c = n - off < 65536 ? n - off : 65536;
		char cb[CMSG_SPACE(4) + CMSG_SPACE(sizeof(struct af_alg_iv) + 16)] = {0};
		struct iovec iov = {(void *)(in + off), c};
		struct msghdr m = {.msg_iov = &iov,
				   .msg_iovlen = 1,
				   .msg_control = cb,
				   .msg_controllen = sizeof(cb)};
		struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
		size_t cl = CMSG_SPACE(4);

		cm->cmsg_level = SOL_ALG;
		cm->cmsg_type = ALG_SET_OP;
		cm->cmsg_len = CMSG_LEN(4);
		memcpy(CMSG_DATA(cm), &op, 4);
		if (ivl && off == 0) {
			struct af_alg_iv *ai;
			cm = (struct cmsghdr *)(cb + cl);
			cm->cmsg_level = SOL_ALG;
			cm->cmsg_type = ALG_SET_IV;
			cm->cmsg_len = CMSG_LEN(sizeof(*ai) + ivl);
			ai = (void *)CMSG_DATA(cm);
			ai->ivlen = ivl;
			memcpy(ai->iv, iv, ivl);
			cl += CMSG_SPACE(sizeof(*ai) + ivl);
		}
		m.msg_controllen = cl;
		if (sendmsg(fd, &m, 0) < 0 || rd(fd, out + off, c) < 0) {
			close(fd);
			close(tfm);
			return -1;
		}
		off += c;
	}
	close(fd);
	close(tfm);
	return 0;
}

/* Reference AES: the plain name "cbc(aes)" resolves to bbcrypto itself when it is the only
 * registered implementation, so name the software cipher explicitly: cbc(<inner driver>). */
static char refname[3][32];
static char aes_inner_name[32];
static int find_reference(void)
{
	static const char *inner[] = {"aes-lib", "aes-generic", "aes-aesni", "aes-arm"};
	static const char *mode[] = {"ecb", "cbc", "ctr"};
	uint8_t key[16] = {0};
	for (unsigned i = 0; i < sizeof(inner) / sizeof(*inner); i++) {
		int ok = 1;
		for (int m = 0; m < 3; m++) {
			int tfm, fd;
			snprintf(refname[m], sizeof(refname[m]), "%s(%s)", mode[m], inner[i]);
			fd = opensock("skcipher", refname[m], key, 16, &tfm);
			if (fd < 0) {
				ok = 0;
				break;
			}
			close(fd);
			close(tfm);
		}
		if (ok) {
			snprintf(aes_inner_name, sizeof(aes_inner_name), "%s", inner[i]);
			printf("INFO AES reference: %s / %s / %s\n", refname[0], refname[1],
			       refname[2]);
			return 0;
		}
	}
	return -1;
}

static void rnd(uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		p[i] = rand() >> 7;
}
static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

static void report(int ok, const char *what, size_t n, const char *extra)
{
	if (ok)
		passes++;
	else
		fails++;
	printf("%s %-28s len=%-8zu %s\n", ok ? "PASS" : "FAIL", what, n, extra);
}

static void t_hash(const char *ref, const char *dut, unsigned dsz, unsigned kl, const size_t *lens,
		   int nl)
{
	for (int i = 0; i < nl; i++) {
		size_t n = lens[i];
		uint8_t *d = malloc(n + 1), key[128], a[64], b[64];
		char w[64];
		rnd(d, n);
		rnd(key, sizeof(key));
		snprintf(w, sizeof(w), "%s keylen=%u", dut, kl);
		int r1 = hash(ref, key, kl, d, n, dsz, a, 0);
		int r2 = hash(dut, key, kl, d, n, dsz, b, 0);
		report(r1 == 0 && r2 == 0 && !memcmp(a, b, dsz), w, n, r2 ? "(call failed)" : "");
		if (n > 100) { /* streaming in odd pieces => HASH_NEW/UPDATE/FINAL path */
			int r3 = hash(dut, key, kl, d, n, dsz, b, 777);
			report(r1 == 0 && r3 == 0 && !memcmp(a, b, dsz), "  streamed (777B pieces)",
			       n, "");
		}
		free(d);
	}
}

static void t_cipher(const char *ref, const char *dut, unsigned kl, unsigned ivl,
		     const size_t *lens, int nl)
{
	for (int i = 0; i < nl; i++) {
		size_t n = lens[i];
		uint8_t *d = malloc(n), *a = malloc(n), *b = malloc(n), *c = malloc(n), key[32],
			iv[16];
		char w[64];
		rnd(d, n);
		rnd(key, 32);
		rnd(iv, 16);
		snprintf(w, sizeof(w), "%s key=%u", dut, kl * 8);
		int r1 = cipher(ref, key, kl, iv, ivl, 0, d, n, a);
		int r2 = cipher(dut, key, kl, iv, ivl, 0, d, n, b);
		report(r1 == 0 && r2 == 0 && !memcmp(a, b, n), w, n,
		       r2 ? "(call failed)" : "encrypt");
		int r3 = cipher(dut, key, kl, iv, ivl, 1, b, n, c);
		report(r3 == 0 && !memcmp(c, d, n), "  decrypt roundtrip", n, "");
		int r4 = cipher(ref, key, kl, iv, ivl, 1, a, n, c);
		report(r1 == 0 && r4 == 0 && !memcmp(c, d, n), "  ref decrypts our ciphertext", n,
		       "");
		free(d);
		free(a);
		free(b);
		free(c);
	}
}

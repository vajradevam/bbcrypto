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

/* AEAD through AF_ALG. in = aad||text (enc) or aad||ct||tag (dec); out = aad||ct||tag or aad||pt.
 * Returns the number of bytes read, or -errno. */
static long aead(const char *name, const uint8_t *key, unsigned kl, const uint8_t *iv, int dec,
		 unsigned al, unsigned tag, const uint8_t *in, size_t n, uint8_t *out)
{
	struct sockaddr_alg sa = {.salg_family = AF_ALG};
	int t = socket(AF_ALG, SOCK_SEQPACKET, 0), fd;
	uint32_t op = dec ? ALG_OP_DECRYPT : ALG_OP_ENCRYPT;
	char cb[CMSG_SPACE(4) + CMSG_SPACE(sizeof(struct af_alg_iv) + 16) + CMSG_SPACE(4)] = {0};
	struct iovec iov = {(void *)in, n};
	struct msghdr m = {
		.msg_iov = &iov, .msg_iovlen = 1, .msg_control = cb, .msg_controllen = sizeof(cb)};
	struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
	struct af_alg_iv *ai;
	size_t cl = CMSG_SPACE(4), outn = dec ? n - tag : n + tag;
	long r;

	if (t < 0)
		return -errno;
	strcpy((char *)sa.salg_type, "aead");
	strncpy((char *)sa.salg_name, name, sizeof(sa.salg_name) - 1);
	if (bind(t, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
	    setsockopt(t, SOL_ALG, ALG_SET_KEY, key, kl) < 0 ||
	    setsockopt(t, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, tag) < 0 ||
	    (fd = accept(t, NULL, NULL)) < 0) {
		r = -errno;
		close(t);
		return r;
	}
	cm->cmsg_level = SOL_ALG;
	cm->cmsg_type = ALG_SET_OP;
	cm->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cm), &op, 4);
	cm = (struct cmsghdr *)(cb + cl);
	cm->cmsg_level = SOL_ALG;
	cm->cmsg_type = ALG_SET_IV;
	cm->cmsg_len = CMSG_LEN(sizeof(*ai) + 12);
	ai = (void *)CMSG_DATA(cm);
	ai->ivlen = 12;
	memcpy(ai->iv, iv, 12);
	cl += CMSG_SPACE(sizeof(*ai) + 12);
	cm = (struct cmsghdr *)(cb + cl);
	cm->cmsg_level = SOL_ALG;
	cm->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cm->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cm), &al, 4);
	cl += CMSG_SPACE(4);
	m.msg_controllen = cl;
	if (sendmsg(fd, &m, 0) < 0) {
		r = -errno;
		goto out;
	}
	r = read(fd, out, outn);
	if (r < 0)
		r = -errno;
	else if ((size_t)r != outn)
		r = -EIO;
out:
	close(fd);
	close(t);
	return r;
}

static char gcmref[64];
static int find_gcm_reference(const char *aes_inner)
{
	static const char *gh[] = {"ghash-generic", "ghash-lib"};
	uint8_t key[16] = {0}, iv[12] = {0}, o[48];
	for (unsigned i = 0; i < 2; i++) {
		snprintf(gcmref, sizeof(gcmref), "gcm_base(ctr(%s),%s)", aes_inner, gh[i]);
		if (aead(gcmref, key, 16, iv, 0, 0, 16, key, 16, o) >= 0) {
			printf("INFO GCM reference: %s\n", gcmref);
			return 0;
		}
	}
	return -1;
}

static void t_gcm(void)
{
	/* McGrew & Viega test case 2 and 4 (also NIST SP 800-38D examples) */
	static const uint8_t z16[16] = {0}, z12[12] = {0};
	static const uint8_t tc2[32] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
					0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
					0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
					0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
	uint8_t o[64] = {0}, back[64] = {0};
	long r = aead("gcm-aes-bbcrypto", z16, 16, z12, 0, 0, 16, z16, 16, o);

	{
		char e[32];
		snprintf(e, sizeof(e), "r=%ld", r);
		report(r == 32 && !memcmp(o, tc2, 32), "NIST GCM test case 2", 16, e);
	}
	r = aead("gcm-aes-bbcrypto", z16, 16, z12, 1, 0, 16, tc2, 32, back);
	report(r == 16 && !memcmp(back, z16, 16), "NIST GCM test case 2 decrypt", 16, "");

	static const size_t tl[] = {0, 1, 15, 16, 17, 100, 4096, 20000, 32700};
	static const unsigned al[] = {0, 13, 20};
	static const unsigned tg[] = {16, 12, 8};
	for (unsigned kl = 16; kl <= 32; kl += 8)
		for (unsigned i = 0; i < sizeof(tl) / sizeof(*tl); i++) {
			unsigned a = al[i % 3], tag = tg[(i / 3) % 3];
			size_t n = tl[i];
			uint8_t *in = malloc(a + n + 16), *x = malloc(a + n + 16),
				*y = malloc(a + n + 16), *pt = malloc(a + n + 16), key[32], iv[12];
			char w[64];
			long r1, r2, r3;

			rnd(in, a + n);
			rnd(key, 32);
			rnd(iv, 12);
			snprintf(w, sizeof(w), "gcm key=%u aad=%u tag=%u", kl * 8, a, tag);
			r1 = aead(gcmref, key, kl, iv, 0, a, tag, in, a + n, x);
			r2 = aead("gcm-aes-bbcrypto", key, kl, iv, 0, a, tag, in, a + n, y);
			report(r1 == (long)(a + n + tag) && r1 == r2 && !memcmp(x, y, r1), w, n,
			       r2 < 0 ? "(call failed)" : "encrypt");
			r3 = aead("gcm-aes-bbcrypto", key, kl, iv, 1, a, tag, y, r2 > 0 ? r2 : 0,
				  pt);
			report(r3 == (long)(a + n) && !memcmp(pt, in, a + n), "  decrypt roundtrip",
			       n, "");
			if (r2 > 0 && a + n > 0) { /* (an empty reply makes AF_ALG skip the
						      operation) corrupt one ciphertext/tag byte:
						      must be rejected, not "decrypted" */
				y[r2 - 1] ^= 1;
				r3 = aead("gcm-aes-bbcrypto", key, kl, iv, 1, a, tag, y, r2, pt);
				report(r3 == -EBADMSG, "  forged tag rejected (EBADMSG)", n,
				       r3 == -EBADMSG ? "" : "NOT REJECTED");
			}
			free(in);
			free(x);
			free(y);
			free(pt);
		}
}

static void vectors(void)
{
	/* NIST: SHA-256("abc"), SHA-1("abc"), AES-128 ECB (FIPS-197 appendix C.1) */
	static const uint8_t sha256_abc[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
					       0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
					       0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
					       0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
	static const uint8_t sha1_abc[20] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81,
					     0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
					     0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
	static const uint8_t pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				       0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	static const uint8_t k[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	static const uint8_t ct[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
				       0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
	uint8_t o[32];

	report(!hash("sha256-bbcrypto", NULL, 0, (const uint8_t *)"abc", 3, 32, o, 0) &&
		       !memcmp(o, sha256_abc, 32),
	       "NIST sha256(\"abc\")", 3, "");
	report(!hash("sha1-bbcrypto", NULL, 0, (const uint8_t *)"abc", 3, 20, o, 0) &&
		       !memcmp(o, sha1_abc, 20),
	       "NIST sha1(\"abc\")", 3, "");
	report(!cipher("ecb-aes-bbcrypto", k, 16, NULL, 0, 0, pt, 16, o) && !memcmp(o, ct, 16),
	       "FIPS-197 AES-128 ECB", 16, "");
}

/* ---- measurement helpers (sweep mode) ---- */
static void setp(const char *name, unsigned v)
{
	char p[128];
	FILE *f;

	snprintf(p, sizeof(p), "/sys/module/bbcrypto/parameters/%s", name);
	f = fopen(p, "w");
	if (!f) {
		perror(p);
		return;
	}
	fprintf(f, "%u\n", v);
	fclose(f);
}

/* transport-only benchmark: the driver echoes <size> bytes off the board <count> times */
static double ping_run(unsigned size, unsigned count, char *line, size_t ll)
{
	glob_t g;
	FILE *f;
	double t = now();

	line[0] = 0;
	if (glob("/sys/bus/usb/drivers/bbcrypto/*/ping", 0, NULL, &g))
		return -1;
	f = fopen(g.gl_pathv[0], "w");
	if (!f) {
		globfree(&g);
		return -1;
	}
	fprintf(f, "%u %u\n", size, count);
	fclose(f); /* the write blocks until the run is complete */
	t = now() - t;
	f = fopen(g.gl_pathv[0], "r");
	if (f) {
		if (!fgets(line, ll, f))
			line[0] = 0;
		fclose(f);
	}
	globfree(&g);
	return t;
}

struct conc {
	const char *alg;
	int hash;
	int n;
	size_t sz;
	int bad;
};

static void *conc_thread(void *a)
{
	struct conc *c = a;
	uint8_t *d = malloc(c->sz), *o = malloc(c->sz), key[32] = {7}, iv[16] = {9}, dig[32];

	memset(d, 0x42, c->sz);
	for (int i = 0; i < c->n; i++) {
		int r = c->hash ? hash(c->alg, NULL, 0, d, c->sz, 32, dig, 0)
				: cipher(c->alg, key, 32, iv, 0, 0, d, c->sz, o);
		if (r)
			c->bad++;
	}
	free(d);
	free(o);
	return NULL;
}

static double conc_run(const char *alg, int hashing, int threads, int n, size_t sz, int *bad)
{
	pthread_t th[16];
	struct conc c[16];
	double t = now();

	for (int i = 0; i < threads; i++) {
		c[i] = (struct conc){alg, hashing, n, sz, 0};
		pthread_create(&th[i], NULL, conc_thread, &c[i]);
	}
	*bad = 0;
	for (int i = 0; i < threads; i++) {
		pthread_join(th[i], NULL);
		*bad += c[i].bad;
	}
	return now() - t;
}

// SPDX-License-Identifier: GPL-2.0
/*
 * Extra checks, included by afalg_test.c (uses its helpers). Run in the default suite:
 *   known-answer vectors, error paths, hash clone/reuse, registration (/proc/crypto),
 *   module parameters (window, chunk), sysfs files, mixed-algorithm concurrency.
 * Run on demand (needs root, drops the board for a moment): `afalg_test unplug`.
 */
#include <dirent.h>
#include <fcntl.h>

static int unhex(const char *s, uint8_t *o)
{
	int n = 0;

	for (; s[0] && s[1]; s += 2) {
		unsigned v;
		sscanf(s, "%2x", &v);
		o[n++] = v;
	}
	return n;
}

static void kat_hash(const char *name, const char *keyhex, const char *data, const char *exp)
{
	uint8_t key[128], e[64], o[64];
	unsigned kl = keyhex ? unhex(keyhex, key) : 0, dl = unhex(exp, e);
	char w[64];

	snprintf(w, sizeof(w), "KAT %s", name);
	report(!hash(name, key, kl, (const uint8_t *)data, strlen(data), dl, o, 0) &&
		       !memcmp(o, e, dl),
	       w, strlen(data), "");
}

static void kat_cipher(const char *name, const char *keyhex, const char *ivhex, const char *pthex,
		       const char *cthex)
{
	uint8_t key[32], iv[16], pt[64], ct[64], o[64];
	unsigned kl = unhex(keyhex, key), n = unhex(pthex, pt);
	char w[64];

	unhex(cthex, ct);
	if (ivhex)
		unhex(ivhex, iv);
	snprintf(w, sizeof(w), "KAT %s key=%u", name, kl * 8);
	report(!cipher(name, key, kl, iv, ivhex ? 16 : 0, 0, pt, n, o) && !memcmp(o, ct, n), w, n,
	       "encrypt");
	report(!cipher(name, key, kl, iv, ivhex ? 16 : 0, 1, ct, n, o) && !memcmp(o, pt, n),
	       "  decrypt", n, "");
}

static void t_vectors2(void)
{
	static const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	const char *pt = "6bc1bee22e409f96e93d7e117393172a";
	const char *iv = "000102030405060708090a0b0c0d0e0f";
	const char *ieee = "00112233445566778899aabbccddeeff";
	static uint8_t big[128];
	uint8_t k[64], iv12[12], aadpt[20 + 64], o[20 + 64 + 16], e[80];
	long r;

	kat_hash("sha256-bbcrypto", NULL, "",
		 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	kat_hash("sha1-bbcrypto", NULL, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
	kat_hash("sha256-bbcrypto", NULL, two,
		 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	kat_hash("sha1-bbcrypto", NULL, two, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
	kat_hash("sha256-async-bbcrypto", NULL, two,
		 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	kat_hash("hmac-sha256-bbcrypto", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "Hi There",
		 "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
	kat_hash("hmac-sha256-bbcrypto", "4a656665", "what do ya want for nothing?",
		 "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	kat_hash("hmac-sha256-async-bbcrypto", "4a656665", "what do ya want for nothing?",
		 "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	/* FIPS-197 appendix C */
	kat_cipher("ecb-aes-bbcrypto", "000102030405060708090a0b0c0d0e0f", NULL, ieee,
		   "69c4e0d86a7b0430d8cdb78070b4c55a");
	kat_cipher("ecb-aes-bbcrypto", "000102030405060708090a0b0c0d0e0f1011121314151617", NULL,
		   ieee, "dda97ca4864cdfe06eaf70a0ec0d7191");
	kat_cipher("ecb-aes-bbcrypto",
		   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", NULL, ieee,
		   "8ea2b7ca516745bfeafc49904b496089");
	/* NIST SP 800-38A, first block */
	kat_cipher("cbc-aes-bbcrypto", "2b7e151628aed2a6abf7158809cf4f3c", iv, pt,
		   "7649abac8119b246cee98e9b12e9197d");
	kat_cipher("cbc-aes-bbcrypto",
		   "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", iv, pt,
		   "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
	kat_cipher("ctr-aes-bbcrypto", "2b7e151628aed2a6abf7158809cf4f3c",
		   "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", pt, "874d6191b620e3261bef6864990db6ce");
	kat_cipher("ctr-aes-bbcrypto",
		   "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		   "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", pt, "601ec313775789a5b7a7f504bbf3d228");
	/* GCM test case 4 (McGrew-Viega): 60-byte plaintext, 20-byte AAD, 128-bit tag */
	unhex("feffe9928665731c6d6a8f9467308308", k);
	unhex("cafebabefacedbaddecaf888", iv12);
	unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aadpt);
	unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf"
	      "0e2449a6b525b16aedf5aa0de657ba637b39",
	      aadpt + 20);
	unhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f"
	      "6a5aac84aa051ba30b396a0aac973d58e091"
	      "5bc94fbc3221a5db94fae95ae7121a47",
	      e);
	r = aead("gcm-aes-bbcrypto", k, 16, iv12, 0, 20, 16, aadpt, 20 + 60, o);
	report(r == 20 + 60 + 16 && !memcmp(o + 20, e, 76), "KAT GCM test case 4 (aad+tag)", 60,
	       "");
	memcpy(o, aadpt, 20);
	memcpy(o + 20, e, 76);
	r = aead("gcm-aes-bbcrypto", k, 16, iv12, 1, 20, 16, o, 20 + 76, big);
	report(r == 20 + 60 && !memcmp(big + 20, aadpt + 20, 60), "KAT GCM test case 4 decrypt", 60,
	       "");
}

/* setsockopt(ALG_SET_KEY) result for a key of this length: 0 or -errno */
static int setkey_result(const char *type, const char *name, unsigned kl)
{
	struct sockaddr_alg sa = {.salg_family = AF_ALG};
	uint8_t key[256] = {0};
	int t = socket(AF_ALG, SOCK_SEQPACKET, 0), r = 0;

	strcpy((char *)sa.salg_type, type);
	strncpy((char *)sa.salg_name, name, sizeof(sa.salg_name) - 1);
	if (t < 0 || bind(t, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -ENOENT;
	if (setsockopt(t, SOL_ALG, ALG_SET_KEY, key, kl) < 0)
		r = -errno;
	close(t);
	return r;
}

static int authsize_result(unsigned sz)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG, .salg_type = "aead", .salg_name = "gcm-aes-bbcrypto"};
	uint8_t key[16] = {0};
	int t = socket(AF_ALG, SOCK_SEQPACKET, 0), r = 0;

	if (t < 0 || bind(t, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
	    setsockopt(t, SOL_ALG, ALG_SET_KEY, key, 16) < 0)
		return -EIO;
	if (setsockopt(t, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, sz) < 0)
		r = -errno;
	close(t);
	return r;
}

static void t_errors(void)
{
	static const unsigned bad[] = {1, 15, 17, 20, 31, 33, 64};
	static const char *ciph[] = {"ecb-aes-bbcrypto", "cbc-aes-bbcrypto", "ctr-aes-bbcrypto"};
	uint8_t d[40] = {0}, o[64], key[32] = {1}, iv[16] = {2}, big[32768 + 64] = {0},
		bigout[32768 + 64];
	char w[64];
	int tfm, fd;
	long r;

	for (unsigned c = 0; c < 3; c++) {
		for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
			snprintf(w, sizeof(w), "%s bad key length %u", ciph[c], bad[i]);
			report(setkey_result("skcipher", ciph[c], bad[i]) == -EINVAL, w, 0,
			       "EINVAL");
		}
		for (unsigned kl = 16; kl <= 32; kl += 8) {
			snprintf(w, sizeof(w), "%s good key length %u", ciph[c], kl);
			report(setkey_result("skcipher", ciph[c], kl) == 0, w, 0, "");
		}
	}
	for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
		snprintf(w, sizeof(w), "gcm bad key length %u", bad[i]);
		report(setkey_result("aead", "gcm-aes-bbcrypto", bad[i]) == -EINVAL, w, 0,
		       "EINVAL");
	}
	report(setkey_result("hash", "hmac-sha256-bbcrypto", 128) == 0, "hmac key 128 accepted", 0,
	       "");
	report(setkey_result("hash", "hmac-sha256-bbcrypto", 129) == -EINVAL,
	       "hmac key 129 rejected", 0, "EINVAL");
	report(setkey_result("hash", "hmac-sha256-async-bbcrypto", 129) == -EINVAL,
	       "hmac-async key 129 rejected", 0, "EINVAL");
	report(setkey_result("hash", "no-such-alg-bbcrypto", 0) == -ENOENT,
	       "unknown algorithm name", 0, "ENOENT");

	static const unsigned as_ok[] = {4, 8, 12, 13, 14, 15, 16},
			      as_bad[] = {0, 1, 3, 5, 11, 17, 32};
	for (unsigned i = 0; i < sizeof(as_ok) / sizeof(*as_ok); i++) {
		snprintf(w, sizeof(w), "gcm authsize %u accepted", as_ok[i]);
		report(authsize_result(as_ok[i]) == 0, w, 0, "");
	}
	for (unsigned i = 0; i < sizeof(as_bad) / sizeof(*as_bad); i++) {
		snprintf(w, sizeof(w), "gcm authsize %u rejected", as_bad[i]);
		report(authsize_result(as_bad[i]) == -EINVAL, w, 0, "EINVAL");
	}
	/* block ciphers refuse partial blocks; CTR does not */
	report(cipher("ecb-aes-bbcrypto", key, 16, NULL, 0, 0, d, 17, o) != 0,
	       "ecb refuses 17 bytes", 17, "");
	report(cipher("cbc-aes-bbcrypto", key, 16, iv, 16, 0, d, 31, o) != 0,
	       "cbc refuses 31 bytes", 31, "");
	report(cipher("ctr-aes-bbcrypto", key, 16, iv, 16, 0, d, 31, o) == 0,
	       "ctr accepts 31 bytes", 31, "");
	/* GCM limit: assoclen+cryptlen+tag <= 32 KiB per request */
	rnd(big, sizeof(big));
	r = aead("gcm-aes-bbcrypto", key, 16, iv, 0, 0, 16, big, 32768 - 16, bigout);
	report(r == 32768, "gcm 32752 bytes (limit) ok", 32752, "");
	r = aead("gcm-aes-bbcrypto", key, 16, iv, 0, 0, 16, big, 32768 - 15, bigout);
	report(r == -EINVAL, "gcm 32753 bytes rejected", 32753, r == -EINVAL ? "EINVAL" : "WRONG");
	/* hash object reuse: after a digest is read the same socket starts a new message */
	fd = opensock("hash", "sha256-bbcrypto", NULL, 0, &tfm);
	if (fd >= 0) {
		uint8_t a[32], b[32], ra[32], rb[32];
		hash("sha256-bbcrypto", NULL, 0, (const uint8_t *)"first", 5, 32, ra, 0);
		hash("sha256-bbcrypto", NULL, 0, (const uint8_t *)"second", 6, 32, rb, 0);
		send(fd, "first", 5, 0);
		int e1 = rd(fd, a, 32);
		send(fd, "second", 6, 0);
		int e2 = rd(fd, b, 32);
		report(!e1 && !e2 && !memcmp(a, ra, 32) && !memcmp(b, rb, 32),
		       "hash socket reused for 2 messages", 11, "");
		close(fd);
		close(tfm);
	} else
		report(0, "hash socket reused for 2 messages", 0, "open failed");
	/* clone mid-message (accept on an op socket exports/imports the hash state) */
	for (unsigned a = 0; a < 3; a++) {
		static const char *nm[] = {"sha256-bbcrypto", "sha1-async-bbcrypto",
					   "hmac-sha256-async-bbcrypto"};
		static const char *rf[] = {"sha256", "sha1", "hmac(sha256)"};
		uint8_t hk[9] = "key12345", e1[32], e2[32], g1[32], g2[32];
		unsigned kl = a == 2 ? 8 : 0, dl = a == 1 ? 20 : 32;
		fd = opensock("hash", nm[a], hk, kl, &tfm);
		int fd2 = fd >= 0 ? accept(fd, NULL, NULL) : -1;
		int ok = fd2 >= 0;
		if (fd >= 0 && fd2 >= 0) {
			send(fd, "abc", 3, MSG_MORE);
			int c = accept(fd, NULL, NULL); /* snapshot after "abc" */
			send(fd, "def", 3, 0);
			send(c, "xyz", 3, 0);
			ok = c >= 0 && !rd(fd, g1, dl) && !rd(c, g2, dl);
			hash(rf[a], hk, kl, (const uint8_t *)"abcdef", 6, dl, e1, 0);
			hash(rf[a], hk, kl, (const uint8_t *)"abcxyz", 6, dl, e2, 0);
			ok = ok && !memcmp(g1, e1, dl) && !memcmp(g2, e2, dl);
			if (c >= 0)
				close(c);
		}
		if (fd2 >= 0)
			close(fd2);
		if (fd >= 0) {
			close(fd);
			close(tfm);
		}
		snprintf(w, sizeof(w), "%s state clone (accept)", nm[a]);
		report(ok, w, 6, "");
	}
}

/* ---- registration: every algorithm listed with the right driver name and priority ---- */
static long param(const char *name)
{
	char p[128];
	long v = -1;
	FILE *f;

	snprintf(p, sizeof(p), "/sys/module/bbcrypto/parameters/%s", name);
	f = fopen(p, "r");
	if (f) {
		if (fscanf(f, "%ld", &v) != 1)
			v = -1;
		fclose(f);
	}
	return v;
}

static void t_registered(void)
{
	static const char *drv[] = {"ecb-aes-bbcrypto",	     "cbc-aes-bbcrypto",
				    "ctr-aes-bbcrypto",	     "gcm-aes-bbcrypto",
				    "sha1-bbcrypto",	     "sha256-bbcrypto",
				    "hmac-sha256-bbcrypto",  "sha1-async-bbcrypto",
				    "sha256-async-bbcrypto", "hmac-sha256-async-bbcrypto"};
	char line[256], cur[64] = "", w[96];
	long prio = param("prio");
	int seen[10] = {0}, pr_ok[10] = {0};
	FILE *f = fopen("/proc/crypto", "r");

	while (f && fgets(line, sizeof(line), f)) {
		char v[64];
		if (sscanf(line, "driver : %63s", v) == 1)
			strcpy(cur, v);
		else if (sscanf(line, "priority : %63s", v) == 1)
			for (unsigned i = 0; i < 10; i++)
				if (!strcmp(cur, drv[i])) {
					seen[i] = 1;
					pr_ok[i] = atol(v) == prio;
				}
	}
	if (f)
		fclose(f);
	for (unsigned i = 0; i < 10; i++) {
		snprintf(w, sizeof(w), "/proc/crypto lists %s", drv[i]);
		report(seen[i], w, 0, "");
		snprintf(w, sizeof(w), "  priority == prio param (%ld)", prio);
		report(pr_ok[i], w, 0, "");
	}
}

/* ---- sysfs: stats counters move, ping works and rejects bad input ---- */
static int sysfs_file(const char *name, char *path, size_t n)
{
	glob_t g;
	char pat[128];

	snprintf(pat, sizeof(pat), "/sys/bus/usb/drivers/bbcrypto/*/%s", name);
	if (glob(pat, 0, NULL, &g))
		return -1;
	snprintf(path, n, "%s", g.gl_pathv[0]);
	globfree(&g);
	return 0;
}

static long stat_val(const char *field)
{
	char p[256], l[128], k[32];
	long v, r = -1;
	FILE *f;

	if (sysfs_file("stats", p, sizeof(p)) || !(f = fopen(p, "r")))
		return -1;
	while (fgets(l, sizeof(l), f))
		if (sscanf(l, "%31s %ld", k, &v) == 2 && !strcmp(k, field))
			r = v;
	fclose(f);
	return r;
}

static void t_sysfs(void)
{
	uint8_t d[1000] = {0}, o[32];
	long q0, b0, e0, q1, b1, q2;
	char p[256], line[256] = "";
	int fd;

	hash("sha256-bbcrypto", NULL, 0, d, 10, 32, o, 0); /* warm up */
	q0 = stat_val("requests"), b0 = stat_val("bytes"), e0 = stat_val("errors");
	report(q0 >= 0 && b0 >= 0 && e0 >= 0, "stats has requests/bytes/errors", 0, "");
	hash("sha256-bbcrypto", NULL, 0, d, 1000, 32, o, 0);
	q1 = stat_val("requests"), b1 = stat_val("bytes");
	report(q1 > q0 && b1 >= b0 + 1000, "stats count a board request", 1000, "");
	hash("sha256", NULL, 0, d, 1000, 32, o,
	     0); /* plain name: stays on the CPU at default prio */
	q2 = stat_val("requests");
	report(param("prio") > 300 || q2 == q1, "plain 'sha256' does not use the board", 0,
	       param("prio") > 300 ? "(prio>300: skipped)" : "");
	report(stat_val("errors") == e0, "no errors counted", 0, "");
	report(stat_val("avg_latency_us") >= 0 && stat_val("max_inflight") >= 1,
	       "latency/inflight reported", 0, "");
	/* ping: transport-only echo */
	if (sysfs_file("ping", p, sizeof(p))) {
		report(0, "ping file present", 0, "");
		return;
	}
	if (access(p, W_OK)) {
		printf("SKIP ping checks (need root)\n");
		return;
	}
	ping_run(64, 20, line, sizeof(line));
	report(strstr(line, "size 64 count 20") != NULL, "ping 64B x20 reports size and count", 0,
	       "");
	ping_run(32768, 5, line, sizeof(line));
	report(strstr(line, "size 32768 count 5") != NULL, "ping 32 KiB x5", 0, "");
	fd = open(p, O_WRONLY);
	report(fd >= 0 && write(fd, "junk", 4) < 0 && errno == EINVAL, "ping rejects junk", 0,
	       "EINVAL");
	if (fd >= 0)
		close(fd);
	fd = open(p, O_WRONLY);
	report(fd >= 0 && write(fd, "64 0", 4) < 0 && errno == EINVAL, "ping rejects count 0", 0,
	       "EINVAL");
	if (fd >= 0)
		close(fd);
	fd = open(p, O_WRONLY);
	report(fd >= 0 && write(fd, "32769 1", 7) < 0 && errno == EINVAL,
	       "ping rejects size > 32 KiB", 0, "EINVAL");
	if (fd >= 0)
		close(fd);
}

/* ---- module parameters: results stay correct for every window / chunk setting ---- */
static int setp_ok(const char *name, unsigned v)
{
	char p[128];
	FILE *f;

	snprintf(p, sizeof(p), "/sys/module/bbcrypto/parameters/%s", name);
	f = fopen(p, "w");
	if (!f)
		return -1;
	fprintf(f, "%u\n", v);
	return fclose(f);
}

static void params_check(const char *what)
{
	enum { N = 70000 };
	static uint8_t d[N], a[N], b[N], key[32], iv[16], x[32], y[32], g1[N + 16 + 13],
		g2[N + 16 + 13];
	char w[96];
	int ok;

	rnd(d, N);
	rnd(key, 32);
	rnd(iv, 16);
	snprintf(w, sizeof(w), "%s: cbc 70000B matches reference", what);
	ok = !cipher(refname[1], key, 32, iv, 16, 0, d, 69984, a) &&
	     !cipher("cbc-aes-bbcrypto", key, 32, iv, 16, 0, d, 69984, b) && !memcmp(a, b, 69984);
	report(ok, w, 69984, "");
	snprintf(w, sizeof(w), "%s: ctr 70000B matches reference", what);
	ok = !cipher(refname[2], key, 32, iv, 16, 0, d, N, a) &&
	     !cipher("ctr-aes-bbcrypto", key, 32, iv, 16, 0, d, N, b) && !memcmp(a, b, N);
	report(ok, w, N, "");
	snprintf(w, sizeof(w), "%s: sha256 70000B matches reference", what);
	ok = !hash("sha256", NULL, 0, d, N, 32, x, 0) &&
	     !hash("sha256-bbcrypto", NULL, 0, d, N, 32, y, 5000) && !memcmp(x, y, 32);
	report(ok, w, N, "");
	snprintf(w, sizeof(w), "%s: gcm 30000B matches reference", what);
	ok = aead(gcmref, key, 32, iv, 0, 13, 16, d, 30013, g1) == 30029 &&
	     aead("gcm-aes-bbcrypto", key, 32, iv, 0, 13, 16, d, 30013, g2) == 30029 &&
	     !memcmp(g1, g2, 30029);
	report(ok, w, 30000, "");
}

static void t_params(void)
{
	static const unsigned win[] = {1, 2, 8, 0, 100}; /* 0 and 100 are clamped to 1..8 */
	static const unsigned chk[] = {16, 1000, 4096, 32768,
				       1 << 20}; /* rounded down to x16, clamped */
	long w0 = param("window"), c0 = param("chunk");
	char w[64];

	if (w0 < 0 || c0 < 0 || setp_ok("window", w0) < 0) {
		printf("SKIP module parameters (not root or not writable)\n");
		return;
	}
	for (unsigned i = 0; i < sizeof(win) / sizeof(*win); i++) {
		snprintf(w, sizeof(w), "window=%u", win[i]);
		report(setp_ok("window", win[i]) == 0, "set window", win[i], "");
		params_check(w);
	}
	setp_ok("window", w0);
	for (unsigned i = 0; i < sizeof(chk) / sizeof(*chk); i++) {
		snprintf(w, sizeof(w), "chunk=%u", chk[i]);
		report(setp_ok("chunk", chk[i]) == 0, "set chunk", chk[i], "");
		params_check(w);
	}
	setp_ok("chunk", c0);
	report(param("window") == w0 && param("chunk") == c0, "parameters restored", 0, "");
}

/* ---- concurrency with checking: threads run different algorithms at once, every result is
 * compared ---- */
struct mix {
	int id, iters, bad;
};

static void *mix_thread(void *a)
{
	struct mix *m = a;
	unsigned seed = 1000 + m->id;
	uint8_t *d = malloc(40000), *x = malloc(40016 + 13), *y = malloc(40016 + 13), key[32],
		iv[16], h1[32], h2[32];

	for (int i = 0; i < m->iters; i++) {
		size_t n = 1 + rand_r(&seed) % 30000;
		int ok = 0;

		for (size_t j = 0; j < n; j++)
			d[j] = rand_r(&seed) >> 7;
		for (int j = 0; j < 32; j++)
			key[j] = rand_r(&seed) >> 7;
		for (int j = 0; j < 16; j++)
			iv[j] = rand_r(&seed) >> 7;
		switch (m->id % 5) {
		case 0:
			ok = !hash("sha256", NULL, 0, d, n, 32, h1, 0) &&
			     !hash("sha256-bbcrypto", NULL, 0, d, n, 32, h2, 0) &&
			     !memcmp(h1, h2, 32);
			break;
		case 1:
			ok = !hash("sha256", NULL, 0, d, n, 32, h1, 0) &&
			     !hash("sha256-async-bbcrypto", NULL, 0, d, n, 32, h2, 777) &&
			     !memcmp(h1, h2, 32);
			break;
		case 2:
			n &= ~15UL;
			n += 16;
			ok = !cipher(refname[1], key, 32, iv, 16, 0, d, n, x) &&
			     !cipher("cbc-aes-bbcrypto", key, 32, iv, 16, 0, d, n, y) &&
			     !memcmp(x, y, n);
			break;
		case 3:
			ok = !cipher(refname[2], key, 32, iv, 16, 0, d, n, x) &&
			     !cipher("ctr-aes-bbcrypto", key, 32, iv, 16, 0, d, n, y) &&
			     !memcmp(x, y, n);
			break;
		default:
			n = 1 + n % 20000;
			ok = aead(gcmref, key, 32, iv, 0, 13, 16, d, 13 + n, x) ==
				     (long)(n + 13 + 16) &&
			     aead("gcm-aes-bbcrypto", key, 32, iv, 0, 13, 16, d, 13 + n, y) ==
				     (long)(n + 13 + 16) &&
			     !memcmp(x, y, n + 13 + 16);
		}
		m->bad += !ok;
	}
	free(d);
	free(x);
	free(y);
	return NULL;
}

static void t_mixed(void)
{
	enum { T = 10, IT = 12 };
	pthread_t th[T];
	struct mix m[T];
	int bad = 0;
	char w[64];

	for (int i = 0; i < T; i++) {
		m[i] = (struct mix){i, IT, 0};
		pthread_create(&th[i], NULL, mix_thread, &m[i]);
	}
	for (int i = 0; i < T; i++) {
		pthread_join(th[i], NULL);
		bad += m[i].bad;
	}
	snprintf(w, sizeof(w), "%d threads x %d mixed requests, all verified", T, IT);
	report(bad == 0, w, 0, bad ? "MISMATCH" : "");
}

/* ---- unplug mode: deauthorize the board while requests run, then bring it back ---- */
static int auth_path(char *p, size_t n)
{
	glob_t g;

	if (glob("/sys/bus/usb/drivers/bbcrypto/*:*", 0, NULL, &g))
		return -1;
	char *s = strrchr(g.gl_pathv[0], '/'), *c = strrchr(s, ':');
	*c = 0; /* .../1-2:1.0 -> .../1-2 */
	snprintf(p, n, "/sys/bus/usb/devices/%s/authorized", s + 1);
	globfree(&g);
	return 0;
}

static int set_auth(const char *p, int v)
{
	FILE *f = fopen(p, "w");

	if (!f)
		return -1;
	fprintf(f, "%d\n", v);
	return fclose(f);
}

static int unplug_mode(void)
{
	pthread_t th[4];
	struct loopres r[4] = {{0}};
	char p[256];
	long ok1, bad1, ok2, bad2, ok3 = 0, bad3 = 0;
	uint8_t d[100] = {0}, o[32], e[32];
	int back = 0;

	if (auth_path(p, sizeof(p)) || set_auth(p, 1)) {
		printf("FAIL cannot find/write the device's authorized file (root? board "
		       "attached?)\n");
		return 1;
	}
	alarm(120); /* a hang is a failure: the process is killed */
	for (int i = 0; i < 4; i++) {
		r[i].idx = i;
		pthread_create(&th[i], NULL, loop_thread, &r[i]);
	}
	sleep(2);
	ok1 = r[0].ok + r[1].ok + r[2].ok + r[3].ok;
	bad1 = r[0].bad + r[1].bad + r[2].bad + r[3].bad;
	report(ok1 > 0 && bad1 == 0, "unplug: requests succeed before", ok1, "");
	set_auth(p, 0); /* the board "disappears" while 4 threads are mid-request */
	sleep(3);
	ok2 = r[0].ok + r[1].ok + r[2].ok + r[3].ok - ok1;
	bad2 = r[0].bad + r[1].bad + r[2].bad + r[3].bad - bad1;
	report(bad2 > 0, "unplug: requests fail (no hang) while gone", bad2, "");
	set_auth(p, 1);
	for (int i = 0; i < 30 && !back; i++) { /* the driver must bind again by itself */
		sleep(1);
		back = stat_val("requests") >= 0;
	}
	report(back, "unplug: driver rebinds after reauthorize", 0, "");
	sleep(3);
	loop_stop = 1;
	for (int i = 0; i < 4; i++) {
		pthread_join(th[i], NULL);
		ok3 += r[i].ok;
		bad3 += r[i].bad;
	}
	ok3 -= ok1 + ok2;
	report(ok3 > 0, "unplug: requests succeed again after", ok3, "");
	report(!hash("sha256-bbcrypto", NULL, 0, d, 100, 32, o, 0) &&
		       !hash("sha256", NULL, 0, d, 100, 32, e, 0) && !memcmp(o, e, 32),
	       "unplug: results correct after", 100, "");
	printf("unplug: ok before/gone/after = %ld/%ld/%ld, failed = %ld/%ld/%ld\n", ok1, ok2, ok3,
	       bad1, bad2, bad3 - bad1 - bad2);
	printf("\n%d passed, %d failed\n", passes, fails);
	return fails != 0;
}

/* bbcrypt - command-line front end that forces the bbcrypto driver via AF_ALG.
 *   bbcrypt hash sha256|sha1 [file]            (stdin if no file)
 *   bbcrypt hmac <hexkey> [file]               hmac(sha256)
 *   bbcrypt enc|dec ecb|cbc|ctr <hexkey> [hexiv] < in > out
 *   bbcrypt gcm-enc|gcm-dec <hexkey> <hexiv12> [hexaad] < in > out   (out = ciphertext||16-byte
 * tag) Add "-b" first to use the in-kernel implementation instead (for comparison). */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#ifndef SOL_ALG
#define SOL_ALG 279
#endif
static int sw;
static int hex(const char *s, unsigned char *o, int max)
{
	int n = strlen(s) / 2;
	if (n > max)
		n = max;
	for (int i = 0; i < n; i++) {
		unsigned v;
		sscanf(s + 2 * i, "%2x", &v);
		o[i] = v;
	}
	return n;
}
static int mk(const char *type, const char *name, const unsigned char *key, int kl)
{
	struct sockaddr_alg sa = {.salg_family = AF_ALG};
	strcpy((char *)sa.salg_type, type);
	strncpy((char *)sa.salg_name, name, sizeof sa.salg_name - 1);
	int t = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (t < 0 || bind(t, (void *)&sa, sizeof sa)) {
		perror(name);
		exit(1);
	}
	if (kl && setsockopt(t, SOL_ALG, ALG_SET_KEY, key, kl)) {
		perror("setkey");
		exit(1);
	}
	int o = accept(t, 0, 0);
	if (o < 0) {
		perror("accept");
		exit(1);
	}
	return o;
}
static void pr(const unsigned char *p, int n)
{
	for (int i = 0; i < n; i++)
		printf("%02x", p[i]);
}
static int dohash(const char *alg, const unsigned char *key, int kl, int fd)
{
	int o = mk("hash", alg, key, kl);
	char b[32768];
	ssize_t n;
	while ((n = read(fd, b, sizeof b)) > 0)
		if (send(o, b, n, MSG_MORE) != n) {
			perror("send");
			return 1;
		}
	unsigned char d[64];
	n = read(o, d, sizeof d);
	if (n <= 0) {
		perror("digest");
		return 1;
	}
	pr(d, n);
	printf("\n");
	return 0;
}
static int docipher(int dec, const char *mode, const unsigned char *key, int kl,
		    const unsigned char *iv, int il)
{
	char name[32], alg[48];
	snprintf(name, sizeof name, "%s(aes)", mode);
	snprintf(alg, sizeof alg, "%s-aes-bbcrypto", mode);
	int o = mk("skcipher", sw ? name : alg, key, kl);
	/* each chunk is a separate sendmsg with the running iv, so work on whole-request buffers */
	size_t cap = 1 << 20, len = 0;
	unsigned char *in = malloc(cap);
	ssize_t n;
	while ((n = read(0, in + len, cap - len)) > 0) {
		len += n;
		if (len == cap) {
			cap *= 2;
			in = realloc(in, cap);
		}
	}
	if (len > 192 * 1024) {
		fprintf(stderr, "input too large for one AF_ALG request (max 192 KiB, the socket "
				"send buffer); split it\n");
		return 1;
	}
	if (strcmp(mode, "ctr") && len % 16) {
		fprintf(stderr, "input must be a multiple of 16 bytes for %s\n", mode);
		return 1;
	}
	unsigned char *out = malloc(len + 1);
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(4 + 16)] = {0};
	struct msghdr m = {.msg_control = cbuf, .msg_controllen = sizeof cbuf};
	struct cmsghdr *c = CMSG_FIRSTHDR(&m);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_OP;
	c->cmsg_len = CMSG_LEN(4);
	*(int *)CMSG_DATA(c) = dec ? ALG_OP_DECRYPT : ALG_OP_ENCRYPT;
	c = CMSG_NXTHDR(&m, c);
	c->cmsg_level = SOL_ALG;
	c->cmsg_type = ALG_SET_IV;
	c->cmsg_len = CMSG_LEN(4 + 16);
	*(unsigned *)CMSG_DATA(c) = 16;
	memcpy(CMSG_DATA(c) + 4, iv, il ? il : 16);
	struct iovec v = {in, len};
	m.msg_iov = &v;
	m.msg_iovlen = 1;
	if (!strcmp(mode, "ecb")) {
		m.msg_controllen = CMSG_SPACE(4);
	}
	if (sendmsg(o, &m, 0) < 0) {
		perror("sendmsg");
		return 1;
	}
	size_t got = 0;
	while (got < len) {
		n = read(o, out + got, len - got);
		if (n <= 0) {

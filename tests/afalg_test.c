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

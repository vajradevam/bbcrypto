/* Runs ON THE BOARD: N back-to-back 32 KiB AF_ALG cipher requests, the way bbcryptod issues them.
 */
#include <linux/if_alg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static long ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
int main(int argc, char **argv)
{
	const char *name = argc > 1 ? argv[1] : "cbc(aes)";
	int n = argc > 2 ? atoi(argv[2]) : 32, i;
	static uint8_t d[32768], o[32768], key[32] = {1};
	for (i = 0; i < n; i++) {
		struct sockaddr_alg sa = {.salg_family = AF_ALG};
		uint32_t op = ALG_OP_ENCRYPT;
		char cb[CMSG_SPACE(4) + CMSG_SPACE(sizeof(struct af_alg_iv) + 16)] = {0};
		struct iovec iov = {d, sizeof(d)};
		struct msghdr m = {.msg_iov = &iov,
				   .msg_iovlen = 1,
				   .msg_control = cb,
				   .msg_controllen = sizeof(cb)};
		struct cmsghdr *c = CMSG_FIRSTHDR(&m);
		struct af_alg_iv *ai;
		long t = ms();
		size_t got = 0;
		int t_fd = socket(AF_ALG, SOCK_SEQPACKET, 0), fd;
		strcpy((char *)sa.salg_type, "skcipher");
		strcpy((char *)sa.salg_name, name);
		if (bind(t_fd, (void *)&sa, sizeof(sa)) ||
		    setsockopt(t_fd, 279, ALG_SET_KEY, key, 32)) {
			perror("bind/key");
			return 1;
		}
		fd = accept(t_fd, NULL, NULL);
		c->cmsg_level = 279;
		c->cmsg_type = ALG_SET_OP;
		c->cmsg_len = CMSG_LEN(4);
		memcpy(CMSG_DATA(c), &op, 4);
		c = CMSG_NXTHDR(&m, c);
		c->cmsg_level = 279;
		c->cmsg_type = ALG_SET_IV;
		c->cmsg_len = CMSG_LEN(sizeof(*ai) + 16);
		ai = (void *)CMSG_DATA(c);
		ai->ivlen = 16;
		if (sendmsg(fd, &m, 0) < 0) {
			perror("sendmsg");
			return 1;
		}
		while (got < sizeof(o)) {
			ssize_t r = read(fd, o + got, sizeof(o) - got);
			if (r <= 0) {
				perror("read");
				return 1;
			}
			got += r;
		}
		close(fd);
		close(t_fd);
		t = ms() - t;
		if (t > 200 || i % 8 == 0)
			printf("chunk %d: %ld ms\n", i, t);
		fflush(stdout);
	}
	printf("done %d chunks\n", n);
	return 0;
}

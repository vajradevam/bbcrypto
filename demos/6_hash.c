/* Demo 6 (C): hash a file on the board through AF_ALG, like `sha256sum` but executed by the
 * BeagleBone. cc -O2 -o 6_hash 6_hash.c && ./6_hash FILE [driver]      default driver:
 * sha256-bbcrypto */
#include <linux/if_alg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s FILE [driver]\n", argv[0]);
		return 1;
	}
	struct sockaddr_alg sa = {.salg_family = AF_ALG};
	strcpy((char *)sa.salg_type, "hash");
	strncpy((char *)sa.salg_name, argc > 2 ? argv[2] : "sha256-bbcrypto",
		sizeof(sa.salg_name) - 1);

	int s = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (s < 0 || bind(s, (void *)&sa, sizeof sa)) {
		perror("alg (is bbcrypto loaded?)");
		return 1;
	}
	int op = accept(s, NULL, NULL);
	FILE *f = fopen(argv[1], "rb");
	if (!f) {
		perror(argv[1]);
		return 1;
	}

	char buf[16384];
	size_t n;
	while ((n = fread(buf, 1, sizeof buf, f)) >
	       0) { /* stream the file; MSG_MORE = more data follows */
		if (send(op, buf, n, MSG_MORE) < 0) {
			perror("send");
			return 1;
		}
	}
	send(op, NULL, 0, 0); /* end of data -> digest */
	unsigned char d[64];
	int len = read(op, d, sizeof d);
	if (len <= 0) {
		perror("digest");
		return 1;
	}
	for (int i = 0; i < len; i++)
		printf("%02x", d[i]);
	printf("  %s\n", argv[1]);
	return 0;
}

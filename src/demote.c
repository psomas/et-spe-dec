#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <signal.h>

#define THPSZ	(1UL << 21)
#define	BUFLEN	(4UL << 30)

#define MADV_ELASTIC 25 
#define MADV_CAPAGING 26
#define MADV_DEMOTE	31

void handler(int signum) {};

int main(int argc, char *argv[]) {	
	unsigned long i;

	printf("enabling et\n");
	assert(!madvise(0, 4096, MADV_ELASTIC));
	assert(!madvise(0, 4096, MADV_CAPAGING));

	char *buf = mmap(BUFLEN, BUFLEN, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	assert(buf != MAP_FAILED);
	printf("mmap@0x%lx\n", buf);

	assert(!madvise(buf, THPSZ * 32, MADV_HUGEPAGE));
	printf("madvise thp\n");

	for (i = 0; i < BUFLEN; i += THPSZ) {
		buf[i] = i;
	}
	printf("alloc\n");

	signal(SIGUSR1, handler);
	
	printf("pausing...\n");
	pause();

	assert(!madvise(buf, THPSZ, MADV_DEMOTE));
	printf("demote\n");

	printf("pausing...\n");
	pause();

	return 0;
}

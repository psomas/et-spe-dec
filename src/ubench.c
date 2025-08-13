#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE	(4 * 1024)      // 4 KiB
#endif

#ifndef	THP_SIZE
#define THP_SIZE	(2UL << 20)      // 2 MiB
#endif

int main(int argc, char *argv[]) {
    int num_tlb_entries; // Number of TLB entries 
    long num_access_loops; // Number of times to cycle through all regions
    size_t buffer_size, sum = 0;
    void *buffer = NULL;
    int i;
    volatile uint8_t value; // Use volatile to prevent compiler optimizations

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <number_of_tlb_entries> <number_of_loops> \n", argv[0]);
        return EXIT_FAILURE;
    }

    num_tlb_entries = atoi(argv[1]);
    if (num_tlb_entries <= 0) {
        fprintf(stderr, "Error: Number of TLB entries must be a positive integer.\n");
        return EXIT_FAILURE;
    }

    num_access_loops = atol(argv[2]);
    if (num_access_loops <= 0) {
        fprintf(stderr, "Error: Number of access loops must be a positive integer.\n");
        return EXIT_FAILURE;
    }

    printf("TLB entries: %d...\n", num_tlb_entries);
    printf("Loops: %ld...\n", num_access_loops);

    buffer_size = (size_t)num_tlb_entries * THP_SIZE;

    // Allocate a buffer using mmap()
    buffer = mmap((void *)(4UL << 30), buffer_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (buffer == MAP_FAILED) {
        perror("mmap failed");
        return EXIT_FAILURE;
    }

    printf("Allocated buffer of size %zu bytes at address %p\n", buffer_size, buffer);

	memset(buffer, 0xfe, buffer_size);

    printf("Initialization complete.\n");

    // Repeatedly accesses one 4KiB page per 64KiB region
    // This loop repeatedly accesses the same set of pages initialized above.
    // If num_tlb_entries is greater than the actual number of TLB entries,
    // this pattern will likely cause TLB misses as the program cycles through
    // more distinct pages than the TLB can hold simultaneously.
    printf("Repeatedly accessing initialized pages, %ld loops...\n", num_access_loops);

    for (long loop = 0; loop < num_access_loops; ++loop) {
        for (i = 0; i < num_tlb_entries; ++i) {
            // Calculate the address of the first byte of the first 4KiB page in the i-th region
            uint8_t *access_address = (uint8_t *)buffer + (size_t)i * THP_SIZE;

            // Read the value from this address
            // The 'volatile' keyword ensures the compiler doesn't optimize this read away.
            value = *access_address;
			sum += value;
        }
    }

    printf("Finished %ld access loops, sum: %ld.\n", num_access_loops, sum);

	munmap(buffer, buffer_size);

    // Allocate a buffer using mmap()
    buffer = mmap((void *)(4UL << 30), buffer_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (buffer == MAP_FAILED) {
        perror("mmap failed");
        return EXIT_FAILURE;
    }

    printf("Re-allocated buffer of size %zu bytes at address %p\n", buffer_size, buffer);

	printf("Issuing MADV_HUGEPAGE...\n");
	assert(!madvise(buffer, buffer_size, MADV_HUGEPAGE));

	memset(buffer, 0xfe, buffer_size);

	//printf("Issuing MADV_COLLAPSE...\n");
	//assert(!madvise(buffer, buffer_size, MADV_HUGEPAGE));
	//assert(!madvise(buffer, buffer_size, MADV_COLLAPSE));
	//assert(!madvise(buffer, buffer_size, MADV_POPULATE_WRITE));
	//memset(buffer, 0xfe, buffer_size);

    printf("Repeatedly accessing initialized pages, %ld loops...\n", num_access_loops);

    for (long loop = 0; loop < num_access_loops * 2; ++loop) {
        for (i = 0; i < num_tlb_entries; ++i) {
            // Calculate the address of the first byte of the first 4KiB page in the i-th region
            uint8_t *access_address = (uint8_t *)buffer + (size_t)i * THP_SIZE;

            // Read the value from this address
            // The 'volatile' keyword ensures the compiler doesn't optimize this read away.
            value = *access_address;
			sum += value;
        }
    }

    printf("Finished %ld access loops, sum: %ld.\n", num_access_loops, sum);

    printf("Repeatedly accessing a subset of pages, %ld loops...\n", num_access_loops * 10);

    for (long loop = 0; loop < num_access_loops * 100; ++loop) {
        for (i = 0; i < num_tlb_entries / 50; ++i) {
            // Calculate the address of the first byte of the first 4KiB page in the i-th region
            uint8_t *access_address = (uint8_t *)buffer + (size_t)i * THP_SIZE + (random() % THP_SIZE);

            // Read the value from this address
            // The 'volatile' keyword ensures the compiler doesn't optimize this read away.
            value = *access_address;
			sum += value;
        }
    }

    printf("Finished %ld access loops, sum: %ld.\n", num_access_loops * 10, sum);

	sleep(3600);

    return EXIT_SUCCESS;
}

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <stddef.h>
#include <assert.h>
#include <stdbool.h>

#include "arm-spe-pkt-decoder.h"

// Define the ARM SPE PMU type. This value can typically be found in
// /sys/bus/event_source/devices/arm_spe_<N>/type on a system with SPE enabled.
// Replace this with the actual value from your system if necessary.
#define ARM_SPE_PMU_TYPE 88 // Example value, confirm on your system

// Structure to hold the perf event file descriptor and mapped buffers
struct perf_event_info {
    int fd;
    void *mmap_buf;
    void *aux_mmap_buf;
    size_t mmap_size;
    size_t aux_mmap_size;
    struct perf_event_mmap_page *metadata_page;
};

struct spe_packet {
	unsigned long va;
	bool tlb;
	bool llc;
	unsigned long lat;
	unsigned long xlat;
};

// Function to open a perf event for ARM SPE
long perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// Function to initialize and open the perf event for ARM SPE
int spe_perf_init(struct perf_event_info *info, size_t mmap_pages, size_t aux_mmap_pages) {
    struct perf_event_attr attr;
    int ret;

    memset(&attr, 0, sizeof(struct perf_event_attr));
    attr.type = ARM_SPE_PMU_TYPE;
    attr.size = sizeof(struct perf_event_attr);

    // Configure the SPE event. The exact config bits depend on the ARM SPE
    // implementation and kernel version. These values are examples.
    // Consult the kernel source (drivers/perf/arm_spe_pmu.c) and
    // /sys/bus/event_source/devices/arm_spe_<N>/format/* for actual bits.
    attr.config = (1UL << 16) | (1UL << 33) | (1UL << 34);
    attr.config1 = 0x8;
    attr.sample_period = 1024;

    // Configure sample information to be collected.
    // PERF_SAMPLE_RAW is crucial for SPE as it indicates data in the AUX buffer.
#if 0
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
                       PERF_SAMPLE_ADDR | PERF_SAMPLE_RAW | PERF_SAMPLE_CPU |
                       PERF_SAMPLE_PERIOD;
#endif
    attr.sample_type = PERF_SAMPLE_RAW;

    //attr.aux_watermark = sysconf(_SC_PAGESIZE); // Trigger AUX event when enough data is available
    //attr.aux_watermark = 1UL << 12;

    attr.disabled = 1; // Start disabled

    // Open the perf event for the current process on any CPU
    info->fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (info->fd < 0) {
        perror("perf_event_open failed");
        return -1;
    }

    // Determine mmap size. The ring buffer requires 1 metadata page + 2^n data pages.
    info->mmap_size = (mmap_pages + 1) * sysconf(_SC_PAGESIZE);
    info->mmap_buf = mmap(NULL, info->mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, info->fd, 0);
    if (info->mmap_buf == MAP_FAILED) {
        perror("mmap failed for main buffer");
        close(info->fd);
        return -1;
    }
    info->metadata_page = info->mmap_buf;

    // mmap the AUX buffer
    info->aux_mmap_size = aux_mmap_pages * sysconf(_SC_PAGESIZE);
	info->metadata_page->aux_offset = info->metadata_page->data_offset + info->metadata_page->data_size;
	info->metadata_page->aux_size = info->aux_mmap_size;
    info->aux_mmap_buf = mmap(NULL, info->aux_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, info->fd, info->metadata_page->aux_offset);
    if (info->aux_mmap_buf == MAP_FAILED) {
        perror("mmap failed for aux buffer");
        munmap(info->mmap_buf, info->mmap_size);
        close(info->fd);
        return -1;
    }

	printf("%lx %lx %lx\n", info->metadata_page->data_head, info->metadata_page->data_offset, info->metadata_page->data_size);
	printf("%lx %lx %lx\n", info->metadata_page->aux_head, info->metadata_page->aux_offset, info->metadata_page->aux_size);

    return 0;
}

// Function to read and process perf events
void process_spe_data(struct perf_event_info *info) {
    struct perf_event_mmap_page *metadata_page = info->metadata_page;
    size_t page_size = sysconf(_SC_PAGESIZE);

    long head = metadata_page->data_head % info->metadata_page->data_size;
	long start = 0;
    size_t offset = metadata_page->data_offset;

    void *base = info->mmap_buf + page_size;

	printf("%lx %lx %lx\n", offset, head, base);

    while (start < head) {
        struct perf_event_header *header = (struct perf_event_header *)(base + start);

        // Process different event types
        switch (header->type) {
            case PERF_RECORD_AUX: {
                struct {
                    struct perf_event_header header;
                    unsigned long aux_offset;
                    unsigned long aux_size;
                    unsigned long flags;
                } *aux_record = (void *)header;

				if (aux_record->flags) {
					printf("AUX flags: %llx\n", aux_record->flags);
				}
				printf("AUX size: %llu\n", aux_record->aux_size);
                //printf("AUX: offset=%llx, size=%llx, flags=%llx\n",
                //       aux_record->aux_offset, aux_record->aux_size, aux_record->flags);

                // Process SPE data in the AUX buffer
                if (aux_record->aux_size > 0 && aux_record->aux_offset < info->aux_mmap_size) {
                    void *spe_data = info->aux_mmap_buf + aux_record->aux_offset;
                    size_t spe_data_size = aux_record->aux_size;

                    // TODO: Parse the SPE data packets from spe_data.
                    // The format is architecture-defined and found in the kernel source.
                    //printf("  SPE data at AUX offset %llx, size %llx. (Parsing requires kernel source details)\n",
                    //      aux_record->aux_offset, aux_record->aux_size);

					//printf("0x%lx 0x%lx\n", *((char *)spe_data), *((char *)spe_data  + 1));
					struct spe_packet pkt = { 0 };

					while (spe_data_size) {
						struct arm_spe_pkt packet;
						size_t ret = arm_spe_do_get_packet(spe_data, spe_data_size, &packet);
						//printf("%ld\n", ret);
						spe_data += ret;
						spe_data_size -= ret;

						switch (packet.type) {
							case ARM_SPE_EVENTS:
								if (packet.payload & (1ul << EV_TLB_WALK)) {
									//printf("TLB walk\n");
									pkt.tlb = 1;
								}
								if (packet.payload & (1ul << EV_LLC_MISS)) {
									//printf("LLC miss\n");
									pkt.llc = 1;
								}
								break;
							case ARM_SPE_COUNTER:
								if (packet.index == SPE_CNT_PKT_HDR_INDEX_TOTAL_LAT) {
									//printf("TOT: %lu\n", packet.payload);
									pkt.lat = packet.payload;
								}
								else if (packet.index == SPE_CNT_PKT_HDR_INDEX_TRANS_LAT) {
									//printf("TOT: %lu\n", packet.payload);
									pkt.xlat = packet.payload;
								}
								break;
							case ARM_SPE_ADDRESS:
								if (packet.index == 0x2) {
									//printf("VA: 0x%lx\n", packet.payload);
									pkt.va = packet.payload;
								}
								break;
							case ARM_SPE_END: 
							case ARM_SPE_TIMESTAMP:
								if (pkt.tlb || pkt.llc) {
									printf("0x%lx %lu (%lu) %s\n", pkt.va, pkt.lat, pkt.xlat, pkt.tlb ? "TLB" : "LLC");
								}
								memset(&pkt, 0, sizeof(pkt));
								break;
						}
					}
                    // Example of how you might start parsing (highly dependent on kernel): // struct spe_packet_header *pkt_header = spe_data;
                    // switch (pkt_header->type) { ... }
                }

                // Mark AUX data as consumed by the kernel (important!)
                // This is typically done by updating the aux_tail in the metadata page.
                // The exact mechanism might involve an ioctl or updating the metadata page directly.
                // Consult kernel documentation or source.
                metadata_page->aux_tail = aux_record->aux_offset + aux_record->aux_size;

                break;
            }
            default:
                //printf("Unknown perf event type: %u (size: %u)\n", header->type, header->size);
                break;
        }

        start += header->size;
    }

    printf("aux tail: 0x%llx (0x%llx)\n", metadata_page->aux_tail, metadata_page->aux_offset + metadata_page->aux_size);
    // Update the kernel's view of the consumed data
    metadata_page->data_tail = head;
}


// Function to clean up perf resources
void spe_perf_cleanup(struct perf_event_info *info) {
    if (info->mmap_buf != MAP_FAILED) {
        munmap(info->mmap_buf, info->mmap_size);
    }
    if (info->aux_mmap_buf != MAP_FAILED) {
        munmap(info->aux_mmap_buf, info->aux_mmap_size);
    }
    if (info->fd >= 0) {
        close(info->fd);
    }
}

int main() {
    struct perf_event_info info;
    memset(&info, 0, sizeof(info));
    info.fd = -1; // Initialize fd to an invalid value

    // Choose the size of the main ring buffer and AUX buffer in pages (must be powers of 2)
    // The main buffer size is 1 + 2^n pages. The AUX buffer size is 2^m pages.
    size_t main_buffer_pages_exp = 4; // 2^4 = 16 pages for data
    size_t aux_buffer_pages_exp = 15;

    if (spe_perf_init(&info, (1 << main_buffer_pages_exp), (1 << aux_buffer_pages_exp)) < 0) {
        fprintf(stderr, "Failed to initialize SPE perf event.\n");
        return EXIT_FAILURE;
    }

    printf("SPE perf event opened successfully (fd: %d).\n", info.fd);
    printf("Main buffer mmaped at %p, size %zu.\n", info.mmap_buf, info.mmap_size);
    printf("AUX buffer mmaped at %p, size %zu.\n", info.aux_mmap_buf, info.aux_mmap_size);

    // Enable the perf event
    if (ioctl(info.fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        perror("ioctl(PERF_EVENT_IOC_ENABLE) failed");
        spe_perf_cleanup(&info);
        return EXIT_FAILURE;
    }

    printf("SPE perf event enabled. Running workload...\n");

    // --- Replace with your target workload ---
    // The code you want to profile goes here.
    // For demonstration, we'll just sleep for a few seconds.
	size_t i, j, sum = 0;

	volatile void *buf = mmap(NULL, 32UL << 30, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
	assert(buf != MAP_FAILED);

	//memset(buf, 0xff, 1UL << 30);
	//
	for (j = 0; j < 5; j++) {
		for (i = 0; i < 32UL << 30; i += 4096) {
			volatile char x = ((volatile char *)buf)[i];
			sum += x;
		}
		//munmap(buf, 1UL << 30);
	}
	printf("%lx\n", sum);

    printf("Workload finished. Disabling SPE perf event...\n");

    // Disable the perf event
    if (ioctl(info.fd, PERF_EVENT_IOC_DISABLE, 0) < 0) {
        perror("ioctl(PERF_EVENT_IOC_DISABLE) failed");
        spe_perf_cleanup(&info);
        return EXIT_FAILURE;
    }

    printf("SPE perf event disabled. Processing collected data...\n");

    // Process the collected data
    process_spe_data(&info);

    printf("Data processing finished. Cleaning up...\n");

    // Clean up resources
    spe_perf_cleanup(&info);

    printf("Cleanup complete.\n");

    return EXIT_SUCCESS;
}

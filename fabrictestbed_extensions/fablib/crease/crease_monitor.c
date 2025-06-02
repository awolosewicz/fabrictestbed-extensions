/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */
#define _POSIX_C_SOURCE 199309L
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 16383
#define MBUF_CACHE_SIZE 127
#define BURST_SIZE 32

#define	PKT_MBUF_DATA_SIZE	RTE_MBUF_DEFAULT_BUF_SIZE
#define	HDR_MBUF_DATA_SIZE	128 + RTE_PKTMBUF_HEADROOM
#define	TLR_MBUF_DATA_SIZE	128 + RTE_PKTMBUF_HEADROOM

#define NSEC_PER_SEC        1000000000L

#define MONPROT 0x6587
#define MONPROT0 0x65
#define MONPROT1 0x87

#ifdef PROFILING
#define TIME_BUILD_TRAILER 0
#define TIME_ADD_TRAILER 1
#define TIME_ADD_HEADERS 2
#define TIME_OTHER 3
#define TIME_TX_PKTS 4
#define TIME_GET_TIME 5

#define TIME_AVG_BUILD_TRAILER 6
#define TIME_AVG_ADD_TRAILER 7
#define TIME_AVG_ADD_HEADERS 8
#define TIME_AVG_OTHER 9
#define TIME_AVG_TX_PKTS 10
#define TIME_AVG_GET_TIME 11

#define TIME_MAX_BUILD_TRAILER 12
#define TIME_MAX_ADD_TRAILER 13
#define TIME_MAX_ADD_HEADERS 14
#define TIME_MAX_OTHER 15
#define TIME_MAX_TX_PKTS 16
#define TIME_MAX_GET_TIME 17

#define TIME_MDEV_BUILD_TRAILER 18
#define TIME_MDEV_ADD_TRAILER 19
#define TIME_MDEV_ADD_HEADERS 20
#define TIME_MDEV_OTHER 21
#define TIME_MDEV_TX_PKTS 22
#define TIME_MDEV_GET_TIME 23
#endif

static uint64_t tsc_hz;

static inline uint64_t timespec64_to_ns(const struct timespec *ts)
{
	return ((uint64_t) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}

/* basicfwd.c: Basic DPDK skeleton forwarding example. */
#ifdef PROFILING
static uint64_t measures[24];
uint64_t start = 0;
uint64_t pop_size = 0;
#endif
unsigned char ana_headers[64];
// Ether(14) + IPv6(40) + len(2) + 2xUID(32)
const uint16_t ana_size = 88;
uint64_t mon_id;
static struct rte_mempool *packet_pool, *clone_pool;

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxconf;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	rxconf = dev_info.default_rxconf;
	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval < 0) {
		printf("Failed to get MAC address on port %u: %s\n",
			port, rte_strerror(-retval));
		return retval;
	}

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */

bool lendian = false;

static inline uint16_t
swap_endian_short(uint16_t value) {
    return ((value >> 8)  & 0x00FF) |
           ((value << 8)  & 0xFF00);
}

static inline uint32_t
swap_endian(uint32_t value) {
    return ((value >> 24) & 0x000000FF) |
           ((value >> 8)  & 0x0000FF00) |
           ((value << 8)  & 0x00FF0000) |
           ((value << 24) & 0xFF000000);
}

static inline uint64_t
swap_endian_long(uint64_t value) {
    return ((value >> 56) & 0x00000000000000FF) |
           ((value >> 40) & 0x000000000000FF00) |
           ((value >> 24) & 0x0000000000FF0000) |
           ((value >> 8)  & 0x00000000FF000000) |
           ((value << 8)  & 0x000000FF00000000) |
           ((value << 24) & 0x0000FF0000000000) |
           ((value << 40) & 0x00FF000000000000) |
           ((value << 56) & 0xFF00000000000000);
}

/**
 * This function handles adding (if needed) the custom trailer that stores the packet UID.
 * The UID is formed as:
 * 0                 64       80         96          112       128
 * | timestamp in ns | mon_id | port num | frame len | MONPROT |
 * Additionally, this function crafts the packet that goes to the analyzer, which is formed as
 * 0				54           56                64       66        68    70    72
 * | ethernet + ip6 | packet len | timestamp in ns | mon_id | port_id | res | res |
 * 72            80
 * | UID trailer | 80 bytes of header stack |
 */
static inline void
crinkle_forward(
	struct rte_mbuf **bufs,
	struct rte_mbuf **cbufs,
	const uint16_t nb_pkts,
	const uint64_t systime_ns,
	const uint64_t port)
{
	for (int i = 0; i < nb_pkts; ++i) {
		#ifdef PROFILING
		start = rte_get_tsc_cycles();
		#endif
		struct rte_mbuf *buf = bufs[i];
		struct rte_mbuf *cbuf;
		if (unlikely ((cbuf = rte_pktmbuf_clone(buf, clone_pool)) == NULL)) {
			continue;
		}
		uint8_t *c;
		
		// candidate_trailer points to the lower 4 bytes, which are the ts check and MONPROT
		uint32_t *candidate_trailer_ptr = rte_pktmbuf_mtod_offset(buf, uint32_t*, buf->data_len-4);
		uint32_t candidate_trailer = *candidate_trailer_ptr;
		// The ts corresponding to ts check
		uint32_t ts_lower = *(candidate_trailer_ptr-2);
		#ifdef PROFILING
		measures[TIME_OTHER] = rte_get_tsc_cycles() - start;

		start = rte_get_tsc_cycles();
		#endif
		uint64_t uid_trailer[2];
		uid_trailer[0] = systime_ns + i;
		uid_trailer[1] = (mon_id << 48) + (port << 32) + ((uid_trailer[0] << 16) & 0x00000000FFFF0000) + MONPROT;
		uint16_t pkt_size = buf->data_len+16;
		if (lendian) {
			pkt_size = swap_endian_short(pkt_size);
			candidate_trailer = swap_endian(candidate_trailer);
			ts_lower = swap_endian(ts_lower);
			uid_trailer[0] = swap_endian_long(uid_trailer[0]);
			uid_trailer[1] = swap_endian_long(uid_trailer[1]);
		}
		#ifdef PROFILING
		measures[TIME_BUILD_TRAILER] = rte_get_tsc_cycles() - start;
		#endif

		// Check for existing UUID trailer
		if ((candidate_trailer & 0x0000FFFF) != MONPROT || (candidate_trailer >> 16) != (ts_lower & 0x0000FFFF)) {
			#ifdef PROFILING
			start = rte_get_tsc_cycles();
			#endif
			uint8_t *trailer;
			if (unlikely((trailer = (uint8_t *)rte_pktmbuf_append(buf, 16)) == NULL)) {
				printf("Failed to append trailer to packet %d\n", i);
				rte_pktmbuf_free(cbuf);
				continue;
			}
			rte_mov16(trailer, (uint8_t *)uid_trailer);
			#ifdef PROFILING
			measures[TIME_ADD_TRAILER] = rte_get_tsc_cycles() - start;
			#endif
		}

		#ifdef PROFILING
		start = rte_get_tsc_cycles();
		#endif
		uint8_t *trailer = rte_pktmbuf_mtod_offset(buf, uint8_t*, buf->data_len-16);
		if (unlikely((c = (uint8_t*)rte_pktmbuf_prepend(cbuf, 88)) == NULL)) {
			printf("Failed to append clone packet %d\n", i);
			rte_pktmbuf_free(cbuf);
			continue;
		}
		rte_mov64(c, ana_headers);
		rte_mov15_or_less(c+54, (uint8_t *)(&pkt_size), 2);
		rte_mov16(c+56, (uint8_t *)uid_trailer);
		rte_mov16(c+72, trailer);
		cbufs[i] = cbuf;
		#ifdef PROFILING
		measures[TIME_ADD_HEADERS] = rte_get_tsc_cycles() - start;
		#endif
	}
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(uint16_t vport_to_devport[], uint16_t devport_to_vport[])
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Main work of application loop. 8< */
	struct timespec systime;
	uint64_t systime_ns;

	// Tests for little endian memory, since we must write to packet
	// buffers values in big-endian format
	int num = 1;
	if (*(char *)&num == 1) {
        lendian = true;
    }

	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {

			// port 0 is the analyzer
			if (port == vport_to_devport[0]) continue;

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			// struct rte_mbuf *cbufs[BURST_SIZE];
			// int retval = rte_pktmbuf_alloc_bulk(mbuf_pool, cbufs, nb_rx);
			// if (retval != 0) {
			// 	printf("Failed to allocate clone bufs: Code %i\n", retval);
			// }
			#ifdef PROFILING
			start = rte_get_tsc_cycles();
			#endif
			clock_gettime(CLOCK_REALTIME, &systime);
			systime_ns = timespec64_to_ns(&systime);
			#ifdef PROFILING
			measures[TIME_GET_TIME] = rte_get_tsc_cycles() - start;
			#endif
			struct rte_mbuf *cbufs[BURST_SIZE];
			crinkle_forward(bufs, cbufs, nb_rx, systime_ns, devport_to_vport[port]);


			#ifdef PROFILING
			start = rte_get_tsc_cycles();
			#endif
			/* Send burst of TX packets, to second port of pair. */
			uint16_t nb_tx = 0;
			if (port == vport_to_devport[1]) {
				nb_tx = rte_eth_tx_burst(vport_to_devport[2], 0,
						bufs, nb_rx);
			}
			else {
				nb_tx = rte_eth_tx_burst(vport_to_devport[1], 0,
						bufs, nb_rx);
			}

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
			
			nb_tx = rte_eth_tx_burst(vport_to_devport[0], 0, cbufs, nb_rx);
			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(cbufs[buf]);
			}
			#ifdef PROFILING
			measures[TIME_TX_PKTS] = rte_get_tsc_cycles() - start;
			#endif

			// timing
			#ifdef PROFILING
			uint64_t delta1 = 0;
			uint64_t delta2 = 0;
			if (nb_tx == 0) {
				continue;
			}
			++pop_size;
			for (int i = 0; i < 6; ++i) {
				delta1 = measures[i] - measures[i+6];
				measures[i+6] = measures[i+6] + (delta1 / pop_size);
				delta2 = measures[i] - measures[i+6];
				measures[i+12] = RTE_MAX(measures[i+12], measures[i]);
				measures[i+18] = measures[i+18] + (delta1 * delta2);
			}
			if (pop_size % 100 == 0) {
				printf("Pop\t%lu\n", pop_size);
				for (int i = 0; i < 6; ++i) {
					printf("Time\t%d\t%lu\t%lu\t%lu\t%lu\n", i,
						   measures[i], measures[i+6], measures[i+12], measures[i+18]);
				}
				fflush(stdout);
			}
			#endif
		}
	}
	/* >8 End of loop. */
}
/* >8 End Basic forwarding application lcore. */



/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	unsigned nb_ports;
	uint16_t portid;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	
	int arg;
	uint16_t vport_to_devport[nb_ports];
	uint16_t devport_to_vport[nb_ports];
	bool set_mon_id = false;
	bool set_macs = false;
	bool set_ips = false;

	const unsigned char ipdata[10] = "\x86\xdd\x60\x00\x00\x00\x00\x50\xfe\x40";
	rte_memcpy(&ana_headers[12], ipdata, 10);
	const unsigned char padding[10] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	rte_memcpy(&ana_headers[54], padding, 10);
	bool macdst = false;
	bool ipdst = false;

	while ((arg = getopt(argc, argv, "n:d:m:i:hv")) != -1) {
		switch (arg) {
			case 'n':
				mon_id = strtol(optarg, NULL, 0);
				set_mon_id = true;
				break;
			case 'd':
				// [dpdk virtual port]@[device number as parsed into dpdk]
				uint16_t vport, devport;
				sscanf(optarg, "%hu@%hu", &vport, &devport);
				vport_to_devport[vport] = devport;
				devport_to_vport[devport] = vport;
				break;
			case 'm':
				// MAC addresses, source then dest
				int parsed = 0;
				if (macdst) {
					parsed = sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
									&ana_headers[0], &ana_headers[1], &ana_headers[2],
									&ana_headers[3], &ana_headers[4], &ana_headers[5]);
					set_macs = true;
				}
				else {
					parsed = sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
									&ana_headers[6], &ana_headers[7], &ana_headers[8],
									&ana_headers[9], &ana_headers[10], &ana_headers[11]);
					macdst = true;
				}
				if (parsed != 6) {
					rte_exit(EXIT_FAILURE, "Invalid MAC address\n");
				}
				break;
			case 'i':
				// IPv6 addresses, source then dest
				if (ipdst) {
					if (inet_pton(AF_INET6, optarg, &ana_headers[38]) != 1) {
						rte_exit(EXIT_FAILURE, "Invalid IPv6 address\n");
					}
					set_ips = true;
				}
				else {
					if (inet_pton(AF_INET6, optarg, &ana_headers[22]) != 1) {
						rte_exit(EXIT_FAILURE, "Invalid IPv6 address\n");
					}
					ipdst = true;
				}
				break;
			case 'h':
				printf("Available options:\n");
				printf("  -n    Set monitor ID\n");
				printf("  -d    Set virtual-actual device mappings, as [virtual]@[actual], actual as parsed by dpdk\n");
				printf("  -m    Set MAC addresses for analyzer (source then dest)\n");
				printf("  -i    Set IP addresses for analyzer (source then dest)\n");
				printf("  -h    Print this help\n");
				printf("  -v    Print version\n");
				exit(EXIT_SUCCESS);
			case 'v':
				printf("Crease Monitor v0.3\n");
				exit(EXIT_SUCCESS);
			case '?':
				switch (optopt) {
					case 'd':
					case 'm':
					case 'i':
					case 'n':
						rte_exit(EXIT_FAILURE, "Option -%c requires an argument.\n", optopt);
					default:
						rte_exit(EXIT_FAILURE, "Unknown option -%c.\n", optopt);
				}
			default:
				abort();
		}
	}
	if (!set_macs) {
		rte_exit(EXIT_FAILURE, "Missing MAC addresses for analyzer connection.\n");
	}
	if (!set_ips) {
		rte_exit(EXIT_FAILURE, "Missing IP addresses for analyzer connection.\n");
	}
	if (!set_mon_id) {
		rte_exit(EXIT_FAILURE, "Did not set monitor id.\n");
	}
	for (uint16_t i = 0; i < nb_ports; ++i) {
		if (vport_to_devport[i] >= nb_ports) {
			rte_exit(EXIT_FAILURE, "Invalid port mapping for virtual port %hu: %hu.\n", i, vport_to_devport[i]);
		}
	}

	packet_pool = rte_pktmbuf_pool_create("packet_pool", NUM_MBUFS, MBUF_CACHE_SIZE,
		0, PKT_MBUF_DATA_SIZE, rte_socket_id());

	if (packet_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init packet mbuf pool\n");

	clone_pool = rte_pktmbuf_pool_create("clone_pool", NUM_MBUFS , MBUF_CACHE_SIZE,
		0, 0, rte_socket_id());

	if (clone_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init clone mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, packet_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
	
	tsc_hz = rte_get_tsc_hz();
	printf("Running at %lu hz\n", tsc_hz);

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main(vport_to_devport, devport_to_vport);
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}

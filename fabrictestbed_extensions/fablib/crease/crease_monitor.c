/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */
#define _POSIX_C_SOURCE 199309L
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>
#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define NSEC_PER_SEC        1000000000L

// HW timestamping code derived from rxtx_calbacks
static int hwts_dynfield_offset = -1;

static inline rte_mbuf_timestamp_t *
hwts_field(struct rte_mbuf *mbuf)
{
	return RTE_MBUF_DYNFIELD(mbuf,
			hwts_dynfield_offset, rte_mbuf_timestamp_t *);
}
int hw_timestamping = 0;

#define TICKS_PER_CYCLE_SHIFT 16
static uint64_t ticks_per_cycle_mult;
static uint64_t tsc_hz;

static inline uint64_t timespec64_to_ns(const struct timespec *ts)
{
	return ((uint64_t) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}

static struct timeval
ns_to_timeval(int64_t nsec)
{
	struct timespec t_spec = {0, 0};
	struct timeval t_eval = {0, 0};
	int32_t rem;

	if (nsec == 0)
		return t_eval;
	rem = nsec % NSEC_PER_SEC;
	t_spec.tv_sec = nsec / NSEC_PER_SEC;

	if (rem < 0) {
		t_spec.tv_sec--;
		rem += NSEC_PER_SEC;
	}

	t_spec.tv_nsec = rem;
	t_eval.tv_sec = t_spec.tv_sec;
	t_eval.tv_usec = t_spec.tv_nsec / 1000;

	return t_eval;
}

/* basicfwd.c: Basic DPDK skeleton forwarding example. */
static uint64_t measures[16];

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

	if (hw_timestamping) {
		if (!(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP)) {
			printf("\nERROR: Port %u does not support hardware timestamping\n"
					, port);
			return -1;
		}
		port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
		rte_mbuf_dyn_rx_timestamp_register(&hwts_dynfield_offset, NULL);
		if (hwts_dynfield_offset < 0) {
			printf("ERROR: Failed to register timestamp field\n");
			return -rte_errno;
		}
	}

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

	if (hw_timestamping && ticks_per_cycle_mult  == 0) {
		uint64_t cycles_base = rte_rdtsc();
		uint64_t ticks_base;
		retval = rte_eth_read_clock(port, &ticks_base);
		if (retval != 0)
			return retval;
		rte_delay_ms(100);
		uint64_t cycles = rte_rdtsc();
		uint64_t ticks;
		rte_eth_read_clock(port, &ticks);
		uint64_t c_freq = cycles - cycles_base;
		uint64_t t_freq = ticks - ticks_base;
		double freq_mult = (double)c_freq / t_freq;
		printf("TSC Freq ~= %" PRIu64
				"\nHW Freq ~= %" PRIu64
				"\nRatio : %f\n",
				c_freq * 10, t_freq * 10, freq_mult);
		/* TSC will be faster than internal ticks so freq_mult is > 0
			* We convert the multiplication to an integer shift & mult
			*/
		ticks_per_cycle_mult = (1 << TICKS_PER_CYCLE_SHIFT) / freq_mult;
	}

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

static inline uint64_t
hwts_to_ns(rte_mbuf_timestamp_t hwts) {
	uint64_t cycles = (hwts * ticks_per_cycle_mult) >> TICKS_PER_CYCLE_SHIFT;
	return (cycles / tsc_hz) * NSEC_PER_SEC;
}

bool lendian = false;

static inline uint64_t
swap_endian(uint64_t value) {
    return ((value >> 56) & 0x00000000000000FF) |
           ((value >> 40) & 0x000000000000FF00) |
           ((value >> 24) & 0x0000000000FF0000) |
           ((value >> 8)  & 0x00000000FF000000) |
           ((value << 8)  & 0x000000FF00000000) |
           ((value << 24) & 0x0000FF0000000000) |
           ((value << 40) & 0x00FF000000000000) |
           ((value << 56) & 0xFF00000000000000);
}

static inline void
crinkle_forward(
	struct rte_mbuf **bufs,
	char **c_plds,
	const uint16_t nb_pkts,
	const uint64_t systime_ns)
{
	for (int i = 0; i < nb_pkts; ++i) {
		struct rte_mbuf *buf = bufs[i];
		char *c_pld = c_plds[i];

		uint64_t time;
		if (hw_timestamping) {
			time = systime_ns + hwts_to_ns(*hwts_field(buf));
		}
		else {
			time = systime_ns + i;
		}
		char * trailer = rte_pktmbuf_append(buf, 16);
		static const uint64_t id = 0x0123456789ABCDEF;
		if (lendian) {
			uint64_t id2 = swap_endian(id);
			uint64_t time2 = swap_endian(time);
			*((uint64_t *)trailer) = id2;
			*((uint64_t *)c_pld) = id2;
			*((uint64_t *)(trailer+64)) = time2;
			*((uint64_t *)(c_pld+8)) = time2;
		}
		else {
			*((uint64_t *)trailer) = id;
			*((uint64_t *)c_pld) = id;
			*((uint64_t *)(trailer+64)) = time;
			*((uint64_t *)(c_pld+8)) = time;
		}
		char * buf_start = rte_pktmbuf_mtod(buf, char*);
		rte_mov64(c_pld+16, buf_start);
		rte_mov16(c_pld+80, buf_start+64);

	}
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(struct rte_mempool *mbuf_pool)
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
	uint8_t ctr = 0;
	//p2 is the analyzer port
	const uint16_t p0 = 1;
	const uint16_t p1 = 2;
	const uint16_t p2 = 0;
	struct timespec systime;
	uint64_t systime_ns;

	// Tests for little endian memory, since we must write to packet
	// buffers values in big-endian format
	const int num = 1;
	if (*(char *)&num == 1) {
        lendian = true;
    }

	struct rte_mbuf *clone_bufs[BURST_SIZE];
	int retval = rte_pktmbuf_alloc_bulk(mbuf_pool, clone_bufs, BURST_SIZE);
	if (retval != 0) {
		printf("Failed to allocate clone bufs: Code %i\n", retval);
	}
	char *clone_plds[BURST_SIZE];
	// Clone addresses will always be the same, so keep constant
	for (int i = 0; i < BURST_SIZE; ++i) {
		struct rte_mbuf *cbuf = clone_bufs[i];
		char *c = rte_pktmbuf_append(cbuf, 64+16+80);
		static const unsigned char data[64] = "\xb0\xa6\x51\xe2\x44\xda\x0a\x66\xc4\x9b\xa7\x99\x86\xdd\x60\x00\x00\x00\x00\x50\xfe\x40"
											  "\x26\x02\xfc\xfb\x00\x22\x00\x01\x08\x66\xc4\xff\xfe\x9b\xa7\x99"
											  "\x26\x02\xfc\xfb\x00\x22\x00\x01\x04\xb4\xea\xff\xfe\x74\x3c\xe8"
											  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
		rte_mov64(c, data);
		clone_plds[i] = c + 64;
	}
	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {

			if (port == p2) continue;

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			uint64_t start = rte_get_tsc_cycles();
			clock_gettime(CLOCK_REALTIME, &systime);
			systime_ns = timespec64_to_ns(&systime);
			crinkle_forward(bufs, clone_plds, nb_rx, systime_ns);
			uint64_t end = rte_get_tsc_cycles();

			/* Send burst of TX packets, to second port of pair. */
			uint16_t nb_tx = 0;
			if (port == p0) {
				nb_tx = rte_eth_tx_burst(p1, 0,
						bufs, nb_rx);
			}
			else {
				nb_tx = rte_eth_tx_burst(p0, 0,
						bufs, nb_rx);
			}

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
			
			nb_tx = rte_eth_tx_burst(p2, 0, clone_bufs, nb_rx);
			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(clone_bufs[buf]);
			}

			measures[ctr++] = end - start;
			if (ctr == sizeof(measures)/sizeof(measures[0])) {
				printf("%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
					   measures[0], measures[1], measures[2], measures[3],
					   measures[4], measures[5], measures[6], measures[7],
					   measures[8], measures[9], measures[10], measures[11],
					   measures[12], measures[13], measures[14], measures[15]);
				fflush(stdout);
				ctr = 0;
			}
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
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	// uint64_t tstart = rte_get_tsc_cycles();
	// struct rte_mbuf * data2 = rte_pktmbuf_alloc(mbuf_pool);
	// uint64_t tend = rte_get_tsc_cycles();
	// uint64_t hz2 = rte_get_tsc_cycles();
	// printf("Delta %lu at hz %lu", tend-tstart, hz2);

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	// if (nb_ports < 2 || (nb_ports & 1))
	// 	rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
	
	tsc_hz = rte_get_tsc_hz();
	printf("Running at %lu hz\n", tsc_hz);

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main(mbuf_pool);
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}

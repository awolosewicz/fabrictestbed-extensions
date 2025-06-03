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

#define NUM_MBUFS 16383
#define MBUF_CACHE_SIZE 127
#define BURST_SIZE 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3

/* allow max jumbo frame 9.5 KB */
#define	JUMBO_FRAME_MAX_SIZE	0x2600
#define MAX_RX_MTU 1500

#define	PKT_MBUF_DATA_SIZE	RTE_MBUF_DEFAULT_BUF_SIZE
#define	HDR_MBUF_DATA_SIZE	128 + RTE_PKTMBUF_HEADROOM
#define	TLR_MBUF_DATA_SIZE	128 + RTE_PKTMBUF_HEADROOM

#define NSEC_PER_SEC        1000000000L

#define MONPROT 0x6587
#define MONPROT0 0x65
#define MONPROT1 0x87

#define MAX_PORTS 3

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

static int rx_queue_per_lcore = 1;

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
static uint16_t nb_rxd = RX_RING_SIZE;
static uint16_t nb_txd = TX_RING_SIZE;
/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[MAX_PORTS];

static uint16_t vport_to_devport[MAX_PORTS];
static uint16_t devport_to_vport[MAX_PORTS];

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[BURST_SIZE];
};

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct __rte_cache_aligned lcore_queue_conf {
	uint64_t tx_tsc;
	uint16_t n_rx_queue;
	uint8_t rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t tx_queue_id[MAX_PORTS];
	struct mbuf_table tx_mbufs[MAX_PORTS];
};
static struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mtu = MAX_RX_MTU,
	},
	.txmode = {},
};

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

static void
print_ethaddr(const char *name, struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

/* Send burst of packets on an output interface */
static void
send_burst(struct lcore_queue_conf *qconf, uint16_t port)
{
	struct rte_mbuf **m_table;
	uint16_t n, queueid;
	int ret;

	queueid = qconf->tx_queue_id[port];
	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;
	n = qconf->tx_mbufs[port].len;

	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	while (unlikely (ret < n)) {
		rte_pktmbuf_free(m_table[ret]);
		ret++;
	}

	qconf->tx_mbufs[port].len = 0;
}

/* Send burst of outgoing packet, if timeout expires. */
static inline void
send_timeout_burst(struct lcore_queue_conf *qconf)
{
	uint64_t cur_tsc;
	uint16_t portid;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	cur_tsc = rte_rdtsc();
	if (likely (cur_tsc < qconf->tx_tsc + drain_tsc))
		return;

	for (portid = 0; portid < MAX_PORTS; portid++) {
		if (qconf->tx_mbufs[portid].len != 0)
			send_burst(qconf, portid);
	}
	qconf->tx_tsc = cur_tsc;
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
	struct rte_mbuf *buf,
	struct lcore_queue_conf *qconf,
	const uint64_t systime_ns,
	const uint64_t port)
{
	#ifdef PROFILING
	start = rte_get_tsc_cycles();
	#endif
	struct rte_mbuf *cbuf;
	if (unlikely ((cbuf = rte_pktmbuf_clone(buf, clone_pool)) == NULL)) {
		return;
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
	uid_trailer[0] = systime_ns;
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
			printf("Failed to append trailer to packet");
			rte_pktmbuf_free(cbuf);
			return;
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
		printf("Failed to append clone packet");
		rte_pktmbuf_free(cbuf);
		return;
	}
	rte_mov64(c, ana_headers);
	rte_mov15_or_less(c+54, (uint8_t *)(&pkt_size), 2);
	rte_mov16(c+56, (uint8_t *)uid_trailer);
	rte_mov16(c+72, trailer);
	#ifdef PROFILING
	measures[TIME_ADD_HEADERS] = rte_get_tsc_cycles() - start;
	#endif
	uint16_t outport;
	if (port == 1) {
		outport = vport_to_devport[2];
	} else {
		outport = vport_to_devport[1];
	}

	uint16_t len = qconf->tx_mbufs[outport].len;
	qconf->tx_mbufs[outport].m_table[len] = cbuf;
	qconf->tx_mbufs[outport].len = ++len;
	if (unlikely(BURST_SIZE == len))
		send_burst(qconf, outport);

	uint16_t ana_len = qconf->tx_mbufs[vport_to_devport[0]].len;
	qconf->tx_mbufs[vport_to_devport[0]].m_table[ana_len] = cbuf;
	qconf->tx_mbufs[vport_to_devport[0]].len = ++ana_len;
	if (unlikely(BURST_SIZE == ana_len))
		send_burst(qconf, vport_to_devport[0]);
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static int
lcore_main(__rte_unused void *dummy)
{
	struct rte_mbuf *bufs[BURST_SIZE];
	unsigned lcore_id;
	int i, j, nb_rx;
	uint16_t portid;
	struct lcore_queue_conf *qconf;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];


	if (qconf->n_rx_queue == 0) {
		printf("lcore %u has nothing to do\n",lcore_id);
		return 0;
	}

	/* Main work of application loop. 8< */
	struct timespec systime;
	uint64_t systime_ns;

	// Tests for little endian memory, since we must write to packet
	// buffers values in big-endian format
	int num = 1;
	if (*(char *)&num == 1) {
        lendian = true;
    }

	for (i = 0; i < qconf->n_rx_queue; ++i) {
		portid = qconf->rx_queue_list[i];
		printf(" -- lcoreid=%u portid=%d\n", lcore_id, portid);
	}

	if (portid == vport_to_devport[0]) {
		while(1) {
			/* Send out packets from TX queues */
			send_timeout_burst(qconf);
		}
	}
	else {
		while (1) {
			#ifdef PROFILING
			start = rte_get_tsc_cycles();
			#endif
			clock_gettime(CLOCK_REALTIME, &systime);
			systime_ns = timespec64_to_ns(&systime);
			#ifdef PROFILING
			measures[TIME_GET_TIME] = rte_get_tsc_cycles() - start;
			#endif
			for (i = 0; i < qconf->n_rx_queue; ++i) {
				portid = qconf->rx_queue_list[i];
				nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

				/* Prefetch first packets */
				for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
					rte_prefetch0(rte_pktmbuf_mtod(bufs[j], void *));
				}

				/* Prefetch and forward already prefetched packets */
				for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
					rte_prefetch0(rte_pktmbuf_mtod(bufs[j + PREFETCH_OFFSET], void *));
					crinkle_forward(bufs[j], qconf, systime_ns++, devport_to_vport[portid]);
				}

				/* Forward remaining prefetched packets */
				for (; j < nb_rx; j++) {
					crinkle_forward(bufs[j], qconf, systime_ns++, devport_to_vport[portid]);
				}
			}
			/* Send out packets from TX queues */
			send_timeout_burst(qconf);
	}

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
	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	unsigned nb_ports = rte_eth_dev_count_avail();
	
	int arg;
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

	uint32_t nb_lcores = rte_lcore_count();
	uint16_t portid;
	uint32_t n_tx_queue;
	unsigned lcore_id = 0, rx_lcore_id = 0;
	struct lcore_queue_conf *qconf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	uint16_t queueid;

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_conf local_port_conf = port_conf;

		qconf = &lcore_queue_conf[rx_lcore_id];

		/* limit the frame size to the maximum supported by NIC */
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		local_port_conf.rxmode.mtu = RTE_MIN(
		    dev_info.max_mtu,
		    local_port_conf.rxmode.mtu);

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       qconf->n_rx_queue == (unsigned)rx_queue_per_lcore) {

			rx_lcore_id ++;
			qconf = &lcore_queue_conf[rx_lcore_id];

			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}
		qconf->rx_queue_list[qconf->n_rx_queue] = portid;
		qconf->n_rx_queue++;

		/* init port */
		printf("Initializing port %d on lcore %u... ", portid,
		       rx_lcore_id);
		fflush(stdout);

		n_tx_queue = nb_lcores;
		if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
			n_tx_queue = MAX_TX_QUEUE_PER_PORT;

		ret = rte_eth_dev_configure(portid, 1, (uint16_t)n_tx_queue,
					    &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n",
				  ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%d\n",
				 ret, portid);

		ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot get MAC address: err=%d, port=%d\n",
				 ret, portid);

		print_ethaddr(" Address:", &ports_eth_addr[portid]);
		printf(", ");

		/* init one RX queue */
		queueid = 0;
		printf("rxq=%hu ", queueid);
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     packet_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%d\n",
				  ret, portid);

		/* init one TX queue per couple (lcore,port) */
		queueid = 0;

		RTE_LCORE_FOREACH(lcore_id) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;
			printf("txq=%u,%hu ", lcore_id, queueid);
			fflush(stdout);

			txconf = &dev_info.default_txconf;
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
						     rte_lcore_to_socket_id(lcore_id), txconf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, "
					  "port=%d\n", ret, portid);

			qconf = &lcore_queue_conf[lcore_id];
			qconf->tx_queue_id[portid] = queueid;
			queueid++;
		}
		ret = rte_eth_promiscuous_enable(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_promiscuous_enable: err=%d, port=%d\n",
				ret, portid);
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n",
				  ret, portid);

		printf("done:\n");
	}
	/* >8 End of initializing all ports. */
	
	tsc_hz = rte_get_tsc_hz();
	printf("Running at %lu hz\n", tsc_hz);

	rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	//lcore_main(vport_to_devport, devport_to_vport);
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}

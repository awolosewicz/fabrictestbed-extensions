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
#include <rte_malloc.h>
#include <rte_ring.h>

#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 128
#define BURST_SIZE 64
#define MIN_REPLAY_SIZE 128
#define BURST_TX_DRAIN_US 1 /* TX drain every ~1us */
/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3

/* allow max jumbo frame 9.5 KB */
#define	JUMBO_FRAME_MAX_SIZE	0x2600
#define MAX_RX_MTU 1500

#define	PKT_MBUF_DATA_SIZE	RTE_MBUF_DEFAULT_BUF_SIZE

#define NSEC_PER_SEC        1000000000L

#define MONPROT 0x6587
#define CREASEPROT 254
#define CREASEVER "Crease Monitor v0.5.0\n"

#define MAX_PORTS 3

static uint64_t tsc_hz;

static inline uint64_t timespec64_to_ns(const struct timespec *ts)
{
	return ((uint64_t) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}

unsigned char ana_headers[64];
// Ether(14) + IPv6(40) + len(2) + 2xUID(32)
const uint16_t ana_size = 88;
uint64_t mon_id;
uint16_t nb_ports;
unsigned nb_lcores, c_lcore, max_replay_size, nb_ana_cores, nb_cores_per_port;
static struct rte_mempool *packet_pool, *clone_pool, *replay_pool;
static struct rte_ring *clone_ring, *replay_ring, *tx_rings[MAX_PORTS - 1];

//static int rx_queue_per_lcore = 1;

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 4096
static uint16_t nb_rxd = RX_RING_SIZE;
static uint16_t nb_txd = TX_RING_SIZE;
static struct rte_ether_addr ports_eth_addr[MAX_PORTS];

static uint16_t vport_to_devport[MAX_PORTS];
static uint16_t devport_to_vport[MAX_PORTS];

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[BURST_SIZE];
};

struct mbuf_table_light {
	struct rte_mbuf *m_table[BURST_SIZE];
};

struct replay_mbuf_table {
	uint32_t len;
	uint64_t *tsc_counts;
	uint16_t *m_lens;
	struct mbuf_table_light *m_tables;
};

struct __rte_cache_aligned replay_buf {
	uint32_t len;
	uint64_t tsc;
	struct rte_mbuf *bufs[BURST_SIZE];
};

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct __rte_cache_aligned lcore_queue_conf {
	uint64_t tx_tsc;
	uint16_t n_rx_queue;
	uint8_t rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t tx_queue_id[MAX_PORTS];
	struct mbuf_table tx_mbufs[MAX_PORTS];
	uint16_t buf_queue_id[MAX_PORTS];
	struct replay_mbuf_table buf_mbufs[MAX_PORTS];
};
static struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

struct __rte_cache_aligned tlr_struct {
	uint64_t systime_ns;
	uint64_t trailer;
};

struct __rte_cache_aligned pkt_metadata {
	struct tlr_struct tlr;
	struct rte_mbuf *buf;
};

static inline uint64_t
extract_long(uint8_t* ptr)
{
	return ((uint64_t)ptr[0] << 56) |
		   ((uint64_t)ptr[1] << 48) |
		   ((uint64_t)ptr[2] << 40) |
		   ((uint64_t)ptr[3] << 32) |
		   ((uint64_t)ptr[4] << 24) |
		   ((uint64_t)ptr[5] << 16) |
		   ((uint64_t)ptr[6] << 8) |
		   ((uint64_t)ptr[7]);
}

#define TYPE_REPLAY_RECORD (uint8_t)1
#define TYPE_REPLAY_CLEAR (uint8_t)2
#define TYPE_REPLAY_RUN (uint8_t)4
#define IDX_REPLAY_RECORD (uint8_t)0
#define IDX_REPLAY_CLEAR (uint8_t)1
#define IDX_REPLAY_RUN (uint8_t)2
uint8_t *c_to_tx;
uint8_t *tx_to_c;
uint16_t c_ctrs[8];
uint64_t replay_start = 0;
uint64_t replay_end = 0;
uint64_t replay_run_start = 0;

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mtu = MAX_RX_MTU,
	},
	.txmode = {},
};

static void
print_ethaddr(const char *name, struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

// /* Send burst of packets on an output interface */
// static void
// send_burst(
// 	struct lcore_queue_conf *qconf,
// 	const uint16_t outport)
// {
// 	struct rte_mbuf **m_table;
// 	uint16_t len, queueid;
// 	int ret;

// 	queueid = qconf->tx_queue_id[outport];
// 	m_table = (struct rte_mbuf **)qconf->tx_mbufs[outport].m_table;
// 	len = qconf->tx_mbufs[outport].len;

// 	ret = rte_eth_tx_burst(outport, queueid, m_table, len);
// 	while (unlikely (ret < len)) {
// 		rte_pktmbuf_free(m_table[ret]);
// 		ret++;
// 	}

// 	qconf->tx_mbufs[outport].len = 0;
// }

static inline void
send_burst_replayable(
	struct rte_mbuf **bufs,
	const uint64_t systime_ns,
	const uint64_t copy_replay_start,
	const uint64_t copy_replay_end,
	const uint16_t outport,
	const uint16_t queueid,
	const uint16_t nb_rx)
{
	struct replay_buf *rbuf;
	int reti;
	unsigned retu;
	uint16_t nb_tx;
	nb_tx = rte_eth_tx_burst(outport, queueid, bufs, nb_rx);
	if (unlikely(nb_tx < nb_rx)) {
		rte_pktmbuf_free_bulk(&bufs[nb_tx], nb_rx - nb_tx);
		printf("Failed to send all packets, sent %d, total %d\n", nb_tx, nb_rx);
	}

	if (unlikely(systime_ns <= copy_replay_end && systime_ns >= copy_replay_start)) {
		reti = rte_mempool_get(replay_pool, (void **)&rbuf);
		if (unlikely(reti < 0)) {
			printf("Error getting replay buf: %s\n", rte_strerror(-reti));
		}

		retu = rte_ring_enqueue_bulk_start(replay_ring, 1, NULL);
		if (unlikely(retu < 1)) {
			printf("Replay buffer overflow, not storing packets\n");
			rte_pktmbuf_free_bulk(bufs, nb_rx);
			return;
		}
		rbuf->tsc = rte_rdtsc_precise();
		rbuf->len = nb_tx;
		rte_memcpy(rbuf->bufs, bufs, nb_tx * sizeof(struct rte_mbuf *));
		rte_ring_enqueue_finish(replay_ring, (void *)rbuf, 1);
	}
	else {
		// Double free since the refcnt will be at +2
		rte_pktmbuf_free_bulk(bufs, nb_rx);
		rte_pktmbuf_free_bulk(bufs, nb_rx);
	}
}

// /* Send burst of outgoing packet, if timeout expires. */
// static inline void
// send_timeout_burst(struct lcore_queue_conf *qconf, const uint64_t systime_ns)
// {
// 	uint16_t portid;

// 	for (portid = 0; portid < MAX_PORTS; portid++) {
// 		if (qconf->tx_mbufs[portid].len != 0) {
// 			if (portid == vport_to_devport[0]) {
// 				send_burst(qconf, portid);
// 			}
// 			else {
// 				send_burst_replayable(qconf, portid, systime_ns, replay_start, replay_end);
// 			}
// 		}
// 	}
// }

/* Get the output devport of input vport */
static inline uint16_t
get_output_port_from_vport(uint16_t input_port) {
	if (input_port == 1) return vport_to_devport[2];
	return vport_to_devport[1];
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
// static inline void
// crinkle_forward(
// 	struct rte_mbuf *buf,
// 	struct lcore_queue_conf *qconf,
// 	const uint64_t systime_ns,
// 	const uint64_t port,
// 	const uint64_t copy_replay_start,
// 	const uint64_t copy_replay_end)
// {
// 	uint16_t len, outport, pkt_size;
// 	struct pkt_metadata *pkt;
// 	struct tlr_struct uid_trailer = pkt->tlr;
// 	const uint32_t *candidate_trailer_ptr = rte_pktmbuf_mtod_offset(buf, uint32_t*, buf->data_len-4);
// 	uint32_t candidate_trailer = *candidate_trailer_ptr;
// 	uint32_t ts_lower = *(candidate_trailer_ptr-2);
// 	uint8_t *trailer = rte_pktmbuf_mtod_offset(buf, uint8_t*, buf->data_len-16);

// 	// Build trailer
// 	uid_trailer.systime_ns = rte_cpu_to_be_64(systime_ns);
// 	uid_trailer.trailer = rte_cpu_to_be_64((mon_id << 48) | (port << 32) | ((uid_trailer.systime_ns << 16) & 0x00000000FFFF0000) | MONPROT);

// 	// Check for existing UUID trailer
// 	if ((candidate_trailer & 0x0000FFFF) != MONPROT || (candidate_trailer >> 16) != (ts_lower & 0x0000FFFF)) {
// 		if (unlikely((trailer = (uint8_t *)rte_pktmbuf_append(buf, 16)) == NULL)) {
// 			printf("Failed to append trailer to packet");
// 			return;
// 		}
// 		rte_mov16(trailer, (uint8_t *)(&uid_trailer));
// 	}

// 	pkt->buf = buf;
// 	rte_ring_enqueue(clone_ring, &pkt);
	
// 	outport = get_output_port_from_vport(port);
// 	len = qconf->tx_mbufs[outport].len;
// 	qconf->tx_mbufs[outport].m_table[len] = buf;
// 	qconf->tx_mbufs[outport].len = ++len;
// 	rte_pktmbuf_refcnt_update(buf, 2);
// 	if (unlikely(BURST_SIZE == len))
// 		send_burst_replayable(qconf, outport, systime_ns, copy_replay_start, copy_replay_end);
	
// 	// len = qconf->tx_mbufs[vport_to_devport[0]].len;
// 	// qconf->tx_mbufs[vport_to_devport[0]].m_table[len] = cbuf;
// 	// qconf->tx_mbufs[vport_to_devport[0]].len = ++len;
// 	// if (unlikely(BURST_SIZE == len))
// 	//  	send_burst(qconf, vport_to_devport[0]);
// }

static inline void
crinkle_process_burst(
	struct rte_mbuf **bufs,
	struct pkt_metadata **pkts,
	const uint16_t nb_rx,
	const uint64_t systime_ns,
	const uint64_t port)
{
	struct rte_mbuf *buf;
	struct pkt_metadata *pkt;
	uint32_t *cand_tlr_ptr, ts_lower;
	uint16_t i;
	uint8_t *tlr;

	for (i = 0; i < nb_rx; ++i) {
		buf = bufs[i];
		pkt = pkts[i];
		struct tlr_struct uid_trailer = pkt->tlr;
		cand_tlr_ptr = rte_pktmbuf_mtod_offset(buf, uint32_t*, buf->data_len-4);
		ts_lower = *(cand_tlr_ptr - 2);
		uid_trailer.systime_ns = rte_cpu_to_be_64(systime_ns);
		uid_trailer.trailer = rte_cpu_to_be_64((mon_id << 48) | (port << 32) | ((uid_trailer.systime_ns << 16) & 0x00000000FFFF0000) | MONPROT);

		// Check for existing UUID trailer
		if ((*cand_tlr_ptr & 0x0000FFFF) != MONPROT || (*cand_tlr_ptr >> 16) != (ts_lower & 0x0000FFFF)) {
			if (unlikely((tlr = (uint8_t *)rte_pktmbuf_append(buf, 16)) == NULL)) {
				printf("Failed to append trailer to packet");
				return;
			}
			rte_mov16(tlr, (uint8_t *)(&uid_trailer));
		}

		rte_pktmbuf_refcnt_update(buf, 2);
		pkt->buf = buf;
		rte_ring_enqueue(clone_ring, &pkt);
	}
}

static inline void
ana_clone_and_tx(
	struct pkt_metadata **pkts,
	struct rte_mbuf **cbufs,
	const uint16_t outport,
	const uint16_t queue_id) 
{
	struct rte_mbuf *buf, *cbuf;
	struct tlr_struct uid_trailer;
	uint8_t *c;
	unsigned nb_deq, nb_tx;
	uint16_t i, pkt_size;
	nb_deq = rte_ring_dequeue_bulk(clone_ring, (void **)pkts, BURST_SIZE, NULL);

	if (nb_deq > 0) {
		for (i = 0; i < nb_deq; ++i) {
			buf = pkts[i]->buf;
			uid_trailer = pkts[i]->tlr;
			cbuf = cbufs[i];
			if (unlikely ((cbuf = rte_pktmbuf_clone(buf, clone_pool)) == NULL)) {
				return;
			}
			if (unlikely((c = (uint8_t*)rte_pktmbuf_prepend(cbuf, 88)) == NULL)) {
				printf("Failed to prepend clone packet");
				rte_pktmbuf_free(cbuf);
				return;
			}
			pkt_size = rte_cpu_to_be_16(buf->data_len);
			rte_mov64(c, ana_headers);
			rte_mov15_or_less(c+54, (uint8_t *)(&pkt_size), 2);
			rte_mov16(c+56, (uint8_t *)(&uid_trailer));
			rte_mov16(c+72, rte_pktmbuf_mtod_offset(buf, uint8_t*, buf->data_len-16));
		}

		nb_tx = rte_eth_tx_burst(outport, queue_id, cbufs, nb_deq);
		if (unlikely(nb_tx < nb_deq)) {
			rte_pktmbuf_free_bulk(&cbufs[nb_tx], nb_deq - nb_tx);
		}
	}
}

static inline void
run_replay(
	struct lcore_queue_conf *qconf,
	const uint16_t port,
	const uint64_t start_time)
{
	if (unlikely(qconf->buf_mbufs[port].len == 0)) return;
	uint32_t ptr = 0;
	uint32_t i;
	int ret;

	uint64_t tsc_delta = ((start_time - replay_start) / NSEC_PER_SEC) * tsc_hz;
	uint64_t tsc_start = qconf->buf_mbufs[port].tsc_counts[0] + tsc_delta;
	uint64_t curr_tsc;

	while (ptr < qconf->buf_mbufs[port].len) {
		curr_tsc = rte_rdtsc_precise();
		if (tsc_start <= curr_tsc) {
			ret = rte_eth_tx_burst(port, qconf->tx_queue_id[port],
								   qconf->buf_mbufs[port].m_tables[ptr].m_table, qconf->buf_mbufs[port].m_lens[ptr]);
			if (unlikely(ret < qconf->buf_mbufs[port].m_lens[ptr])) {
				rte_pktmbuf_free_bulk(&qconf->buf_mbufs[port].m_tables[ptr].m_table[ret], qconf->buf_mbufs[port].m_lens[ptr] - ret);
				printf("Failed to send all packets, sent %d, total %d\n", ret, qconf->buf_mbufs[port].m_lens[ptr]);
			}
			++ptr;
			//tsc_start += qconf->buf_mbufs[port].tsc_counts[ptr] - qconf->buf_mbufs[port].tsc_counts[ptr-1];
			tsc_start = qconf->buf_mbufs[port].tsc_counts[ptr] + tsc_delta;
		}
	}
	ptr = 0;
	// Does the refcnt update second so that replay can happen immediately
	while (ptr < qconf->buf_mbufs[port].len) {
		for(i = 0; i < qconf->buf_mbufs[port].m_lens[ptr]; ++i) {
			rte_pktmbuf_refcnt_update(qconf->buf_mbufs[port].m_tables[ptr].m_table[i], 1);
		}
		++ptr;
	}
}

static inline void
crinkle_command_handler(
	struct rte_mbuf *buf,
	const uint64_t systime_ns)
{
	uint8_t* cursor = rte_pktmbuf_mtod_offset(buf, uint8_t*, 12);
	unsigned i;
	if (*cursor != 0x86 || *(cursor + 1) != 0xDD) return;
	cursor += 2 + 6;
	if (*cursor != CREASEPROT) return;
	cursor += 2 + 32;

	if (*cursor == TYPE_REPLAY_RECORD) {
		printf("Replay record command received\n");
		replay_start = extract_long(++cursor);
		cursor += 8;
		replay_end = extract_long(cursor);
		printf("Replay record start: %lu, end: %lu\n", replay_start, replay_end);
	}
	else if (*cursor == TYPE_REPLAY_CLEAR) {
		printf("Replay clear command received\n");
		// if c_ctrs is > 0, that means one or more worker threads have not finished
		// handling the last command
		if (unlikely(c_ctrs[IDX_REPLAY_CLEAR] > 0)) return;
		if (unlikely(c_ctrs[IDX_REPLAY_RUN] > 0)) return;
		replay_end = 0;
		for (i = 0; i < nb_lcores; ++i) {
			if (unlikely(i == c_lcore)) continue;
			c_to_tx[i] |= TYPE_REPLAY_CLEAR;
		}
		c_ctrs[IDX_REPLAY_CLEAR] = nb_lcores;
		printf("Clearing replay buffers\n");
	}
	else if (*cursor == TYPE_REPLAY_RUN) {
		printf("Replay run command received\n");
		if (unlikely(replay_end == 0 || systime_ns < replay_end)) return;
		if (unlikely(c_ctrs[IDX_REPLAY_CLEAR] > 0)) return;
		if (unlikely(c_ctrs[IDX_REPLAY_RUN] > 0)) return;
		replay_run_start = extract_long(++cursor);
		for (i = 0; i < nb_lcores; ++i) {
			if (unlikely(i == c_lcore)) continue;
			c_to_tx[i] |= TYPE_REPLAY_RUN;
		}
		c_ctrs[IDX_REPLAY_RUN] = nb_lcores;
		printf("Replay run start: %lu\n", replay_run_start);
	}
}

static int
ana_main(
	void *arg) 
{
	struct pkt_metadata *pkts[BURST_SIZE];
	struct rte_mbuf *cbufs[BURST_SIZE];
	const uint16_t queue_id = (uint16_t)(*(uint32_t *)arg & 0xFFFF);
	const uint16_t outport = get_output_port_from_vport(0);
	ana_clone_and_tx(pkts, cbufs, outport, queue_id);
	return 0;
}

static int
crinkle_rx(
	void *arg)
{
	struct rte_mbuf *bufs[BURST_SIZE];
	struct pkt_metadata *pkts[BURST_SIZE];
	struct timespec ts;
	uint64_t systime_ns;
	int nb_rx;
	const uint16_t port_id = (uint16_t)(*(uint32_t *)arg >> 16);
	const uint16_t queue_id = (uint16_t)(*(uint32_t *)arg & 0xFFFF);
	const uint16_t vport = devport_to_vport[port_id];
	const uint16_t outport = get_output_port_from_vport(vport);
	//struct rte_ring *tx_ring = tx_rings[vport - 1];
	while (1) {
		nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);
		// ret = rte_ring_enqueue_bulk(tx_ring, bufs, nb_rx, NULL);
		// if (unlikely(ret < nb_rx)) {
		// 	rte_pktmbuf_free_bulk(&bufs[ret], nb_rx - ret);
		// 	printf("TX ring for port %hu full, dropped %d packets\n", vport, nb_rx - ret);
		// }
		if (nb_rx > 0) {
			clock_gettime(CLOCK_REALTIME, &ts);
			systime_ns = timespec64_to_ns(&ts);
			crinkle_process_burst(bufs, pkts, nb_rx, systime_ns, port_id);
			send_burst_replayable(bufs, systime_ns, replay_start, replay_end,
								  outport, queue_id, nb_rx);
		}
	}
	return -1;
}

// static int
// crinkle_tx(
// 	const uint16_t port_id,
// 	const uint16_t queue_id) 
// {
// 	return 0;
// }

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
// static int
// lcore_main(__rte_unused void *dummy)
// {
// 	struct rte_mbuf *bufs[BURST_SIZE];
// 	unsigned lcore_id, k;
// 	int i, j, nb_rx;
// 	uint16_t portid;
// 	struct lcore_queue_conf *qconf;

// 	lcore_id = rte_lcore_id();
// 	qconf = &lcore_queue_conf[lcore_id];

// 	if (qconf->n_rx_queue == 0) {
// 		printf("lcore %u has nothing to do\n",lcore_id);
// 		return 0;
// 	}

// 	/* Main work of application loop. 8< */
// 	struct timespec systime;
// 	uint64_t systime_ns;
// 	uint64_t last_burst_ns = 0;

// 	for (i = 0; i < qconf->n_rx_queue; ++i) {
// 		portid = qconf->rx_queue_list[i];
// 		printf(" -- lcoreid=%u portid=%d\n", lcore_id, portid);
// 	}

// 	uint32_t ctr_max = 10000000;

// 	while (1) {
// 		nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);
		
// 		for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; ++j) {
// 			rte_prefetch0(rte_pktmbuf_mtod(bufs[j], void *));
// 		}

// 		for (j = 0; j < (nb_rx - PREFETCH_OFFSET); ++j) {
// 			rte_prefetch0(rte_pktmbuf_mtod(bufs[j + PREFETCH_OFFSET], void *));
// 			crinkle_forward(bufs[j], qconf, systime_ns++, devport_to_vport[portid],
// 							replay_start, replay_end);
// 		}

// 		/* Forward remaining prefetched packets */
// 		for (; j < nb_rx; ++j) {
// 			crinkle_forward(bufs[j], qconf, systime_ns++, devport_to_vport[portid],
// 							replay_start, replay_end);
// 		}

// 		/* Send out packets from TX queues */
// 		if (unlikely(systime_ns - last_burst_ns >= BURST_TX_DRAIN_US*1000)) {
// 			send_timeout_burst(qconf, systime_ns);
// 			last_burst_ns = systime_ns;
// 		}

// 		if (c_to_tx[lcore_id] & TYPE_REPLAY_CLEAR) {
// 			for (i = 0; i < nb_ports; ++i) {
// 				if (qconf->buf_mbufs[i].len == 0) continue;
// 				for (k = 0; k < qconf->buf_mbufs[i].len; ++k) {
// 					// double free since the refcnt will be at +2
// 					rte_pktmbuf_free_bulk(qconf->buf_mbufs[i].m_tables[k].m_table, qconf->buf_mbufs[i].m_lens[k]);
// 					rte_pktmbuf_free_bulk(qconf->buf_mbufs[i].m_tables[k].m_table, qconf->buf_mbufs[i].m_lens[k]);
// 					qconf->buf_mbufs[i].m_lens[k] = 0;
// 				}
// 				qconf->buf_mbufs[i].len = 0;
// 			}
// 			tx_to_c[lcore_id] |= TYPE_REPLAY_CLEAR;
// 			c_to_tx[lcore_id] &= ~TYPE_REPLAY_CLEAR;
// 		}
// 		else if (c_to_tx[lcore_id] & TYPE_REPLAY_RUN) {
// 			run_replay(qconf, get_output_port_from_vport(devport_to_vport[portid]), replay_run_start);
// 			tx_to_c[lcore_id] |= TYPE_REPLAY_RUN;
// 			c_to_tx[lcore_id] &= ~TYPE_REPLAY_RUN;
// 		}
// 	}
// 	/* >8 End of loop. */
// }
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
	nb_ports = rte_eth_dev_count_avail();
	
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
	uint16_t vport, devport;
	int parsed = 0;

	while ((arg = getopt(argc, argv, "n:d:m:i:r:hv")) != -1) {
		switch (arg) {
			case 'n':
				mon_id = strtol(optarg, NULL, 0);
				set_mon_id = true;
				break;
			case 'd':
				// [dpdk virtual port]@[device number as parsed into dpdk]
				sscanf(optarg, "%hu@%hu", &vport, &devport);
				vport_to_devport[vport] = devport;
				devport_to_vport[devport] = vport;
				break;
			case 'm':
				// MAC addresses, source then dest
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
			case 'r':
				sscanf(optarg, "%u", &max_replay_size);
				break;
			case 'h':
				printf("Available options:\n");
				printf("  -n    Set monitor ID\n");
				printf("  -d    Set virtual-actual device mappings, as [virtual]@[actual], actual as parsed by dpdk\n");
				printf("  -m    Set MAC addresses for analyzer (source then dest)\n");
				printf("  -i    Set IP addresses for analyzer (source then dest)\n");
				printf("  -r    Set maximum replay size, default %u\n", MIN_REPLAY_SIZE);
				printf("  -h    Print this help\n");
				printf("  -v    Print version\n");
				exit(EXIT_SUCCESS);
			case 'v':
				printf(CREASEVER);
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
	if (max_replay_size < MIN_REPLAY_SIZE) max_replay_size = MIN_REPLAY_SIZE;

	printf(CREASEVER);
	printf("Monitor ID: %lu\n", mon_id);
	printf("Virtual port to device port mapping:\n");
	for (uint16_t i = 0; i < nb_ports; ++i) {
		printf("  Virtual port %hu -> Device port %hu\n", i, vport_to_devport[i]);
	}
	printf("Maximum replay size: %u\n", max_replay_size);

	packet_pool = rte_pktmbuf_pool_create("packet_pool", (max_replay_size+256)*BURST_SIZE, MBUF_CACHE_SIZE,
		0, PKT_MBUF_DATA_SIZE, rte_socket_id());

	if (packet_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init packet mbuf pool: %s\n", rte_strerror(rte_errno));

	clone_pool = rte_pktmbuf_pool_create("clone_pool", NUM_MBUFS , MBUF_CACHE_SIZE,
		0, 0, rte_socket_id());

	if (clone_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init clone mbuf pool: %s\n", rte_strerror(rte_errno));

	replay_pool = rte_mempool_create("replay_pool", max_replay_size, sizeof(struct replay_buf),
		RTE_MEMPOOL_CACHE_MAX_SIZE, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
	
	if (replay_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init replay mbuf pool: %s\n", rte_strerror(rte_errno));

	clone_ring = rte_ring_create("clone_ring", NUM_MBUFS, rte_socket_id(), RING_F_MP_RTS_ENQ | RING_F_MC_RTS_DEQ);

	if (clone_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create clone ring: %s\n", rte_strerror(rte_errno));

	replay_ring = rte_ring_create("replay_ring", max_replay_size, rte_socket_id(), RING_F_MP_HTS_ENQ | RING_F_MC_HTS_DEQ);

	if (replay_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create replay ring: %s\n", rte_strerror(rte_errno));

	// for (uint16_t i = 0; i < nb_ports - 1; ++i) {
	// 	char ring_name[32];
	// 	snprintf(ring_name, 32, "tx_ring_%d", i);
	// 	tx_rings[i] = rte_ring_create(ring_name, NUM_MBUFS, rte_socket_id(), RING_F_MP_HTS_ENQ | RING_F_MC_HTS_DEQ);
	// 	if (tx_rings[i] == NULL)
	// 		rte_exit(EXIT_FAILURE, "Cannot create tx ring %d: %s\n", i, rte_strerror(rte_errno));
	// }

	nb_lcores = rte_lcore_count();
	nb_ana_cores = 1;
	nb_cores_per_port = (nb_lcores - 1 - nb_ana_cores) / (nb_ports - 1);
	if (nb_cores_per_port == 0) {
		rte_exit(EXIT_FAILURE, "Not enough cores, need at least %u\n", (nb_ports - 1 + nb_ana_cores + 1));
	}
	c_to_tx = rte_malloc("uint8_t", (nb_lcores - 1)*sizeof(uint8_t), 0);
	tx_to_c = rte_malloc("uint8_t", (nb_lcores - 1)*sizeof(uint8_t), 0);
	uint16_t portid;
	unsigned lcore_id = 0, rx_lcore_id = 0;
	struct lcore_queue_conf *qconf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	uint16_t queueid;

	/*
	 * Master core handles command handling
	 * ana cores handle sending to analyzer
	 * other cores handle other ports
	 * Master core, for now, solely receives commands and instructs others
	 * Ana core solely handles transmission out of port to analyzer
	 * Other cores receive traffic, add trailer, create clone
	 * they write the clone to a ring the ana cores consume from
	 * Setup must configure ports and then rings.
	 */

	

	/* Initialize ana port */
	if (1) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		portid = vport_to_devport[0];

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, rte_strerror(-ret));

		local_port_conf.rxmode.mtu = RTE_MIN(
			dev_info.max_mtu,
			local_port_conf.rxmode.mtu);

		c_lcore = 0;
		printf("Initializing port %d on lcore %u... ", portid,
			rx_lcore_id);
		fflush(stdout);

		ret = rte_eth_dev_configure(portid, 1, nb_ana_cores,
					&local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%s, port=%d\n",
				 rte_strerror(-ret), portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%s, port=%d\n",
				 rte_strerror(-ret), portid);

		ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot get MAC address: err=%s, port=%d\n",
				 rte_strerror(-ret), portid);

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
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%s, port=%d\n",
				  rte_strerror(-ret), portid);
		rx_lcore_id++;
		
		for (lcore_id = 1; lcore_id < nb_ana_cores + 1; ++lcore_id) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;
			printf("txq=%u,%hu ", lcore_id, queueid);
			fflush(stdout);

			txconf = &dev_info.default_txconf;
			//printf("txconf offloads: 0x%" PRIx64 "\n", txconf->offloads);
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
						     rte_lcore_to_socket_id(lcore_id), txconf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%s, "
					  "port=%d\n", rte_strerror(-ret), portid);
			queueid++;
			rx_lcore_id++;
		}
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n",
				  ret, portid);

		printf("done:\n");
	}

	/* Initializing all ports. 8< */
	for (uint16_t vport = 1; vport < nb_ports; ++vport) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		portid = vport_to_devport[vport];

		/* limit the frame size to the maximum supported by NIC */
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, rte_strerror(-ret));

		local_port_conf.rxmode.mtu = RTE_MIN(
		    dev_info.max_mtu,
		    local_port_conf.rxmode.mtu);
			
		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0) {

			rx_lcore_id ++;

			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}
		printf("Initializing port %d on lcore %u... ", portid,
			rx_lcore_id);
		fflush(stdout);
		ret = rte_eth_dev_configure(portid, 1, nb_cores_per_port,
					&local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n",
					ret, portid);

		/* init port */

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
		const unsigned lcore_max = (1 + nb_ana_cores + (nb_cores_per_port * vport));
		for(; lcore_id < lcore_max; ++lcore_id) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;
			printf("txq=%u,%hu ", lcore_id, queueid);
			fflush(stdout);

			txconf = &dev_info.default_txconf;
			//printf("txconf offloads: 0x%" PRIx64 "\n", txconf->offloads);
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
						     rte_lcore_to_socket_id(lcore_id), txconf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%s, "
					  "port=%d\n", rte_strerror(-ret), portid);
			queueid++;
			rx_lcore_id++;
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

	uint32_t args[nb_lcores - 1];
	for (lcore_id = 1; lcore_id <= nb_ana_cores; ++lcore_id) {
		args[lcore_id - 1] = lcore_id - 1;
		rte_eal_remote_launch((lcore_function_t *)ana_main, (void *)&args[lcore_id - 1], lcore_id);
	}
	for (uint16_t vport = 1; vport < nb_ports; ++vport) {
		portid = vport_to_devport[vport];
		const unsigned lcore_max = (1 + nb_ana_cores + (nb_cores_per_port * vport));
		uint16_t queueid = 0;
		for(; lcore_id < lcore_max; ++lcore_id) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;
			args[lcore_id - 1] = (portid << 16) | queueid++;
			rte_eal_remote_launch((lcore_function_t *)crinkle_rx, (void *)&args[lcore_id - 1], lcore_id);
		}
	}

	struct rte_mbuf *bufs[BURST_SIZE];
	struct timespec systime;
	uint64_t systime_ns;
	unsigned k;
	int i, nb_rx;
	lcore_id = c_lcore;
	qconf = &lcore_queue_conf[lcore_id];

	while (1) {
		clock_gettime(CLOCK_REALTIME, &systime);
		systime_ns = timespec64_to_ns(&systime);
		portid = qconf->rx_queue_list[0];
		
		nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

		for (i = 0; i < nb_rx; ++i) {
			crinkle_command_handler(bufs[i], systime_ns);
		}

		for (k = 0; k < (nb_lcores - 1); ++k) {
			if (tx_to_c[k] & TYPE_REPLAY_CLEAR) {
				--c_ctrs[IDX_REPLAY_CLEAR];
				tx_to_c[k] &= ~TYPE_REPLAY_CLEAR;
			}
			if (tx_to_c[k] & TYPE_REPLAY_RUN) {
				--c_ctrs[IDX_REPLAY_RUN];
				tx_to_c[k] &= ~TYPE_REPLAY_RUN;
			}
		}
	}
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

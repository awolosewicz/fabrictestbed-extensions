/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<8> PROT_TCP = 6;
const bit<8> PROT_UDP = 17;
#define GTPU_PORT 2152

const bit<32> INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> INSTANCE_TYPE_EGRESS_CLONE = 2;
const bit<32> CLONE_SESSION_ID = 5;
const bit<32> MAX_PAYLOAD = 9216;

#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == INSTANCE_TYPE_INGRESS_CLONE)
#define IS_E2E_CLONE(std_meta) (std_meta.instance_type == INSTANCE_TYPE_EGRESS_CLONE)

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;
typedef bit<16> protport_t;
typedef bit<32> TEID;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    macAddr_t dst;
    macAddr_t src;
    bit<16>   etype;
}

header ipv4_t {
    bit<4>    ver;
    bit<4>    ihl;
    bit<8>    dsv;
    bit<16>   len;
    bit<16>   id;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    prot;
    bit<16>   chksum;
    ip4Addr_t src;
    ip4Addr_t dst;
}

header ipv6_t{
   bit<4>     ver;
   bit<8>     class;
   bit<20>    flow;
   bit<16>    len;
   bit<8>     next;
   bit<8>     hoplmt;
   ip6Addr_t  src;
   ip6Addr_t  dst;
}

header size_t {
    bit<8> next;
    bit<8> len;
    bit<48> size;
    bit<128> uid;
}

header etherip_t {
    bit<4> ver;
    bit<12> res;
}

header tcp_t {
    protport_t src;
    protport_t dst;
    bit<32> seq;
    bit<32> ack;
    bit<4> offset;
    bit<4> reserved;
    bit<8> flags;
    bit<16> window;
    bit<16> chksum;
    bit<16> urg;
}

header udp_t {
    protport_t src;
    protport_t dst;
    bit<16> len;
    bit<16> chksum;
}

header pld_t {
    varbit<(MAX_PAYLOAD*8)> pld;
}

header uid_t {
    bit<128> uid;
}

struct metadata {
    @field_list(1)
    bit<9> ingress_port;
    @field_list(1)
    bit<9> egress_port;
}

struct headers {
    ethernet_t   o_eth;
    ipv6_t       o_ipv6;
    size_t       size;
    etherip_t    ethip;
    ethernet_t   eth;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
    tcp_t        tcp;
    udp_t        udp;
    pld_t        pld;
    uid_t        uid;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.eth);
        transition select(hdr.eth.etype) {
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_pld_ipv4;
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition parse_pld_ipv6;
    }

    state parse_pld_ipv4 {
        packet.extract(hdr.pld, ((bit<32>) hdr.ipv4.len - ((bit<32>) hdr.ipv4.ihl) * 4) * 8);
        transition select(standard_metadata.packet_length - ((bit<32>) hdr.ipv4.len + ((bit<32>) hdr.ipv4.ihl - 5) * 4 + 14)) {
            0: accept;
            default: parse_uid;
        }
    }

    state parse_pld_ipv6 {
        packet.extract(hdr.pld, ((bit<32>) hdr.ipv6.len) * 8);
        transition select(standard_metadata.packet_length - ((bit<32>) hdr.ipv6.len + 14 + 40)) {
            0: accept;
            default: parse_uid;
        }
    }

    state parse_uid {
        packet.extract(hdr.uid);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {

    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1) r_monitor_id;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action l2_bridge(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action strip_uid() {
        hdr.uid.setInvalid();
    }

    table table_l2_bridge {
        key = {
            standard_metadata.ingress_port:exact;
        }
        actions = {
            l2_bridge;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table table_do_uid {
        key = {
            standard_metadata.egress_spec:exact;
        }
        actions = {
            strip_uid;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (table_l2_bridge.apply().miss) {
            return;
        }
        meta.ingress_port = standard_metadata.ingress_port;
        if (table_do_uid.apply().miss && !hdr.uid.isValid()) {
            hdr.uid.setValid();
            bit<32> monitor_id;
            r_monitor_id.read(monitor_id, 0);
            bit<128> uid_front = (7950 << 112); //0x1F0E
            hdr.uid.uid = uid_front + ((bit<128>) monitor_id << 100) + (((bit<128>) standard_metadata.ingress_port) << 96) + (bit<128>) standard_metadata.ingress_global_timestamp;
        }
        //clone(CloneType.I2E, CLONE_SESSION_ID);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<macAddr_t>(2) macs;
    register<ip6Addr_t>(2) ip1;
    register<ip6Addr_t>(2) ip2;
    register<egressSpec_t>(1) swport;
    register<bit<32>>(1) trunc;
    register<bit<32>>(1) r_monitor_id2;
    register<bit<32>>(4) debug;

    apply {
        if (IS_E2E_CLONE(standard_metadata)) {
            bit<32> old_len = standard_metadata.packet_length;
            bit<32> trunc_len;
            trunc.read(trunc_len, 0);
            trunc_len = trunc_len + 14 + 40 + 8 + 2 + 16;

            hdr.o_eth.setValid();
            macs.read(hdr.o_eth.dst, 1);
            macs.read(hdr.o_eth.src, 0);
            hdr.o_eth.etype = TYPE_IPV6;

            hdr.o_ipv6.setValid();
            hdr.o_ipv6.ver = 6;
            hdr.o_ipv6.class = 12;
            hdr.o_ipv6.len = ((bit<16>) trunc_len - 14 - 40);
            hdr.o_ipv6.next = 60;
            hdr.o_ipv6.hoplmt = 64;
            ip6Addr_t ip1src;
            ip6Addr_t ip1dst;
            ip6Addr_t ip2src;
            ip6Addr_t ip2dst;
            ip1.read(ip1src, 0);
            ip1.read(ip1dst, 1);
            ip2.read(ip2src, 0);
            ip2.read(ip2dst, 1);
            hdr.o_ipv6.src = (ip1src << 64) + ip2src;
            hdr.o_ipv6.dst = (ip1dst << 64) + ip2dst;

            hdr.size.setValid();
            hdr.size.next = 97;
            hdr.size.len = 2;
            bit<32> monitor_id;
            r_monitor_id2.read(monitor_id, 0);
            hdr.size.size = ((bit<48>) 7684 << 32) + ((bit<48>) monitor_id << 20) + (((bit<48>) meta.ingress_port) << 16) + ((bit<48>) old_len); //0x1E04
            hdr.size.uid = hdr.uid.uid;

            hdr.ethip.setValid();
            hdr.ethip.ver = 3;
            hdr.ethip.res = 0;
            truncate(trunc_len);

            hdr.uid.setInvalid();

            swport.read(standard_metadata.egress_spec, 0);
            return;
        }
        clone_preserving_field_list(CloneType.E2E, CLONE_SESSION_ID, 1);
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {  
        
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.o_eth);
        packet.emit(hdr.o_ipv6);
        packet.emit(hdr.size);
        packet.emit(hdr.ethip);
        packet.emit(hdr.eth);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.pld);
        packet.emit(hdr.uid);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

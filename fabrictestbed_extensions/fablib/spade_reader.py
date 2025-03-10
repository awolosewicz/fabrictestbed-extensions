import enum
from ipaddress import IPv4Address, IPv6Address

from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt
from scapy.packet import Packet, Raw, bind_layers
from scapy.fields import ShortField


ETH_INNER_IDX = 4
IP_INNER_IDX = 5

if __name__ == "__main__":

    class EtherIP(Packet):
        name = "EtherIP"
        fields_desc = [ ShortField("ver", 12288)]

    class PktLayers(enum.IntEnum):
        ETHER_O = 0
        IPv6_O = 1
        IPV6_O_EXT = 2
        ETHIP = 3
        ETHER_I = 4
        IP_I = 5
        PROT_I = 6

    class Flow:
        def __init__(self, txport, rxport, ip_src, ip_dst, ip_prot, prot_sport, prot_dport):
            self.txport = txport
            self.rxport = rxport
            self.ip_src = ip_src
            self.ip_dst = ip_dst
            self.ip_prot = ip_prot
            self.prot_sport = prot_sport
            self.prot_dport = prot_dport

        def __hash__(self):
            return hash((self.txport, self.rxport, self.ip_src, self.ip_dst, self.ip_prot,
                        self.prot_sport, self.prot_dport))
        
        def __eq__(self, other):
            return (self.txport, self.rxport, self.ip_src, self.ip_dst, self.ip_prot,
                        self.prot_sport, self.prot_dport) == (other.txport, other.rxport, other.ip_src, other.ip_dst, other.ip_prot,
                                                              other.prot_sport, other.prot_dport)

    bind_layers(IPv6, EtherIP, nh=97)
    bind_layers(IPv6ExtHdrDestOpt, EtherIP, nh=97)
    bind_layers(EtherIP, Ether)
    flowptr = 0
    flows = {}
    
    with open("spade_pipe", 'a') as pipe:
        print(f'Writing initial spade vertices')
        pipe.write('type:Agent id:h11\n')
        pipe.write('type:Process id:h11p0\n')
        pipe.write('type:WasControlledBy from:h11p0 to:h11\n')
        pipe.write('type:Agent id:h12\n')
        pipe.write('type:Process id:h12p0\n')
        pipe.write('type:WasControlledBy from:h12p0 to:h12\n')
        pipe.write('type:Agent id:s11\n')
        pipe.write('type:Process id:s11p0\n')
        pipe.write('type:WasControlledBy from:s11p0 to:s11\n')
        pipe.write('type:Process id:s11p1\n')
        pipe.write('type:WasControlledBy from:s11p1 to:s11\n')


    def analyze_packet(pkt: Packet):
        global flowptr
        global flows
        print('Packet detected!')
        size = None
        monitor_id = None
        monitor_iface_id = None
        uid = None
        eth_src = None
        eth_dst = None
        eth_type = None
        ip_ver = None
        ip_src = None
        ip_dst = None
        ip_prot = None
        prot_sport = None
        prot_dport = None
        time = None

        monitors = {
            0: {
                1: ('h11p0', 's11p0'),
                2: ('s11p0', 'h11p0'),
            },
            1: {
                1: ('h12p0', 's11p1'),
                2: ('s11p1', 'h12p0'),
            }
        }

        if IPv6ExtHdrDestOpt in pkt:
            base = pkt['IPv6ExtHdrDestOpt']
            print('Packet is from monitor')
            for option in base.options:
                if option.otype == 30:
                    data = option.optdata.hex()
                    print(f'Option 1 data: {data}')
                    monitor_id = int(data[0:3], 16)
                    monitor_iface_id = int(data[3], 16)
                    size = int(data[4:9], 16)
                    print(f'monitor id {monitor_id}, monitor iface {monitor_iface_id}, size {size}')
                if option.otype == 31:
                    uid_b = option.optdata.hex()
                    uid = ('1f0e'+uid_b).upper()
                    print(f'uid: {uid}')
            if uid is None:
                return
            print(f'Parsing inner Ether')
            h_eth = base['Ether']
            eth_src = h_eth.src
            eth_dst = h_eth.dst
            eth_type = hex(h_eth.type)
            h_ip = None
            print(f'Parsing inner IP')
            if IP in base:
                print(f'Found IP version 4')
                h_ip = base['IP']
                ip_src = IPv4Address(h_ip.src)
                ip_dst = IPv4Address(h_ip.dst)
                ip_prot = h_ip.proto
            elif IPv6 in base:
                print(f'Found IP version 6')
                h_ip = base['IPv6']
                ip_src = IPv6Address(h_ip.src)
                ip_dst = IPv6Address(h_ip.dst)
                ip_prot = h_ip.nh
            print(f'tx {monitor_id}p{monitor_iface_id}')
            tx_port = monitors[monitor_id][monitor_iface_id][0]
            rx_port = monitors[monitor_id][monitor_iface_id][1]
            thisflow = Flow(tx_port, rx_port, ip_src, ip_dst, ip_prot, prot_sport, prot_dport)
            flowhash = hash(thisflow)
            fid = None
            if flowhash in flows:
                fid = flows[flowhash]
                print(f'Previous flow {fid}')
            else:
                fid = flowptr
                flowptr += 1
                flows[flowhash] = fid
                print(f'New flow {fid}')
                with open("spade_pipe", 'a') as pipe:
                    pipe.write(f'type:Artifact id:{fid} eth.type:{eth_type} ip.src:{ip_src} ip.dst:{ip_dst} ip.prot:{ip_prot} prot.sport:{prot_sport} prot.dport:{prot_dport}\n')
            print('Writing spade edges')
            with open("spade_pipe", 'a') as pipe:
                pipe.write(f'type:Used from:{rx_port} to:{fid} pkt_id:{uid} size:{size}\n')
                pipe.write(f'type:WasGeneratedBy from:{fid} to:{tx_port} pkt_id:{uid} size:{size}\n')

    sniff(prn=analyze_packet, iface="enp7s0")
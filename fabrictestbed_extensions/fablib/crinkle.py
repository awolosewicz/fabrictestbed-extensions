from __future__ import annotations

import ipaddress
import json
import logging
import enum
import shutil
import time
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fabric_cf.orchestrator.swagger_client import (
        Slice as OrchestratorSlice,
        Sliver as OrchestratorSliver,
    )
    from fabrictestbed_extensions.fablib.fablib import FablibManager

from concurrent import futures
from ipaddress import IPv6Address, ip_address
from fabrictestbed.slice_editor import Node as FimNode

from fabrictestbed.slice_editor import ExperimentTopology
from fabrictestbed_extensions.fablib.interface import Interface
from fabrictestbed_extensions.fablib.network_service import NetworkService
from fabrictestbed_extensions.fablib.node import Node
from fabrictestbed_extensions.fablib.slice import Slice

CAPERSTART = "./caper/caper.byte -q -p -e"
PCAPDIR = "/home/ubuntu/pcaps/"
LOCALP4DIR = "."
REMOTEWORKDIR = ".crinkle"

TCPDUMP_IMAGES = ["default_ubuntu_20",
                  "default_ubuntu_22",
                  "default_ubuntu_24",
                  "attestable_bmv2_v2_ubuntu_20",
                  "docker_ubuntu_20",
                  "docker_ubuntu_22"]

class MonNetData(enum.IntEnum):
    NODENAME = 0
    IFACENAME = 1
    MIFACENAME = 2
    ISSINK = 3
    PORTNUM = 4

class CrinkleAnalyzer(Node):
    default_image = "default_ubuntu_22"

    def __init__(
        self,
        slice: Slice,
        node: FimNode,
        validate: bool = False,
        raise_exception: bool = False,
    ):
        super().__init__(slice=slice, node=node, validate=validate, raise_exception=raise_exception)

    @staticmethod
    def new_node(
        slice: Slice = None,
        name: str = None,
        site: str = None,
        avoid: list[str] = [],
        validate: bool = False,
        raise_exception: bool = False,
    ):
        """
        Not intended for API call.  See: CrinkleSlice.add_monitor()

        Creates a new Crinkle analyzer FABRIC node and returns a fablib node with the
        new node.

        :param slice: the fablib slice to build the new node on
        :type slice: Slice

        :param name: the name of the new node
        :type name: str

        :param site: the name of the site to build the node on
        :type site: str

        :param avoid: a list of node names to avoid
        :type avoid: List[str]

        :param validate: Validate node can be allocated w.r.t available resources
        :type validate: bool

        :param raise_exception: Raise exception in case of failure
        :type raise_exception: bool

        :return: a new fablib node
        :rtype: CrinkleAnalyzer
        """
        if site is None:
            [site] = slice.get_fablib_manager().get_random_sites(avoid=avoid)
        
        logging.info(f"Adding Crinkle Analyzer {name}, slice: {slice.get_name()}, site: {site}")

        analyzer = CrinkleAnalyzer(
            slice,
            slice.topology.add_node(name=name, site=site),
            validate=validate,
            raise_exception=raise_exception
        )

        analyzer.set_capacities(
            cores=CrinkleAnalyzer.default_cores,
            ram=CrinkleAnalyzer.default_ram,
            disk=CrinkleAnalyzer.default_disk
        )

        analyzer.set_image(CrinkleAnalyzer.default_image)

        analyzer.init_fablib_data()

        return analyzer
    
    @staticmethod
    def get_node(slice: Slice = None, node=None):
        """
        Returns a new Crinkle monitor node using existing FABRIC resources.

        :note: Not intended for API call.

        :param slice: the fablib slice storing the existing node
        :type slice: Slice

        :param node: the FIM node stored in this fablib node
        :type node: Node

        :return: a new fablib node storing resources
        :rtype: CrinkleMonitor
        """
        return CrinkleAnalyzer(slice, node)
    
class CrinkleMonitor(Node):

    default_image = "default_ubuntu_22"
    default_cores = 2
    default_ram = 2
    default_disk = 10

    class MonitorData():
        def __init__(
            self,
            port_nums: int = 0,
            port_sequence: str = "",
            net_name: str = None,
            net_type: str = None,
            cnet_iface: Interface = None,
            iface_mappings: dict[Interface, tuple[str, Interface, bool, int]] = {},
            monitor_id: int = None
        ):
            self.port_nums = port_nums
            self.port_sequence = port_sequence
            self.net_name = net_name
            self.net_type = net_type
            self.cnet_iface = cnet_iface
            self.iface_mappings = iface_mappings
            self.monitor_id = monitor_id

    def __init__(
        self,
        slice: Slice,
        node: FimNode,
        validate: bool = False,
        raise_exception: bool = False,
    ):
        super().__init__(slice=slice, node=node, validate=validate, raise_exception=raise_exception)
        self.get_monitor_data()
        self.creation_data: list[tuple[str, str, str, bool, int]] = [] # see MonNetData

    @staticmethod
    def new_node(
        slice: Slice = None,
        name: str = None,
        site: str = None,
        avoid: list[str] = [],
        validate: bool = False,
        raise_exception: bool = False,
    ):
        """
        Not intended for API call.  See: CrinkleSlice.add_monitor()

        Creates a new Crinkle monitor FABRIC node and returns a fablib node with the
        new node.

        :param slice: the fablib slice to build the new node on
        :type slice: Slice

        :param name: the name of the new node
        :type name: str

        :param site: the name of the site to build the node on
        :type site: str

        :return: a new fablib node
        :rtype: CrinkleMonitor
        """
        logging.info(f"Adding Crinkle Monitor {name}, slice: {slice.get_name()}, site: {site}")
        
        monitor = CrinkleMonitor(
            slice,
            slice.topology.add_node(name=name, site=site),
            validate=True,
            raise_exception=True
        )

        monitor.set_capacities(
            cores=CrinkleMonitor.default_cores,
            ram=CrinkleMonitor.default_ram,
            disk=CrinkleMonitor.default_disk
        )

        monitor.set_image(CrinkleMonitor.default_image)

        monitor.init_fablib_data()

        return monitor
    
    @staticmethod
    def get_node(slice: Slice = None, node=None):
        """
        Returns a new Crinkle monitor node using existing FABRIC resources.

        :note: Not intended for API call.

        :param slice: the fablib slice storing the existing node
        :type slice: Slice

        :param node: the FIM node stored in this fablib node
        :type node: Node

        :return: a new fablib node storing resources
        :rtype: CrinkleMonitor
        """
        return CrinkleMonitor(slice, node)
    
    def get_monitor_data(self):
        """
        Get monitor-specific data.
        """
        logging.info(f"{self.get_name()} get_monitor_data()")
        if "monitor_config" in self.get_user_data():
            data = self.get_user_data()["monitor_config"]
            #data_iface_mappings = self.get_user_data()["iface_mappings"]
            #logging.info(f"Retrieved monitor iface mappings as: {data_iface_mappings}")
            iface_mappings = {}
            for node_iface, (node_name, monitor_iface, is_sink, port_num) in data["iface_mappings"].items():
                iface_mappings[self.slice.get_interface(name=node_iface)] = (
                    node_name, self.slice.get_interface(name=monitor_iface), is_sink, port_num
                )
            self.data = self.MonitorData(
                port_nums=data["port_nums"],
                port_sequence=data["port_sequence"],
                net_name=data["net_name"],
                net_type=data["net_type"],
                cnet_iface=self.slice.get_interface(data["cnet_iface"]),
                monitor_id=data["monitor_id"],
                iface_mappings=iface_mappings
            )
            logging.info(f"Retrieved monitor config as: {self.data.__dict__}")
        else:
            self.data = self.MonitorData()
            logging.info(f"Did not retrieve stored monitor data, initializing")
        
    def set_monitor_data(self):
        """
        Set monitor-specific data.
        """
        logging.info(f"{self.get_name()} set_monitor_data()")
        user_data = self.get_user_data()
        iface_mappings = {}
        for node_iface, (node_name, monitor_iface, is_sink, port_num) in self.data.iface_mappings.items():
            iface_mappings[node_iface.get_name()] = (
                node_name, monitor_iface.get_name(), is_sink, port_num
            )
        data_dict = {
            "port_nums": self.data.port_nums,
            "port_sequence": self.data.port_sequence,
            "net_name": self.data.net_name,
            "net_type": self.data.net_type,
            "cnet_iface": self.data.cnet_iface.get_name(),
            "monitor_id": self.data.monitor_id,
            "iface_mappings": iface_mappings
        }
        logging.info(f"Writing monitor config to user data: {data_dict}")
        user_data["monitor_config"] = data_dict
        #logging.info(f"Writing monitor iface mappings to user data: {iface_mappings}")
        #user_data["iface_mappings"] = iface_mappings
        self.set_user_data(user_data=user_data)
    
class CrinkleSlice(Slice):
    def __init__(
            self,
            fablib_manager: FablibManager,
            name: str = None,
            user_only: bool = True,
            pcaps_dir: str = None,
            name_prefix: str = None,
            analyzer_name: str = None
    ):
        super().__init__(fablib_manager=fablib_manager, name=name, user_only=user_only)
        self.monitors: dict[str, CrinkleMonitor] = {}
        self.analyzer: CrinkleAnalyzer = None
        self.analyzer_name: str = analyzer_name
        self.cnets: dict[str, NetworkService] = {}
        self.analyzer_cnet: NetworkService = None
        self.analyzer_iface: Interface = None
        self.pcaps_dir = pcaps_dir
        self.prefix = name_prefix
        self.monitor_count = 0

    @staticmethod
    def new_slice(
            fablib_manager: FablibManager, 
            name: str = None,
            pcaps_dir: str = ".query_analysis_pcaps",
            name_prefix: str = "C"
        ):
        """
        Create a new crinkle slice
        :param fablib_manager:
        :param name:
        :param analyzer_name:
        :param cores:
        :param ram:
        :param disk:
        :param site:
        :param image:
        :param pcaps_dir:
        :return: CrinkleSlice
        """
        slice = CrinkleSlice(fablib_manager=fablib_manager, name=name, pcaps_dir=pcaps_dir,
                             name_prefix=name_prefix)
        slice.topology = ExperimentTopology()
        if fablib_manager:
            fablib_manager.cache_slice(slice_object=slice)
        return slice
    
    @staticmethod
    def get_slice(
        fablib_manager: FablibManager,
        sm_slice: OrchestratorSlice = None,
        user_only: bool = True,
        pcaps_dir: str = ".query_analysis_pcaps",
        name_prefix: str = "C"
    ):
        logging.info("crinkleslice.get_slice()")
        slice = CrinkleSlice(fablib_manager=fablib_manager, name=sm_slice.name,
                             pcaps_dir=pcaps_dir, name_prefix=name_prefix)
        slice.sm_slice = sm_slice
        slice.slice_id = sm_slice.slice_id
        slice.slice_name = sm_slice.name
        slice.user_only = user_only
        if fablib_manager:
            fablib_manager.cache_slice(slice_object=slice)

        try:
            slice.update_topology()
        except Exception as e:
            logging.error(
                f"Slice {slice.slice_name} could not update topology: slice.get_slice"
            )
            logging.error(e, exc_info=True)

        try:
            slice.update_slivers()
        except Exception as e:
            logging.error(
                f"Slice {slice.slice_name} could not update slivers: slice.get_slice"
            )
            logging.error(e, exc_info=True)

        slice.analyzer = slice.get_analyzer(name=f"{name_prefix}_analyzer")
        analyzer_site = slice.analyzer.get_site()
        for net in slice.get_networks():
            if net.get_name().startswith(f"{name_prefix}_net_"):
                slice.cnets[net.get_site()] = net
        slice.analyzer_cnet = slice.cnets[analyzer_site]
        slice.analyzer_name = slice.analyzer.get_name()
        slice.analyzer_iface = slice.analyzer.get_interface(network_name=slice.analyzer_cnet.get_name())

        for node in slice.get_nodes():
            node_name: str = node.get_name()
            if node_name.startswith(f"{name_prefix}_monitor_"):
                monitor = slice.get_monitor(name=node_name)
                monitor.get_monitor_data()
                slice.monitors[monitor.data.net_name] = monitor
                slice.monitor_count += 1

        return slice
    
    def add_analyzer(
            self,
            site: str = None,
            cores: int = 4,
            ram: int = 16,
            disk: int = 500,
            instance_type: str = None,
            host: str = None,
            user_data: dict = {},
            avoid: list[str] = [],
            validate: bool = False,
            raise_exception: bool = False,
        ) -> CrinkleAnalyzer:
        """
        Creates a new Crinkle Analyzer node on this fablib slice.

        :param name: Name of the new node
        :type name: String

        :param site: (Optional) Name of the site to deploy the node
            on.  Default to a random site.
        :type site: String

        :param cores: (Optional) Number of cores in the node.
            Default: 2 cores
        :type cores: int

        :param ram: (Optional) Amount of ram in the node.  Default: 8
            GB
        :type ram: int

        :param disk: (Optional) Amount of disk space n the node.
            Default: 10 GB
        :type disk: int

        :param instance_type:
        :type instance_type: String

        :param host: (Optional) The physical host to deploy the node.
            Each site has worker nodes numbered 1, 2, 3, etc.  Host
            names follow the pattern in this example of STAR worker
            number 1: "star-w1.fabric-testbed.net".  Default: unset
        :type host: String

        :param user_data
        :type user_data: dict

        :param avoid: (Optional) A list of sites to avoid is allowing
            random site.
        :type avoid: List[String]

        :param validate: Validate node can be allocated w.r.t available resources
        :type validate: bool

        :param raise_exception: Raise exception in case of Failure
        :type raise_exception: bool

        :return: a new Crinkle Analyzer node
        :rtype: CrinkleAnalyzer
        """

        analyzer = CrinkleAnalyzer.new_node(
            slice=self,
            name=f"{self.prefix}_analyzer",
            site=site,
            avoid=avoid,
            validate=validate,
            raise_exception=raise_exception
        )

        analyzer.init_fablib_data()

        user_data_working = analyzer.get_user_data()
        for k, v in user_data.items():
            user_data_working[k] = v
        analyzer.set_user_data(user_data_working)

        if instance_type:
            analyzer.set_instance_type(instance_type)
        else:
            analyzer.set_capacities(cores=cores, ram=ram, disk=disk)

        analyzer.set_image(CrinkleAnalyzer.default_image)

        if host:
            analyzer.set_host(host)

        self.nodes = None
        self.interfaces = {}

        if validate:
            status, error = self.get_fablib_manager().validate_node(node=analyzer)
            if not status:
                analyzer.delete()
                analyzer = None
                logging.warning(error)
                if raise_exception:
                    raise ValueError(error)

        self.analyzer = analyzer
        self.analyzer_name = analyzer.get_name()
        analyzer_site = self.analyzer.get_site()
        if analyzer_site not in self.cnets or self.cnets[analyzer_site] is None:
            self.cnets[analyzer_site] = self.add_l3network(name=f"{self.prefix}_net_{site}", type="IPv6")
        self.analyzer_cnet = self.cnets[analyzer_site]
        analyzer_iface = self.analyzer.add_component(model="NIC_Basic",
                                                     name=f"{self.prefix}_nic_cnet").get_interfaces()[0]
        analyzer_iface.set_mode("auto")
        self.analyzer_cnet.add_interface(analyzer_iface)
        # Import here due to circular import issues
        from fabrictestbed_extensions.fablib.fablib import FablibManager
        self.analyzer.add_route(subnet=FablibManager.FABNETV6_SUBNET, next_hop=self.analyzer_cnet.get_gateway())

        return analyzer
    
    def add_monitor(
            self,
            name: str = None,
            site: str = None,
            user_data: dict = {},
            net_name: str = None
    ) -> CrinkleMonitor:
        """
        Not intended for API call.
        See: CrinkleSlice.add_monitored_l2network() or CrinkleSlice.add_monitored_l3network()

        Creates a new Crinkle monitor node.
        """
        if self.analyzer is None:
            raise Exception(f"Analyzer must be created before adding monitors using add_analyzer()")
        
        monitor = CrinkleMonitor.new_node(
            slice=self,
            name=name,
            site=site,
        )

        monitor.init_fablib_data()

        user_data_working = monitor.get_user_data()
        for k, v in user_data.items():
            user_data_working[k] = v
        monitor.set_user_data(user_data_working)
        
        monitor.set_capacities(cores=CrinkleMonitor.default_cores, ram=CrinkleMonitor.default_ram, disk=CrinkleMonitor.default_disk)

        monitor.set_image(CrinkleAnalyzer.default_image)

        self.nodes = None
        self.interfaces = {}

        status, error = self.get_fablib_manager().validate_node(node=monitor)
        if not status:
            monitor.delete()
            monitor = None
            logging.warning(error)
            raise ValueError(error)
        
        if site not in self.cnets or self.cnets[site] is None:
            self.cnets[site] = self.add_l3network(name=f"{self.prefix}_net_{site}", type="IPv6")
        cnet = self.cnets[site]
        monitor_cnet_iface = monitor.add_component(model="NIC_Basic",
                                                   name=f"{self.prefix}_nic_cnet").get_interfaces()[0]
        monitor_cnet_iface.set_mode("auto")
        cnet.add_interface(monitor_cnet_iface)
        monitor.add_route(subnet=self.analyzer_cnet.get_subnet(), next_hop=cnet.get_gateway())
        monitor.data.cnet_iface = monitor_cnet_iface
        monitor.data.net_name = net_name
        monitor.data.monitor_id = self.monitor_count
        self.monitor_count += 1
        monitor.set_monitor_data()
        
        return monitor
    
    def get_analyzer(self, name:str) -> CrinkleAnalyzer:
        try:
            return CrinkleAnalyzer.get_node(self, self.get_fim_topology().nodes[name])
        except Exception as e:
            logging.info(e, exc_info=True)
            raise Exception(f"Node not found: {name}")
    
    def get_monitor(self, name: str) -> CrinkleMonitor:
        try:
            return CrinkleMonitor.get_node(self, self.get_fim_topology().nodes[name])
        except Exception as e:
            logging.info(e, exc_info=True)
            raise Exception(f"Node not found: {name}")

    def add_monitored_l2network(
        self,
        name: str = None,
        interfaces: list[Interface] = [],
        type: str = None,
        subnet: ipaddress = None,
        gateway: ipaddress = None,
        user_data: dict = {},
        sinks: list[Interface] = []
    ) -> CrinkleMonitor:
        # Directly from NetworkService.__calculate_l2_nstype
        from fabrictestbed_extensions.fablib.facility_port import FacilityPort

        # if there is a basic NIC, WAN must be STS
        basic_nic_count = 0

        sites = set([])
        includes_facility_port = False
        facility_port_interfaces = 0
        for interface in interfaces:
            sites.add(interface.get_site())
            if isinstance(interface.get_node(), FacilityPort):
                includes_facility_port = True
                facility_port_interfaces += 1
            if interface.get_model() == "NIC_Basic":
                basic_nic_count += 1

        rtn_nstype = None
        if 1 >= len(sites) >= 0:
            rtn_nstype = NetworkService.network_service_map["L2Bridge"]
        elif len(sites) == 2:
            # Use L2STS when connecting two facility ports instead of L2PTP
            # L2PTP limitation for Facility Ports:
            # basically the layer-2 point-to-point server template applied is not popping
            # vlan tags over the MPLS tunnel between two facility ports.
            if (
                includes_facility_port and facility_port_interfaces < 2
            ) and not basic_nic_count:
                # For now WAN FacilityPorts require L2PTP
                rtn_nstype = NetworkService.network_service_map["L2PTP"]
            elif len(interfaces) >= 2:
                rtn_nstype = NetworkService.network_service_map["L2STS"]
        else:
            raise Exception(
                f"Invalid Network Service: Networks are limited to 2 unique sites. Site requested: {sites}"
            )
        type = str(rtn_nstype)
        monitor_site = interfaces[0].get_site()
        monitor = self.add_monitor(name=f"{self.prefix}_monitor_{name}", site=monitor_site, net_name=name)

        if type == "L2Bridge":
            for iface in interfaces:
                iface_node_name = iface.get_node().get_name()
                monitor_iface = monitor.add_component("NIC_Basic", f"{self.prefix}_nic_{iface_node_name}").get_interfaces()[0]
                monitor_iface.set_mode("manual")
                self.add_l2network(f"{name}-{iface_node_name}", [iface, monitor_iface], "L2Bridge", subnet, gateway, user_data)
                monitor.data.net_type = type
                monitor.creation_data.append((iface_node_name, iface.get_name(), f"{self.prefix}_nic_{iface_node_name}", (iface in sinks), 0))
            self.monitors[name] = monitor
        monitor.set_monitor_data()
        return monitor
    
    def submit(
        self,
        wait: bool = True,
        wait_timeout: int = 1800,
        wait_interval: int = 20,
        progress: bool = True,
        wait_jupyter: str = "text",
        post_boot_config: bool = True,
        wait_ssh: bool = True,
        extra_ssh_keys: list[str] = None,
        lease_start_time: datetime = None,
        lease_end_time: datetime = None,
        lease_in_hours: int = None,
        validate: bool = False,
        allocate_hosts: bool = True
    ) -> str:
        logging.info("Crinkle submit()")
        if self.analyzer is None:
            raise Exception(f"Analyzer must be added before Crinkle slice submission using add_analyzer()")
        
        if (allocate_hosts):
            allocated = {}
            logging.info("Allocating Monitors and their connected Nodes to different worker hosts")
            for _, monitor in self.monitors.items():
                logging.info(f"Allocating Monitor for network {monitor.data.net_name}")
                if monitor.data.net_type == "L2Bridge":
                    endpoint1 = self.get_node(name=monitor.creation_data[0][0])
                    endpoint2 = self.get_node(name=monitor.creation_data[1][0])
                    endpoints = [endpoint1, endpoint2]
                    fablib = self.get_fablib_manager()
                    site = fablib.get_resources().get_site(endpoint1.get_site())
                    hosts = site.get_hosts()
                    endhosts = {}
                    for endpoint in endpoints:
                        if endpoint.get_host() is not None:
                            continue
                        foundhost = False
                        for host in hosts.values():
                            allocated_comps = allocated.setdefault(host.get_name(), {})
                            if fablib._FablibManager__can_allocate_node_in_host(
                                host=host, node=endpoint, allocated=allocated_comps, site=site)[0]:
                                endpoint.set_host(host_name=host.get_name())
                                endhosts.setdefault(host.get_name(), True)
                                foundhost = True
                                logging.info(f'Node {endpoint.get_name()} assigned to {host.get_name()}')
                                break
                        if not foundhost:
                            raise Exception(f"Could not place node {endpoint.get_name()}")
                    for host in hosts.values():
                        if host.get_name() in endhosts:
                            continue
                        allocated_comps = allocated.setdefault(host.get_name(), {})
                        if fablib._FablibManager__can_allocate_node_in_host(
                            host=host, node=monitor, allocated=allocated_comps, site=site)[0]:
                            monitor.set_host(host_name=host.get_name())
                            logging.info(f'Node {monitor.get_name()} assigned to {host.get_name()}')
                            break
                    if monitor.get_host() is None:
                        raise Exception(f"Could not place monitor for network {monitor.data.net_name}")
        
        return super().submit(wait=wait, wait_timeout=wait_timeout, wait_interval=wait_interval, progress=progress, wait_jupyter=wait_jupyter, post_boot_config=post_boot_config, wait_ssh=wait_ssh,
                       extra_ssh_keys=extra_ssh_keys, lease_start_time=lease_start_time, lease_end_time=lease_end_time, lease_in_hours=lease_in_hours, validate=validate)
    
    def post_boot_config(self):
        super().post_boot_config()
        logging.info(f"Crinkle post_boot_config")
        self.analyzer = self.get_node(name=self.analyzer_name)
        site = self.analyzer.get_site()
        self.analyzer_cnet = self.get_l3network(name=f"{self.prefix}_net_{site}")
        self.analyzer_iface = self.analyzer.get_interface(network_name=self.analyzer_cnet.get_name())
        self.cnets[site]=self.analyzer_cnet
        jobs: list[futures.Future] = []
        counter = 0
        spade_commands = (f'mkdir {REMOTEWORKDIR};'
                          'git clone https://github.com/ashish-gehani/SPADE.git;'
                          'sudo add-apt-repository -y ppa:openjdk-r/ppa; sudo apt-get update; sudo apt-get install -y openjdk-11-jdk;'
                          'sudo apt-get install -y auditd bison clang cmake curl flex fuse git ifupdown libaudit-dev libfuse-dev linux-headers-`uname -r` lsof pkg-config unzip uthash-dev wget;'
                          'sudo apt-get install -y graphviz python3-scapy;'
                          'cd SPADE; ./configure; make;'
                        )
        spade_job = self.analyzer.execute_thread(spade_commands)
        for key, monitor in self.monitors.items():
            logging.info(f"Refreshing monitor for net {key} after slice creation, count {counter}")
            refreshed_monitor = self.get_monitor(monitor.get_name())
            mon_site = refreshed_monitor.get_site()
            refreshed_monitor.execute(f"mkdir {REMOTEWORKDIR}")
            jobs.append(refreshed_monitor.upload_file_thread(f"{LOCALP4DIR}/base-crinkle.p4", f"{REMOTEWORKDIR}/base-crinkle.p4"))
            jobs.append(refreshed_monitor.execute_thread('source /etc/lsb-release; '
                                                         'echo "deb http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${DISTRIB_RELEASE}/ /" | sudo tee /etc/apt/sources.list.d/home:p4lang.list; '
                                                         'curl -fsSL https://download.opensuse.org/repositories/home:p4lang/xUbuntu_${DISTRIB_RELEASE}/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_p4lang.gpg > /dev/null; '
                                                         'sudo apt-get update; '
                                                         'sudo apt install -y p4lang-p4c'))
            if self.cnets[mon_site] is None or not self.cnets[mon_site].is_instantiated():
                self.cnets[mon_site] = self.get_l3network(name=f"{self.prefix}_net_{mon_site}")
            refreshed_monitor.data.cnet_iface = refreshed_monitor.get_interface(network_name=f"{self.prefix}_net_{mon_site}")
            dev_name = refreshed_monitor.data.cnet_iface.get_device_name()
            refreshed_monitor.data.port_sequence += f"-i {refreshed_monitor.data.port_nums}@{dev_name} "
            refreshed_monitor.data.port_nums += 1
            for data in monitor.creation_data:
                logging.info(f"Initializing monitor after slice creation with data: {data}")
                iface: Interface = self.get_node(name=data[MonNetData.NODENAME]).get_interface(name=data[MonNetData.IFACENAME])
                mon_iface = refreshed_monitor.get_component(name=data[MonNetData.MIFACENAME]).get_interfaces()[0]
                dev_name = mon_iface.get_device_name()
                refreshed_monitor.data.port_sequence += f"-i{refreshed_monitor.data.port_nums}@{dev_name} "
                refreshed_monitor.data.iface_mappings[iface] = (
                    data[MonNetData.NODENAME], mon_iface, data[MonNetData.ISSINK], refreshed_monitor.data.port_nums)
                refreshed_monitor.data.port_nums += 1
                jobs.append(refreshed_monitor.execute_thread(f'sudo ifconfig {dev_name} promisc'))
            self.monitors[key] = refreshed_monitor
            refreshed_monitor.set_monitor_data()
            counter += 1
        logging.info(f"Crinkle post_boot_config waiting on jobs to finish")
        print("Configuring Crinkle Resources")
        futures.wait(jobs)
        logging.info(f"Saving Crinkle Data")
        self.submit(wait=True, progress=False, post_boot_config=False, wait_ssh=False, allocate_hosts=False)
        self.update()
        logging.info(f'Waiting on Crinkle analyzer SPADE install to finish')
        futures.wait([spade_job])
        logging.info(f'Starting SPADE')
        self.analyzer.execute_thread('./SPADE/bin/spade debug')
        time.sleep(3)
        spade_control_commands = ('add reporter DSL /home/ubuntu/spade_pipe\n'
                                  'add analyzer CommandLine\n'
                                  'add storage Neo4j database=/home/ubuntu/spade_database\n')
        self.analyzer.execute(f'echo -e "{spade_control_commands}" | ./SPADE/bin/spade control', quiet=True)
        self.analyzer.upload_file("spade-reader.py", "spade-reader.py")
        self.analyzer.execute("sudo chmod u+x spade-reader.py")
        self.analyzer.execute_thread("sudo python3 spade-reader.py")
        logging.info(f"Crinkle post_boot_config done")

    @staticmethod
    def mac_to_int(mac: str):
        hexes = mac.split(':')
        intval = 0
        for i in range(0, 6):
            hexval = hexes[5-i]
            intval += (16**(2*i+1))*int(hexval[0], 16) + (16**(2*i))*int(hexval[1], 16)
        return intval
    
    @staticmethod
    def ip6_to_int(ip6: str):
        ip6 = IPv6Address(ip6)
        return (int(ip6)//(2**64),int(ip6)%(2**64))
        
    def start_bmv2(self, monitor: CrinkleMonitor, wait: bool=True):
        command = (f'p4c --target bmv2 --arch v1model {REMOTEWORKDIR}/base-crinkle.p4 -o {REMOTEWORKDIR};'
                   f'nohup bash -c "sudo simple_switch {monitor.data.port_sequence}{REMOTEWORKDIR}/base-crinkle.json --log-file ~/monitor.log -- --enable-swap; echo " 1> /dev/null 2> /dev/null &')
        job = None
        if wait:
            monitor.execute(command=command)
        else:
            job = monitor.execute_thread(command=command)
        return job
    
    def configure_bridging(self, monitor: CrinkleMonitor, wait: bool=True):
        p4_commands = []
        if monitor.data.net_type in ["L2Bridge", "L2STS", "L2PTP"]:
            sinks = {}
            p4_commands = ["table_add table_l2_bridge l2_bridge 1 => 2",
                           "table_add table_l2_bridge l2_bridge 2 => 1",
                           f'register_write macs 1 {self.mac_to_int("ff:ff:ff:ff:ff:ff")}',
                           f'register_write macs 0 {self.mac_to_int(monitor.data.cnet_iface.get_mac())}',
                           f'register_write ip1 0 {self.ip6_to_int(monitor.data.cnet_iface.get_ip_addr())[0]}',
                           f'register_write ip1 1 {self.ip6_to_int(self.analyzer_iface.get_ip_addr())[0]}',
                           f'register_write ip2 0 {self.ip6_to_int(monitor.data.cnet_iface.get_ip_addr())[1]}',
                           f'register_write ip2 1 {self.ip6_to_int(self.analyzer_iface.get_ip_addr())[1]}',
                           'register_write swport 0 0',
                           'register_write trunc 0 80',
                           f'register_write r_monitor_id 0 {monitor.data.monitor_id}',
                           f'register_write r_monitor_id2 0 {monitor.data.monitor_id}',
                           'mirroring_add 5 0']
            for _, (_, _, is_sink, port_num) in monitor.data.iface_mappings.items():
                if is_sink:
                    p4_commands.append(f'table_add table_do_uid strip_uid {port_num} => ')
                sinks[port_num] = is_sink
        p4_command_chain = ""
        for command in p4_commands[:-1]:
            p4_command_chain += command+'\n'
        p4_command_chain += p4_commands[-1]
        job = None
        if wait:
            monitor.execute(f'echo -e "{p4_command_chain}" | simple_switch_CLI')
        else:
            job = monitor.execute_thread(f'echo -e "{p4_command_chain}" | simple_switch_CLI')
        return job
    
    def configure_all_bridging(self):
        logging.info(f"Adding default bmv2 rules for monitors")
        jobs = []
        for monitor in self.monitors.values():
            jobs.append(self.configure_bridging(monitor=monitor, wait=False))
        logging.info(f"Waiting for rules jobs to finish")
        futures.wait(jobs)

    @staticmethod
    def ip_net_like(net: str):
        net_mask = net.split('/')
        ret_str = ""
        net_parts = net_mask[0].split('.')
        ctr = 0
        if net_parts[ctr] == "0":
            ret_str += '%'
        else:
            ret_str += net_parts[ctr]
        ctr += 1
        while ctr < len(net_parts):
            if net_parts[ctr] == "0":
                ret_str += '.%'
            else:
                ret_str += '.'+net_parts[ctr]
            ctr += 1
        if ctr < 3:
            ret_str += '.%'
        return ret_str
                

    def get_graph(self, name: str = "graph", filterin: str = None, net_names: list[str] = [], node_names: list[str] = []):
        spade_filter = ""
        if filterin is not None:
            filter_words = filterin.split(' ')
            i = 0
            ctr = 0
            while i < len(filter_words) and ctr < 100:
                do_ip = False
                do_port = False
                if filter_words[i] == 'and' or filter_words[i] == 'or':
                    spade_filter += f'{filter_words[i]} '
                    i += 1
                if filter_words[i] == 'src':
                    spade_filter += '\\"ip.src\\"'
                    do_ip = True
                    i += 1
                elif filter_words[i] == 'dst':
                    spade_filter += '\\"ip.dst\\"'
                    do_ip = True
                    i += 1
                elif filter_words[i] == 'ip':
                    spade_filter += '''\\"eth.type\\" == '0x800' '''
                    do_ip = True
                    i += 1
                elif filter_words[i] == 'tcp':
                    spade_filter += '''\\"ip.prot\\" == '6' '''
                    do_port = True
                    i += 1
                elif filter_words[i] == 'udp':
                    spade_filter += '''\\"ip.prot\\" == '17' '''
                    do_port = True
                    i += 1
                elif filter_words[i] == 'icmp':
                    spade_filter += '''\\"ip.prot\\" == '1' '''
                    i += 1
                elif filter_words[i] == 'host':
                    spade_filter += f'''\\"ip.src\\" == '{filter_words[i+1]}' or ip.dst == '{filter_words[i+1]}' '''
                    i += 2
                elif filter_words[i] == 'net':
                    spade_filter += f'''\\"ip.src\\" LIKE '{self.ip_net_like(filter_words[i+1])}' or ip.dst LIKE '{self.ip_net_like(filter_words[i+1])}' '''
                    i += 2
                if do_ip:
                    if filter_words[i] == 'src':
                        spade_filter += 'and \\"ip.src\\"'
                        i += 1
                    elif filter_words[i] == 'dst':
                        spade_filter += 'and \\"ip.dst\\"'
                        i += 1
                    if filter_words[i] == 'host':
                        if filter_words[i-1] == 'src' or filter_words[i-1] == 'dst':
                            spade_filter += f''' == '{filter_words[i+1]}' '''
                        else:
                            spade_filter += f'''and \\"ip.src\\" == '{filter_words[i+1]}' or ip.dst == '{filter_words[i+1]}' '''
                        i += 2
                    elif filter_words[i] == 'net':
                        if filter_words[i-1] == 'src' or filter_words[i-1] == 'dst':
                            spade_filter += f'''\\" LIKE '{self.ip_net_like(filter_words[i+1])}' '''
                        else:
                            spade_filter += f'''and \\"ip.src\\" LIKE '{self.ip_net_like(filter_words[i+1])}' or ip.dst LIKE '{self.ip_net_like(filter_words[i+1])}' '''
                        i += 2
                    else:
                        raise Exception(f"Invalid term following {filter_words[i]}: {filter_words[i+1]}")
                if do_port:
                    if i >= len(filter_words): break
                    if filter_words[i] == 'port':
                        spade_filter += f'''and \\"prot.sport\\" == '{filter_words[i+1]}' or \\"prot.dport\\" == '{filter_words[i+1]}' '''
                        i += 2
                    elif filter_words[i] == 'src':
                        spade_filter += f'''and \\"prot.sport\\"  == '{filter_words[i+1]}' '''
                        i += 2
                    elif filter_words[i] == 'dst':
                        spade_filter += f'''and \\"prot.dport\\"  == '{filter_words[i+1]}' '''
                        i += 2
                ctr += 1
            spade_filter = spade_filter.rstrip()
            graph_build = f'''\\$graph1 = \\$base.getLineage(\\$base.getVertex({spade_filter}), 1, 'b')\n\\$graph = \\$graph1 + \\$base.getPath(\\$graph1.getVertex(\\"type\\" == 'Process'), \\$base.getVertex(\\"type\\" == 'Agent'), 1)'''
            self.analyzer.execute(f'echo -e "set storage Neo4j\n{graph_build}\nexport > /home/ubuntu/{REMOTEWORKDIR}/{name}.dot\ndump all \\$graph" | ./SPADE/bin/spade query; '
                                    f'dot -Tsvg {REMOTEWORKDIR}/{name}.dot -o {REMOTEWORKDIR}/{name}.svg')
            self.analyzer.download_file(f'{name}.svg', f'{REMOTEWORKDIR}/{name}.svg')
        else:
            self.analyzer.execute(f'echo -e "set storage Neo4j\nexport > /home/ubuntu/{REMOTEWORKDIR}/{name}.dot\ndump all \\$base" | ./SPADE/bin/spade query; '
                                    f'dot -Tsvg {REMOTEWORKDIR}/{name}.dot -o {REMOTEWORKDIR}/{name}.svg')
            self.analyzer.download_file(f'{name}.svg', f'{REMOTEWORKDIR}/{name}.svg')
    
    def start_monitor(self, monitor: CrinkleMonitor, wait: bool=True) -> tuple[list[futures.Future], futures.Future]:
        if monitor is None:
            raise Exception("Monitor cannot be None")
        tcpdumps: list[futures.Future] = []
        for _, (iface_node_name, mon_iface, _, _) in monitor.data.iface_mappings.items():
            logging.info(f"Starting Monitor for network {monitor.get_name()} iface for {iface_node_name} ")
            # mon_iface_name = mon_iface.get_device_name()
            # tcpdumps.append(monitor.execute_thread(command=f"mkdir {monitor.data.net_name}; sudo tcpdump -vvvxxenK -i {mon_iface_name} -w {monitor.data.net_name}/{iface_node_name}.pcap"))
        bmv2_start = self.start_bmv2(monitor=monitor, wait=wait)
        if wait:
            # tcpdumps2: list[futures.Future] = []
            # for tcpdump in tcpdumps:
            #     if not tcpdump.running():
            #         tcpdumps2.append(tcpdump)
            # logging.info(f"Waiting for {monitor.data.net_name} monitor to finish starting tcpdump processes ")
            # iteration = len(tcpdumps2)
            # count = 0
            # while len(tcpdumps2) > 0:
            #     if tcpdumps2[-1].running():
            #         tcpdumps2.pop()
            #     if count == iteration:
            #         logging.info(f"Waiting for {monitor.data.net_name} monitor to finish starting tcpdump processes ")
            #         count = 0
            #     count += 1
            logging.info(f"Adding default bmv2 rules for {monitor.data.net_name} monitor")
            self.configure_bridging(monitor=monitor, wait=True)
        return [tcpdumps, bmv2_start]
        
    def start_all_monitors(self, wait: bool=True):
        tcpdump_lists: list[list[futures.Future]] = []
        bmv2_list: list[futures.Future] = []
        for monitor in self.monitors.values():
            jobs = self.start_monitor(monitor=monitor, wait=False)
            tcpdump_lists.append(jobs[0])
            bmv2_list.append(jobs[1])
        tcpdumps: list[futures.Future] = sum(tcpdump_lists, [])
        if wait:
            # tcpdumps2: list[futures.Future] = []
            # for tcpdump in tcpdumps:
            #     if not tcpdump.running():
            #         tcpdumps2.append(tcpdump)
            # logging.info(f"Waiting for monitors to finish starting tcpdump processes ")
            # iteration = len(tcpdumps2)
            # count = 0
            # while len(tcpdumps2) > 0:
            #     if tcpdumps2[-1].running():
            #         tcpdumps2.pop()
            #     if count == iteration:
            #         logging.info(f"Waiting for monitors to finish starting tcpdump processes ")
            #         count = 0
            #     count += 1
            logging.info(f"Waiting for monitors to finish starting bmv2 processes ")
            futures.wait(bmv2_list)
            self.configure_all_bridging()
        return tcpdumps

    def stop_monitor(self, monitor: CrinkleMonitor):
        if monitor is None:
            raise Exception("mon_net cannot be None")
        monitor.execute("sudo killall simple_switch")

    def stop_all_monitors(self):
        for monitor in self.monitors.values():
            self.stop_monitor(monitor=monitor)

    def retrieve_pcaps(self, monitor: CrinkleMonitor):
        if monitor is None:
            raise Exception("mon_net cannot be None")
        shutil.rmtree(f"{self.pcaps_dir}/{monitor.data.net_name}/.", True)
        monitor.download_directory(f"{self.pcaps_dir}/{monitor.data.net_name}", remote_directory_path=f"{monitor.data.net_name}")
        self.analyzer.execute(f"sudo rm -rf {PCAPDIR}/{monitor.data.net_name}")
        self.analyzer.upload_directory(f"{self.pcaps_dir}/{monitor.data.net_name}", f"{PCAPDIR}/{monitor.data.net_name}")

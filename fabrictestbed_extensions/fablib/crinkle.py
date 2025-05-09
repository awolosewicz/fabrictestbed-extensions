from __future__ import annotations

import ipaddress
import json
import logging
import enum
import shutil
import time
import random
from IPython.core.display_functions import display
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
from fabrictestbed_extensions.fablib.site import Site, Host

CAPERSTART = "./caper/caper.byte -q -p -e"
PCAPDIR = "/home/ubuntu/pcaps/"
LOCALP4DIR = "."
REMOTEWORKDIR = ".crease"
CREASEDIR = "fabrictestbed-extensions/fabrictestbed_extensions/fablib/crease"
MONITORURL = "https://transparnet.cs.iit.edu/~awolosewicz/dpdk-crease_monitor"
DPDKNAME = "dpdk-crease_monitor"
MONPROT = 0x6587

UBUNTU_IMAGES = ["default_ubuntu_20",
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
    default_image = "attestable_bmv2_v2_ubuntu_20"

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

    default_image = "attestable_bmv2_v2_ubuntu_20"
    default_cores = 2
    default_ram = 4
    default_disk = 10

    class MonitorData():
        def __init__(
            self,
            port_nums: int = 0,
            cmd_args: str = "",
            net_name: str = None,
            net_type: str = None,
            cnet_iface: Interface = None,
            iface_mappings: dict[str, tuple[str, Interface, bool, int]] = {},
            monitor_id: int = None
        ):
            self.port_nums = port_nums
            self.cmd_args = cmd_args
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
                iface_mappings[node_iface] = (
                    node_name, self.slice.get_interface(name=monitor_iface), is_sink, port_num
                )
            self.data = self.MonitorData(
                port_nums=data["port_nums"],
                cmd_args=data["cmd_args"],
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
            iface_mappings[node_iface] = (
                node_name, monitor_iface.get_name(), is_sink, port_num
            )
        data_dict = {
            "port_nums": self.data.port_nums,
            "cmd_args": self.data.cmd_args,
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
        self.monitor_string = None
        self.probe_id = 0
        self.do_allocate_hosts = True
        self.did_post_boot = False

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
    
    def get_crinkle_data(self, analyzer: CrinkleAnalyzer):
        """
        Get slice-wide crinkle data.
        """
        logging.info(f"get_crinkle_data()")
        if "crinkle_slice_config" in analyzer.get_user_data():
            data = self.analyzer.get_user_data()["crinkle_slice_config"]
            #data_iface_mappings = self.get_user_data()["iface_mappings"]
            #logging.info(f"Retrieved monitor iface mappings as: {data_iface_mappings}")
            self.analyzer_name = data["analyzer_name"]
            self.prefix = data["prefix"]
            self.monitor_string = data["monitor_string"]
            self.did_post_boot = data["did_post_boot"]
            logging.info(f"Retrieved crinkle slice config as:\n{self.analyzer_name}\n{self.prefix}\n{self.monitor_string}")
        else:
            logging.info(f"Did not retrieve stored crinkle slice config")
        
    def set_crinkle_data(self):
        """
        Set slice-wide crinkle data.
        """
        logging.info(f"set_crinkle_data()")
        user_data = self.analyzer.get_user_data()
        data_dict = {
            "analyzer_name": self.analyzer_name,
            "prefix": self.prefix,
            "monitor_string": self.monitor_string,
            "did_post_boot": self.did_post_boot
        }
        logging.info(f"Writing crinkle slice config to user data: {data_dict}")
        user_data["crinkle_slice_config"] = data_dict
        #logging.info(f"Writing monitor iface mappings to user data: {iface_mappings}")
        #user_data["iface_mappings"] = iface_mappings
        self.analyzer.set_user_data(user_data=user_data)
    
    @staticmethod
    def get_slice(
        fablib_manager: FablibManager,
        sm_slice: OrchestratorSlice = None,
        user_only: bool = True,
        pcaps_dir: str = ".query_analysis_pcaps",
        name_prefix: str = "C"
    ):
        """
        Not intended for API use. See FablibManager.get_crinkle_slice().

        Gets an existing crinkle fablib slice using a slice manager slice
        :param fablib_manager:
        :param sm_slice:
        :param user_only: True indicates return own slices; False indicates return project slices
        :type user_only: bool
        :param name_prefix: The prefix Crinkle will append its resources with, which should not prefix any other resources
        :type name_prefix: String
        :return: CrinkleSlice
        """
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
        slice.get_crinkle_data(slice.analyzer)
        analyzer_site = slice.analyzer.get_site()
        for net in slice.get_networks():
            if net.get_name().startswith(f"{name_prefix}_ananet_"):
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
        
        if slice.monitor_string == '':
            slice.reset_monitor_string()
        slice.set_crinkle_data()

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
            self.cnets[analyzer_site] = self.add_l3network(name=f"{self.prefix}_ananet_{site}", type="IPv6")
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

        :param name: The name for the monitor node
        :type name: String
        :param site:
        :type site: String
        :param user_data
        :type user_data: dict
        :param net_name: The name of the network this will monitor
        :type net_name: String
        :return: a new monitor node
        :rtype: CrinkleMonitor
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
        
        if site == "EDUKY":
            monitor.set_image("default_ubuntu_22")
        else:
            monitor.set_image(CrinkleMonitor.default_image)

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
        """
        Gets an analyzer from the CrinkleSlice by name.

        :param name: Name of the analyzer
        :type name: String
        :return: the analyzer node
        :rtype: CrinkleAnalyzer
        """
        try:
            return CrinkleAnalyzer.get_node(self, self.get_fim_topology().nodes[name])
        except Exception as e:
            logging.info(e, exc_info=True)
            raise Exception(f"Node not found: {name}")
    
    def get_monitor(self, name: str) -> CrinkleMonitor:
        """
        Gets a monitor from the CrinkleSlice by name.

        :param name: Name of the monitor
        :type name: String
        :return: the monitor node
        :rtype: CrinkleMonitor
        """
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
        """
        Adds an L2 network similarly to Slice.add_l2network, but additionally adds a
        CrinkleMonitor node to the network which all traffic routes through. The
        CrinkleMonitor nodes will collect traffic information and update the
        CrinkleAnalyzer node. Additionally, certain functions will use the CrinkleMonitor
        nodes to emit or modify packets.

        

        :param name: the name of the network service
        :type name: String

        :param interfaces: a list of interfaces to build the network
            with
        :type interfaces: List[Interface]

        :param type: optional L2 network type "L2Bridge", "L2STS", or
            "L2PTP"
        :type type: String

        :param subnet:
        :type subnet: ipaddress

        :param gateway:
        :type gateway: ipaddress

        :param user_data
        :type user_data: dict

        :param sinks: A set of interfaces which should have any Crinkle packet trailers
            stripped before entering.
        :type sinks: list[Interface]

        :return: a new CrinkleMonitor
        :rtype: CrinkleMonitor
        """
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
                new_net = self.add_l2network(f"{self.prefix}_net_{name}_{iface_node_name}", [iface, monitor_iface], "L2Bridge", subnet, gateway, user_data)
                self.set_orig_net_name(new_net, name)
                monitor.data.net_type = type
                monitor.creation_data.append((iface_node_name, iface.get_name(), f"{self.prefix}_nic_{iface_node_name}", (iface in sinks), 0))
            self.monitors[name] = monitor
        monitor.set_monitor_data()
        return monitor
    
    @staticmethod
    def get_orig_net_name(net: NetworkService) -> str:
        user_data = net.get_user_data()
        if "crinkle_net_name" in user_data:
            orig_name = user_data["crinkle_net_name"]
            logging.info(f"Retrieved original network name for {net.get_name()} as {orig_name}")
            return orig_name
        else:
            logging.info(f"Did not retrieve original network name for {net.get_name()}")
            return ""

    @staticmethod
    def set_orig_net_name(net: NetworkService, name: str):
        logging.info(f"Storing orig name for network {net.get_name()} as {name}")
        user_data = net.get_user_data()
        user_data["crinkle_net_name"] = name
        net.set_user_data(user_data=user_data)

    
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
    ) -> str:
        """
        Similarly to Slice.submit(), submits a slice request to FABRIC.
        This version does extra work to support Crinkle resources, such as
        ensuring monitors are on different workers from the nodes they monitor.


        :param wait: indicator for whether to wait for the slice's resources to be active
        :type wait: bool

        :param wait_timeout: how many seconds to wait on the slice resources
        :type wait_timeout: int

        :param wait_interval: how often to check on the slice resources
        :type wait_interval: int

        :param progress: indicator for whether to show progress while waiting
        :type progress: bool

        :param wait_jupyter: Special wait for jupyter notebooks.
        :type wait_jupyter: str

        :param post_boot_config:
        :type post_boot_config: bool

        :param wait_ssh:
        :type wait_ssh: bool

        :param extra_ssh_keys: Optional list of additional SSH public keys to be installed in the slivers of this slice
        :type extra_ssh_keys: List[str]

        :param lease_start_time: Optional lease start time in UTC format: %Y-%m-%d %H:%M:%S %z.
                           Specifies the beginning of the time range to search for available resources valid for `lease_in_hours`.
        :type lease_start_time: datetime

        :param lease_end_time: Optional lease end time in UTC format: %Y-%m-%d %H:%M:%S %z.
                         Specifies the end of the time range to search for available resources valid for `lease_in_hours`.
        :type lease_end_time: datetime

        :param lease_in_hours: Optional lease duration in hours. By default, the slice remains active for 24 hours (1 day).
                               This parameter is only applicable during creation.
        :type lease_in_hours: int

        :param validate: Validate node can be allocated w.r.t available resources
        :type validate: bool

        :return: slice_id
        :rtype: String
        """
        logging.info("Crinkle submit()")
        if self.analyzer is None:
            raise Exception(f"Analyzer must be added before Crinkle slice submission using add_analyzer()")
        
        if (self.do_allocate_hosts):
            allocated = {}
            logging.info("Allocating Monitors and their connected Nodes to different worker hosts")
            sitenames_to_sites: dict[str, Site] = {}
            sitenames_to_hosts: dict[str, dict[str, Host]] = {}
            fablib = self.get_fablib_manager()
            fabresources = fablib.get_resources()
            for _, monitor in self.monitors.items():
                logging.info(f"Allocating Monitor for network {monitor.data.net_name}")
                if monitor.data.net_type == "L2Bridge":
                    endpoint1 = self.get_node(name=monitor.creation_data[0][0])
                    endpoint2 = self.get_node(name=monitor.creation_data[1][0])
                    endpoints = [endpoint1, endpoint2]
                    sitename = endpoint1.get_site()
                    site = sitenames_to_sites.setdefault(sitename, fabresources.get_site(sitename))
                    hosts = sitenames_to_hosts.setdefault(sitename, site.get_hosts())
                    hostlist = list(hosts.items())
                    hostlist = sorted(hostlist)
                    #random.shuffle(hostlist)
                    endhosts = {}
                    for endpoint in endpoints:
                        if endpoint.get_host() is not None:
                            endhosts.setdefault(endpoint.get_host(), True)
                            continue
                        foundhost = False
                        for hostname, host in hostlist[1:]:
                            allocated_comps = allocated.setdefault(hostname, {})
                            if fablib._FablibManager__can_allocate_node_in_host(
                                host=host, node=endpoint, allocated=allocated_comps, site=site)[0]:
                                endpoint.set_host(host_name=hostname)
                                endhosts.setdefault(hostname, True)
                                foundhost = True
                                logging.info(f'Node {endpoint.get_name()} assigned to {hostname}')
                                break
                        if not foundhost:
                            raise Exception(f"Could not place node {endpoint.get_name()}")
                    for hostname, host in hostlist:
                        if hostname in endhosts:
                            continue
                        allocated_comps = allocated.setdefault(hostname, {})
                        if fablib._FablibManager__can_allocate_node_in_host(
                            host=host, node=monitor, allocated=allocated_comps, site=site)[0]:
                            monitor.set_host(host_name=hostname)
                            logging.info(f'Node {monitor.get_name()} assigned to {hostname}')
                            break
                    if monitor.get_host() is None:
                        raise Exception(f"Could not place monitor for network {monitor.data.net_name}")
                self.do_allocate_hosts = False
            logging.info("Hosts allocated")
        
        return super().submit(wait=wait, wait_timeout=wait_timeout, wait_interval=wait_interval, progress=progress, wait_jupyter=wait_jupyter, post_boot_config=post_boot_config, wait_ssh=wait_ssh,
                       extra_ssh_keys=extra_ssh_keys, lease_start_time=lease_start_time, lease_end_time=lease_end_time, lease_in_hours=lease_in_hours, validate=validate)
    
    def post_boot_config(self):
        """
        Runs post_boot_config identically to Slice.post_boot_config before running
        Crinkle specific functions. These are to:
            - Install the SPADE provenance analyzer to the analyzer node
            - Install other needed libraries and software to the analyzer and monitors
            - Update the slice local variables with new references to FABRIC resources
            - Create the monitor.data entries and save them to FABRIC
            - Start the SPADE instance and analyzer listening service

        Only use this method after a non-blocking submit call and only call it
        once.
        """
        super().post_boot_config()
        logging.info(f"Crinkle post_boot_config")
        if not self.did_post_boot:
            self.analyzer = self.get_node(name=self.analyzer_name)
            site = self.analyzer.get_site()
            self.analyzer_cnet = self.get_l3network(name=f"{self.prefix}_ananet_{site}")
            self.analyzer_iface = self.analyzer.get_interface(network_name=self.analyzer_cnet.get_name())
            self.cnets[site]=self.analyzer_cnet
            jobs: list[futures.Future] = []
            counter = 0
            self.monitor_string = f"{self.analyzer_iface.get_device_name()} "
            for key, monitor in self.monitors.items():
                logging.info(f"Refreshing monitor for net {key} after slice creation, count {counter}")
                refreshed_monitor = self.get_monitor(monitor.get_name())
                mon_site = refreshed_monitor.get_site()
                jobs.append(refreshed_monitor.execute_thread(f"sudo ip link set {self.analyzer_iface.get_device_name()} up; wget -q -O {REMOTEWORKDIR}/{DPDKNAME} {MONITORURL}; chmod u+x {REMOTEWORKDIR}/{DPDKNAME}"))
                if self.cnets[mon_site] is None or not self.cnets[mon_site].is_instantiated():
                    self.cnets[mon_site] = self.get_l3network(name=f"{self.prefix}_ananet_{mon_site}")
                refreshed_monitor.data.cnet_iface = refreshed_monitor.get_interface(network_name=f"{self.prefix}_ananet_{mon_site}")
                ordered_devs = {}
                ctr = 0
                # Need a way to know where a specific interface falls *in the OS ordering of them*
                # Such as, if an interface is device enp8s0, and OS has enp7s0, enp8s0, enp9s0, return 1
                # And because this isn't consistent per site, cannot assume enp7s0 is first
                for entry in refreshed_monitor.get_dataplane_os_interfaces():
                    ordered_devs[entry['ifname']] = ctr
                    ctr += 1
                refreshed_monitor.data.cmd_args += f"-n {refreshed_monitor.data.monitor_id} "
                refreshed_monitor.data.cmd_args += f"-m {refreshed_monitor.data.cnet_iface.get_mac()} -m {self.analyzer_iface.get_mac()} "
                refreshed_monitor.data.cmd_args += f"-i {refreshed_monitor.data.cnet_iface.get_ip_addr()} -i {self.analyzer_iface.get_ip_addr()} "
                dev_name = refreshed_monitor.data.cnet_iface.get_device_name()
                refreshed_monitor.data.cmd_args += f"-d {refreshed_monitor.data.port_nums}@{ordered_devs[dev_name]} "
                refreshed_monitor.data.port_nums += 1
                self.monitor_string += f'{refreshed_monitor.data.monitor_id} '
                for data in monitor.creation_data:
                    logging.info(f"Initializing monitor after slice creation with data: {data}")
                    mon_iface = refreshed_monitor.get_component(name=data[MonNetData.MIFACENAME]).get_interfaces()[0]
                    dev_name = mon_iface.get_device_name()
                    refreshed_monitor.data.cmd_args += f"-d {refreshed_monitor.data.port_nums}@{ordered_devs[dev_name]} "
                    refreshed_monitor.data.iface_mappings[data[MonNetData.IFACENAME]] = (
                        data[MonNetData.NODENAME], mon_iface, data[MonNetData.ISSINK], refreshed_monitor.data.port_nums)
                    self.monitor_string += f'{refreshed_monitor.data.port_nums}@{data[MonNetData.IFACENAME]} '
                    refreshed_monitor.data.port_nums += 1
                self.monitor_string += ' '
                self.monitors[key] = refreshed_monitor
                refreshed_monitor.set_monitor_data()
                counter += 1
            self.monitor_string = self.monitor_string.rstrip()
            logging.info(f"Crinkle post_boot_config waiting on jobs to finish")
            print("Configuring Crinkle Resources")
            ctr = 0
            for _ in futures.as_completed(jobs):
                ctr += 1
                logging.info(f'{ctr}/{len(jobs)} jobs finished')
                print(f'{ctr}/{len(jobs)} jobs finished')
            logging.info(f"Saving Crinkle Data")
            self.set_crinkle_data()
            self.submit(wait=True, progress=False, post_boot_config=False, wait_ssh=False)
            self.update()
            logging.info(f"Rebooting Crinkle monitors")
            print("Rebooting Crinkle Resources")
            for monitor in self.monitors.values():
                monitor.execute("sudo reboot")
            logging.info(f"Waiting on Crinkle monitors to finish reboot")
            self.wait_ssh(progress=True)
            jobs = []
            logging.info(f"Enabling Crinkle monitor interfaces")
            for monitor in self.monitors.values():
                cmd = f'sudo ip link set {monitor.data.cnet_iface.get_device_name()} up; sudo ip link set {monitor.data.cnet_iface.get_device_name()} promisc on; '
                for (_, iface, _, _) in monitor.data.iface_mappings.values():
                    dev_name = iface.get_device_name()
                    cmd += f'sudo ip link set {dev_name} up; sudo ip link set {dev_name} promisc on; '
                jobs.append(monitor.execute_thread(cmd.rstrip()))
            ctr = 0
            for _ in futures.as_completed(jobs):
                ctr += 1
                logging.info(f'{ctr}/{len(jobs)} jobs finished')
                print(f'{ctr}/{len(jobs)} jobs finished')
            logging.info(f'Starting SPADE')
            self.analyzer.execute_thread(f'./{REMOTEWORKDIR}/SPADE/bin/spade debug')
            time.sleep(5)
            spade_control_commands = ('add reporter DSL /home/ubuntu/spade_pipe\n'
                                    'add analyzer CommandLine\n'
                                    'add storage Neo4j database=/home/ubuntu/spade_database\n')
            self.analyzer.execute(f'echo -e "{spade_control_commands}" | ./{REMOTEWORKDIR}/SPADE/bin/spade control', quiet=True)
            self.analyzer.upload_file(f"{CREASEDIR}/spade_reader.py", f"{REMOTEWORKDIR}/spade_reader.py")
            self.analyzer.execute(f"sudo chmod u+x {REMOTEWORKDIR}/spade_reader.py")
            if self.monitor_string == '':
                self.reset_monitor_string()
            self.analyzer.execute_thread(f"sudo ./{REMOTEWORKDIR}/spade_reader.py {self.monitor_string}")
            logging.info(f"Crinkle post_boot_config done")
            print("Crinkle post_boot_config done")
            self.did_post_boot = True

    def get_non_crinkle_nodes(self, refresh: bool = False) -> list[Node]:
        """
        Gets a list of all nodes in this slice.

        :return: a list of fablib nodes
        :rtype: List[Node]
        """
        if not self.nodes or not len(self.nodes):
            refresh = True
        nodes = self.get_nodes(refresh=refresh)
        crinkle_nodes = [mon_name for mon_name in self.monitors.keys()]
        crinkle_nodes.append(self.analyzer_name)
        i = 0
        while i < len(nodes):
            node = nodes[i]
            nodename: str = node.get_name()
            if nodename.startswith(f'{self.prefix}_monitor_') or nodename == f'{self.prefix}_analyzer':
                nodes.pop(i)
            else:
                i += 1
        return nodes
    
    @staticmethod
    def mac_to_int(mac: str):
        """
        Translates a MAC address to an int

        :param mac: MAC address
        :type mac: String
        :return: The integer value of the MAC address
        :rtype: int
        """
        hexes = mac.split(':')
        intval = 0
        for i in range(0, 6):
            hexval = hexes[5-i]
            intval += (16**(2*i+1))*int(hexval[0], 16) + (16**(2*i))*int(hexval[1], 16)
        return intval
    
    @staticmethod
    def ip6_to_int(ip6: str):
        """
        Translates an IPv6 address to an int

        :param mac: IPv6 address
        :type mac: String
        :return: A tuple of the integer values of the front and back halves
        :rtype: tuple[int, int]
        """
        ip6 = IPv6Address(ip6)
        return (int(ip6)//(2**64),int(ip6)%(2**64))
    
    def trace_ping(self, src_ip: str, dst_ip: str, iface_name: str = "", iface: Interface = None, name: str = "trace_ping"):
        """
        Create a ping packet from src_ip to dst_ip, that will be sent into the specified
        monitored interface. This will return a graph of the history of the request as it traversed
        the network.
        """
        self.probe(f'Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src={src_ip},dst={dst_ip})/ICMP()',
                   iface_name=iface_name, iface=iface, name=name)
    
    def probe(self, scapy: str, iface_name: str = "", iface: Interface = None, name: str = "probe"):
        """
        Send a packet, formed from the given scapy definition and appended with a unique id,
        into the targeted interface then download the graph of its traversal across
        the network.

        :param scapy: Scapy definition the packet will be crafted from, as a string
        :type scapy: String
        :param iface_name: The name of the interface to target with the packet
        :type iface_name: String
        :param iface: An interface to target with the packet
        :param name: The name of the downloaded graph
        :type name: String
        """
        if iface_name == "" and iface is not None:
            iface_name = iface.get_name()
        else:
            raise Exception("Exception: Either iface_name or iface must not be empty")
        
        net = self.get_interface(name=iface_name).get_network()
        net_name = net.get_name()
        if not net_name.startswith(f'{self.prefix}_net_'):
            raise Exception("Exception: interface must be part of a monitored network")
        
        orig_net_name = self.get_orig_net_name(net)
        monitor = None
        if orig_net_name == "":
            ifaces = net.get_interfaces()
            for net_iface in ifaces:
                node_name = net_iface.get_node().get_name()
                if node_name.startswith(f"{self.prefix}_monitor_"):
                    monitor = self.get_monitor(node_name)
        else:
            monitor = self.monitors[orig_net_name]
        
        port = monitor.data.iface_mappings[iface_name][3]
        dev_name = monitor.data.iface_mappings[iface_name][1].get_device_name()
        if port == 1:
            port = 2
        else:
            port = 1
        scapy = scapy.replace('"', '\\"')
        scapy = scapy.replace("'", "\\'")
        # uid_trailer[1] = (mon_id << 48) + (port << 32) + ((uid_trailer[0] << 16) & 0x00000000FFFF0000) + MONPROT;
        uid = (self.probe_id << 64) + (monitor.data.monitor_id << 48) + (port << 32) + ((self.probe_id << 16) & 0x00000000FFFF0000) + MONPROT
        self.probe_id += 1
        new_scapy = f'Raw({scapy})/Raw(int({uid}).to_bytes(16, \\"big\\"))'
        monitor.execute(f'''echo -e "from scapy.all import *\npkt={new_scapy}\nsendp(pkt, iface='{dev_name}')\n" | sudo python3''')
        self.get_graph(name=name, pkt_id=uid)

    def dump_counters(self) -> dict[str, dict[str, tuple[str, int, int]]]:
        """
        Runs through each non-crinkle Node, gets the rx_packets and tx_packets count for
        each interface, then returns a dict of form dict[node name, dict[iface name, (dev name, rx, tx)]].
        """
        rdict: dict[str, dict[str, tuple[str, int, int]]] = {}
        for node in self.get_non_crinkle_nodes():
            if node.get_image() in UBUNTU_IMAGES:
                nodename = node.get_name()
                for iface in node.get_interfaces():
                    ifacename = iface.get_name()
                    devname = iface.get_device_name()
                    stdout, _ = node.execute(f"cat /sys/class/net/{devname}/statistics/rx_packets && cat /sys/class/net/{devname}/statistics/tx_packets")
                    counters = stdout.splitlines()
                    rx = int(counters[0])
                    tx = int(counters[1])
                    rdict[nodename][ifacename] = (devname, rx, tx)
        return rdict

    def list_counters(self,
                      output=None,
                      fields=None,
                      filter_function=None,
                      quiet=False,
                      pretty_names=True):
        table = []
        counter_dict = self.dump_counters()

        pretty_names_dict = {}
        if pretty_names:
            pretty_names_dict = {
                "node_name": "Node Name",
                "interface": "Interface",
                "dev_name": "Device Name",
                "rx_pkts": "RX Packets",
                "tx_pkts": "TX Packets"
            }

        for nodename, nodedict in counter_dict.items():
            for ifacename, ifacetuple in nodedict.items():
                rowdict = {"node_name": nodename,
                           "interface": ifacename,
                           "dev_name": ifacetuple[0],
                           "rx_pkts": ifacetuple[1],
                           "tx_pkts": ifacetuple[2]}
                table.append(rowdict)

        table = sorted(table, key=lambda x: (x["Node Name"], x["Interface"]))

        table = self.get_fablib_manager().list_table(
            table,
            fields=fields,
            title="Interface Counters",
            output=output,
            quiet=True,
            filter_function=filter_function,
            pretty_names_dict=pretty_names_dict
        )

        if table and not quiet:
            display(table)

        return table


    @staticmethod
    def ip_net_like(net: str):
        """
        Not intended for API use. Transforms IPv4 subnets into LIKE terms for SPADE.

        :param net: The IPv4 subnet, either of the form X.0.0.0/8, X.Y.0.0/16, X.Y.Z.0/24,
            or X, X.Y, X.Y.Z
        :type net: String
        :return: the LIKE term for SPADE
        :rtype: String
        """
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
                

    def get_graph(self, name: str = "graph", filterin: str = None, tstart = None, tend = None, tformat="epoch", pkt_id = None, quiet=True):
        """
        Produce and download a graph of the data stored in the analyzer's SPADE database,
        filtered using the given arguments.

        :param name: The name of the downloaded graph, default "graph".
        :type name: String
        :param filterin: A tcpdump filter (currently supports ip, tcp, udp, icmp) to filter flows in the graph on
        :type filterin: String
        :param tstart: A time filter, such that the returned graph is for all packets with time >= tstart. Default off
        :type tstart: int
        :param tend: A time filter, such that the returned graph is for all packets with time <= tend. Default off
        :type tend: int
        :param pkt_id: Only return packets matching the id
        :type pkt_id: int
        :param quiet: If True, suppresses SPADE query output and just returns the graph
        :type quiet: bool
        """
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
                    if i + 1 < len(filter_words):
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
        time_filter = ""
        if tformat != "epoch":
            if tstart:
                tstart: datetime = datetime.strptime(tstart, tformat)
                tstart = tstart.timestamp() * 1000000
            elif tend:
                tend: datetime = datetime.strptime(tend, tformat)
                tend = tend.timestamp() * 1000000
        if tstart and tend:
            time_filter += f'''(\\"epoch\\" >= '{tstart}' and \\"epoch\\" <= '{tend}')'''
        elif tstart:
            time_filter += f'''(\\"epoch\\" >= '{tstart}')'''
        elif tend:
            time_filter += f'''(\\"epoch\\" <= '{tstart}')'''
        graph_build = ""
        if pkt_id:
            graph_build += f'''\\$graph0 = \\$base.getPath(\\$base.getEdge(\\"pkt_id\\" == '{pkt_id}').limit(1000).getEdgeEndpoints(), \\$base.getVertex(\\"type\\" == 'Agent'), 1) + \\$base.getEdge(\\"pkt_id\\" == '{pkt_id}').limit(1000) + \\$base.getEdge(\\"pkt_id\\" == '{pkt_id}').limit(1000).getEdgeEndpoints()\n'''
        else:
            graph_build += '''\\$graph0 = \\$base\n'''
        if time_filter != "":
            graph_build += f'''\\$graph1 = \\$graph0.getPath(\\$graph0.getEdge({time_filter}).limit(1000).getEdgeEndpoints(), \\$graph0.getVertex(\\"type\\" == 'Agent'), 1) + \\$graph0.getEdge({time_filter}).limit(1000) + \\$graph0.getEdge({time_filter}).limit(1000).getEdgeEndpoints()\n'''
        else:
            graph_build += '''\\$graph1 = \\$graph0\n'''
        graph_build += f'''\\$graph2 = \\$graph1.getLineage(\\$graph1.getVertex({spade_filter}), 1, 'b')\n\\$graph3 = \\$graph2 + \\$base.getPath(\\$graph2.getVertex(\\"type\\" == 'Process'), \\$base.getVertex(\\"type\\" == 'Agent'), 1)'''
        self.analyzer.execute(f'echo -e "set storage Neo4j\n{graph_build}\nexport > /home/ubuntu/{REMOTEWORKDIR}/{name}.dot\ndump all \\$graph3" | ./{REMOTEWORKDIR}/SPADE/bin/spade query; '
                                f'dot -Tsvg {REMOTEWORKDIR}/{name}.dot -o {REMOTEWORKDIR}/{name}.svg', quiet=quiet)
        self.analyzer.download_file(f'{name}.svg', f'{REMOTEWORKDIR}/{name}.svg')

    def reset_monitor_string(self):
        logging.info("Crinkle tried to start with blank monitor string, regenerating it")
        self.monitor_string = f"{self.analyzer_iface.get_device_name()} "
        for monitor in self.monitors.values():
            self.monitor_string += f'{monitor.data.monitor_id} '
            for iface_name, (_, _, _, num) in monitor.data.iface_mappings.items():
                self.monitor_string += f'{num}@{iface_name} '
        self.monitor_string = self.monitor_string.rstrip()

    def reset_analyzer(self, quiet: bool = True):
        """
        Reset the analyzer, wiping the database.
        """
        if self.monitor_string == '':
            self.reset_monitor_string()
        self.analyzer.execute(f'''sudo killall python3; echo -e "remove storage Neo4j\n" | ./{REMOTEWORKDIR}/SPADE/bin/spade control; rm -rf {REMOTEWORKDIR}/spade_database/; echo -e "add storage Neo4j database=/home/ubuntu/{REMOTEWORKDIR}/spade_database\n" | ./{REMOTEWORKDIR}/SPADE/bin/spade control''', quiet=quiet)
        self.analyzer.execute_thread(f'sudo ./{REMOTEWORKDIR}/spade_reader.py {self.monitor_string}')
    
    def start_monitor(self, monitor: CrinkleMonitor, wait: bool=True, quiet: bool=False) -> futures.Future | None:
        """
        Start the DPDK script on a monitor.

        :param monitor: The monitor node to target
        :type monitor: CrinkleMonitor
        :param wait: Whether this call is blocking, default True
        :type wait: bool
        :param quiet: Whether to print stdout/stderr of a blocking call, default False
        :type quiet: bool
        :return: The future of a non-blocking call, or None
        :rtype: concurrent.futures.Future
        """
        if monitor is None:
            raise Exception("Monitor cannot be None")
        logging.info(f"Starting Crinkle monitor {monitor.data.net_name}")
        job = None
        if wait:
            monitor.execute(f"sudo ./{REMOTEWORKDIR}/{DPDKNAME} -- {monitor.data.cmd_args} &", quiet=quiet)
        else:
            job = monitor.execute_thread(f"sudo ./{REMOTEWORKDIR}/{DPDKNAME} -- {monitor.data.cmd_args}")
        return job
        
    def start_all_monitors(self, wait: bool=True, no_return: bool=True) -> list[futures.Future] | None:
        """
        Start the DPDK script on all monitors.

        :param wait: Whether this call is blocking, default True
        :type wait: bool
        :param no_return: Whether to return None instead of the list of jobs
        :type no_return: bool
        :return: The futures of all started jobs
        :rtype: list[concurrent.futures.Future]
        """
        start_list: list[futures.Future] = []
        for monitor in self.monitors.values():
            start_list.append(self.start_monitor(monitor=monitor, wait=False))
        if wait:
            logging.info(f"Waiting for monitors to finish starting")
            ctr = 0
            max = len(start_list)
            while ctr < max:
                if start_list[ctr].running():
                    ctr += 1
                    logging.info(f'{ctr}/{max} started')
        if (no_return):
            return
        return start_list

    def stop_monitor(self, monitor: CrinkleMonitor):
        if monitor is None:
            raise Exception("monitor cannot be None")
        monitor.execute(f"sudo killall {DPDKNAME}")

    def stop_all_monitors(self):
        for monitor in self.monitors.values():
            self.stop_monitor(monitor=monitor)

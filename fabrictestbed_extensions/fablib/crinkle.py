import os
import shutil
import queue
import ipaddress
import datetime
import enum
import logging
from typing import TYPE_CHECKING

from fim.user import Labels, NodeType

from fabrictestbed_extensions.fablib.slice import Slice
from fabrictestbed_extensions.fablib.node import Node
from fabrictestbed_extensions.fablib.switch import Switch
from fabrictestbed_extensions.fablib.component import Component
from fabrictestbed_extensions.fablib.network_service import NetworkService
from fabrictestbed_extensions.fablib.interface import Interface
from fabrictestbed.slice_editor import ExperimentTopology
from ipaddress import IPv4Address, ip_address

if TYPE_CHECKING:
    from fabric_cf.orchestrator.swagger_client import (
        Slice as OrchestratorSlice,
        Sliver as OrchestratorSliver,
    )
    from fabrictestbed_extensions.fablib.fablib import FablibManager

from fabrictestbed.slice_editor import Node as FimNode

from concurrent import futures

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

class CrinkleAnalyzer(Node):
    default_image = "default_ubuntu_24"

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

    default_image = "default_ubuntu_24"
    default_cores = 2
    default_ram = 2
    default_disk = 10

    class MonitorData():
        def __init__(
            self
        ):
            self.port_nums: int = 0
            self.port_sequence: str = None
            self.net_name: str = None
            self.net_type: str = None
            self.cnet_iface: Interface = None
            self.iface_mappings: dict[Interface, tuple[str, Interface]] = {}

    def __init__(
        self,
        slice: Slice,
        node: FimNode,
        validate: bool = False,
        raise_exception: bool = False,
    ):
        super().__init__(slice=slice, node=node, validate=validate, raise_exception=raise_exception)
        self.data = self.MonitorData()
        self.creation_data = list[tuple[str, str, str]] = [] # see MonNetData

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
        if "monitor_config" in self.get_user_data():
            self.data = self.get_user_data()["monitor_config"]
        else:
            self.data = self.MonitorData()
        
    def set_monitor_data(self):
        """
        Set monitor-specific data.
        """
        user_data = self.get_user_data()
        user_data["monitor_config"] = self.data
        self.set_user_data(user_data=user_data)
    
class CrinkleSlice(Slice):
    def __init__(
            self,
            fablib_manager: FablibManager,
            slice_name: str = None,
            user_only: bool = True,
            pcaps_dir: str = None,
            name_prefix: str = None
    ):
        super().__init__(fablib_manager=fablib_manager, slice_name=slice_name, user_only=user_only)
        self.monitors: dict[str, CrinkleMonitor] = {}
        self.analyzer: CrinkleAnalyzer = None
        self.analyzer_name: str = None
        self.cnets: dict[str, NetworkService] = {}
        self.analyzer_cnet: NetworkService = None
        self.pcaps_dir = pcaps_dir
        self.prefix = name_prefix

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
        pcaps_dir: str = None,
        name_prefix: str = None
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

        return slice
    
    def add_analyzer(
            self,
            name: str = "C_analyzer",
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
            name=name,
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
        if self.cnets[analyzer_site] is None:
            self.cnets[analyzer_site] = self.add_l3network(name=f"{self.prefix}_net_{site}", type="IPv6")
        cnet = self.cnets[analyzer_site]
        analyzer_iface = self.analyzer.add_component(model="NIC_Basic",
                                                     name=f"{self.prefix}_nic_{self.analyzer_name}_{site}").get_interfaces()[0]
        analyzer_iface.set_mode("auto")
        cnet.add_interface(analyzer_iface)
        self.analyzer.add_route(subnet=FablibManager.FABNETV6_SUBNET, next_hop=cnet.get_gateway())

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
        
        if self.cnets[site] is None:
            self.cnets[site] = self.add_l3network(name=f"{self.prefix}_net_{site}", type="IPv6")
        cnet = self.cnets[site]
        monitor_cnet_iface = monitor.add_component(model="NIC_Basic",
                                                   name=f"{self.prefix}_nic_{net_name}_monitor_{site}").get_interfaces()[0]
        monitor_cnet_iface.set_mode("auto")
        monitor.add_route(subnet=self.analyzer_cnet.get_subnet(), next_hop=cnet.get_gateway())
        monitor.data.cnet_iface = monitor_cnet_iface
        monitor.data.net_name = net_name
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
        monitor = self.add_monitor(name=f"{name}_monitor", site=monitor_site, net_name=name)

        if type == "L2Bridge":
            for iface in interfaces:
                iface_node_name = iface.get_node().get_name()
                monitor_iface = monitor.add_component("NIC_Basic", f"monitor_{iface_node_name}").get_interfaces()[0]
                self.add_l2network(f"{name}-{iface_node_name}", [iface, monitor_iface], "L2Bridge", subnet, gateway, user_data)
                monitor.data.net_type = type
                monitor.creation_data.append((iface_node_name, iface.get_name(), f"monitor_{iface_node_name}"))
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
    ) -> str:
        super().submit(wait=wait, wait_timeout=wait_timeout, wait_interval=wait_interval, progress=progress, wait_jupyter=wait_jupyter, post_boot_config=post_boot_config, wait_ssh=wait_ssh,
                       extra_ssh_keys=extra_ssh_keys, lease_start_time=lease_start_time, lease_end_time=lease_end_time, lease_in_hours=lease_in_hours, validate=validate)
        self.analyzer = self.get_node(name=self.analyzer_name)
        site = self.analyzer.get_site()
        self.analyzer_cnet = self.get_l3network(name=f"C_network_{site}")
        self.cnets[site]=self.analyzer_cnet

        for key, monitor in self.monitors.items():
            refreshed_monitor = self.get_monitor(monitor.get_name())
            refreshed_monitor.get_monitor_data()
            mon_site = refreshed_monitor.get_site()
            refreshed_monitor.upload_file_thread(f"{LOCALP4DIR}/base-crinkle.p4", f"{REMOTEWORKDIR}/base-crinkle.p4")
            if not self.cnets[mon_site].is_instantiated():
                self.cnets[mon_site] = self.get_l3network(name=f"{self.prefix}_net_{mon_site}")
            refreshed_monitor.data.cnet_iface = refreshed_monitor.get_interface(network_name=f"{self.prefix}_net_{mon_site}")
            for data in monitor.creation_data:
                iface = self.get_node(name=data[MonNetData.NODENAME]).get_interface(name=data[MonNetData.IFACENAME])
                mon_iface = refreshed_monitor.get_component(name=data[MonNetData.MIFACENAME]).get_interfaces()[0]
                refreshed_monitor.data.iface_mappings[iface] = (data[MonNetData.NODENAME], mon_iface)
                refreshed_monitor.data.port_sequence += f"-i{refreshed_monitor.data.port_nums}@{mon_iface.get_device_name()}"
                refreshed_monitor.data.port_nums += 1
            self.monitors[key] = refreshed_monitor
            del monitor
            refreshed_monitor.set_monitor_data()
        
    def start_bmv2(self, monitor: CrinkleMonitor, wait: bool=True):
        command = (f'p4c --target bmv2 --arch v1model {REMOTEWORKDIR}/base-crinkle.p4;'
                   f'nohup bash -c "sudo simple_switch {monitor.data.port_sequence} base-crinkle.json --log-file ~/monitor.log --log-flush -- --enable-swap" &')
        job = None
        if wait:
            monitor.execute(command=command)
        else:
            job = monitor.execute_thread(command=command)
        return job
    
    def start_monitor(self, monitor: CrinkleMonitor, wait: bool=True) -> tuple[list[futures.Future], futures.Future]:
        if monitor is None:
            raise Exception("Monitor cannot be None")
        tcpdumps: list[futures.Future] = []
        for _, (iface_node_name, mon_iface) in monitor.data.iface_mappings.items():
            logging.info(f"Starting Monitor for network {monitor.get_name()} ")
            mon_iface_name = mon_iface.get_device_name()
            tcpdumps.append(monitor.execute_thread(command=f"sudo tcpdump -vvvxxen -i {mon_iface_name} -w {monitor.data.net_name}/{iface_node_name}.pcap"))
        bmv2_start = self.start_bmv2(monitor=monitor, wait=False)
        if wait:
            tcpdumps2: list[futures.Future] = []
            for tcpdump in tcpdumps:
                if not tcpdump.running():
                    tcpdumps2.append(tcpdump)
            logging.info(f"Waiting for {monitor.data.net_name} monitor to finish starting tcpdump processes ")
            iteration = len(tcpdumps2)
            count = 0
            while len(tcpdumps2) > 0:
                if tcpdumps2[-1].running():
                    tcpdumps2.pop()
                if count == iteration:
                    logging.info(f"Waiting for {monitor.data.net_name} monitor to finish starting tcpdump processes ")
                    count = 0
                count += 1
            logging.info(f"Waiting for {monitor.data.net_name} monitor to finish starting bmv2 processes ")
            futures.wait(bmv2_start)
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
            tcpdumps2: list[futures.Future] = []
            for tcpdump in tcpdumps:
                if not tcpdump.running():
                    tcpdumps2.append(tcpdump)
            logging.info(f"Waiting for monitors to finish starting tcpdump processes ")
            iteration = len(tcpdumps2)
            count = 0
            while len(tcpdumps2) > 0:
                if tcpdumps2[-1].running():
                    tcpdumps2.pop()
                if count == iteration:
                    logging.info(f"Waiting for monitors to finish starting tcpdump processes ")
                    count = 0
                count += 1
            logging.info(f"Waiting for monitors to finish starting bmv2 processes ")
            futures.wait(bmv2_list)
        return tcpdumps

    def stop_monitor(self, monitor: CrinkleMonitor):
        if monitor is None:
            raise Exception("mon_net cannot be None")
        monitor.execute("sudo killall tcpdump")

    def stop_all_monitors(self):
        for monitor in self.monitors.values():
            self.stop_monitor(monitor=monitor)

    def retrieve_pcaps(self, monitor: CrinkleMonitor):
        if monitor is None:
            raise Exception("mon_net cannot be None")
        shutil.rmtree(f"{self.pcaps_dir}/{monitor.data.net_name}/.", True)
        monitor.download_directory(f"{self.pcaps_dir}/{monitor.data.net_name}", remote_directory_path=f"/home/ubuntu/{monitor.data.net_name}")
        self.analyzer.execute(f"sudo rm -rf {PCAPDIR}/{monitor.data.net_name}")
        self.analyzer.upload_directory(f"{self.pcaps_dir}/{monitor.data.net_name}", f"{PCAPDIR}/{monitor.data.net_name}")

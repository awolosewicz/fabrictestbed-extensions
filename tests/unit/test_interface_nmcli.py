"""Unit tests for the single-round-trip nmcli configuration path.

``Interface._config_nmcli`` and its supporting string-builder helpers on
``Node`` build a full sequence of nmcli commands and issue them as one
chained SSH command instead of one round trip per step. These tests drive
``_config_nmcli`` against lightly mocked ``Interface``/``Node``/network
objects (constructed via ``__new__`` to skip real ``__init__`` wiring) so
the *real* string-builder implementations run and we can assert on the
shape of the single command that gets executed.
"""

import unittest
from unittest.mock import MagicMock

import pytest
from fabrictestbed.slice_editor import ServiceType

from fabrictestbed_extensions.fablib.interface import Interface

# node.py has a module-level import (SliverDTO from
# fabrictestbed.external_api.orchestrator_client) that only exists in
# fabrictestbed>=2.0.7 (see pyproject.toml). Environments pinned to an
# older fabrictestbed (e.g. 1.8.1) fail to import fabrictestbed_extensions
# .fablib.node at all; skip this module there rather than erroring out the
# whole test collection.
try:
    from fabrictestbed_extensions.fablib.node import Node

    _NODE_IMPORT_ERROR = None
except ImportError as e:  # pragma: no cover - environment dependent
    Node = None
    _NODE_IMPORT_ERROR = e

pytestmark = pytest.mark.skipif(
    Node is None,
    reason=f"fabrictestbed_extensions.fablib.node unimportable in this env: {_NODE_IMPORT_ERROR}",
)


def _make_node():
    """A Node instance with only the bits _config_nmcli's command builders
    touch mocked out; the real string-builder methods run unmodified."""
    node = Node.__new__(Node)
    node.execute = MagicMock(return_value=("", ""))
    node._nm_conn_name = MagicMock(return_value="fabric-enp7s0")
    node._detect_ip_version_for_interface = MagicMock(return_value="ipv4")
    return node


def _make_interface(device_name="enp7s0", vlan=None, physical_iface="enp7s0"):
    iface = Interface.__new__(Interface)
    iface.get_device_name = MagicMock(return_value=device_name)
    iface.get_vlan = MagicMock(return_value=vlan)
    iface.get_physical_os_interface_name = MagicMock(return_value=physical_iface)
    return iface


class TestConfigNmcliSingleRoundTrip(unittest.TestCase):
    """_config_nmcli should issue exactly one node.execute() call."""

    def test_l2_network_single_execute_call(self):
        node = _make_node()
        iface = _make_interface()

        network = MagicMock()
        network.get_type.return_value = ServiceType.L2Bridge
        network.get_gateway.return_value = None

        iface._config_nmcli(node, network, addr="192.168.1.5", subnet="192.168.1.0/24")

        node.execute.assert_called_once()
        (command,), kwargs = node.execute.call_args
        self.assertTrue(kwargs.get("quiet"))
        self.assertNotIn("timeout", kwargs)

        self.assertIn("nmcli c add", command)
        self.assertIn("2>/dev/null || sudo nmcli c mod", command)
        # Steps are chained with " ; " rather than "&&" so each step is
        # independent (execute() never raises on non-zero exit anyway).
        self.assertIn(" ; ", command)
        self.assertNotIn("&&", command)
        # L2 branch: never-default yes, no PBR/fabnet route logic.
        self.assertIn("never-default yes", command)
        self.assertIn("ipv6.method disabled", command)
        self.assertIn("rp_filter=2", command)

    def test_fabnetv4_ext_single_execute_call_with_pbr_conditional(self):
        node = _make_node()
        iface = _make_interface()

        network = MagicMock()
        network.get_type.return_value = ServiceType.FABNetv4Ext
        network.get_gateway.return_value = "192.168.1.1"

        iface._config_nmcli(node, network, addr="192.168.1.5", subnet="192.168.1.0/24")

        node.execute.assert_called_once()
        (command,), kwargs = node.execute.call_args
        self.assertTrue(kwargs.get("quiet"))
        self.assertNotIn("timeout", kwargs)

        self.assertIn("nmcli c add", command)
        self.assertIn("2>/dev/null || sudo nmcli c mod", command)
        self.assertIn(" ; ", command)

        # PBR branch is a single shell conditional probing the management
        # default route, replacing the old separate probe round trip.
        self.assertIn("if [ -n", command)
        self.assertIn("else", command)
        self.assertIn("fi", command)
        self.assertIn("route-table", command)
        self.assertIn("routing-rules", command)

    def test_vlan_interface_uses_vlan_connection_type(self):
        node = _make_node()
        iface = _make_interface(device_name="enp7s0.100", physical_iface="enp7s0")
        iface.get_vlan = MagicMock(return_value="100")

        network = MagicMock()
        network.get_type.return_value = ServiceType.L2Bridge
        network.get_gateway.return_value = None

        iface._config_nmcli(node, network, addr="10.0.0.5", subnet="10.0.0.0/24")

        node.execute.assert_called_once()
        (command,), _ = node.execute.call_args
        self.assertIn("type vlan", command)
        self.assertIn("dev enp7s0 id 100", command)


class TestNmcliStringBuilders(unittest.TestCase):
    """Direct tests of the Node string-builder helpers used above."""

    def test_ensure_connection_cmd_add_or_mod(self):
        node = Node.__new__(Node)
        cmd = node._nmcli_ensure_connection_cmd(
            conn_name="fabric-enp7s0",
            ifname="enp7s0",
            ip_version="ipv4",
            addresses="10.0.0.5/24",
        )
        self.assertIn("sudo nmcli c add type ethernet ifname enp7s0", cmd)
        self.assertIn("2>/dev/null || sudo nmcli c mod fabric-enp7s0", cmd)

    def test_fabnet_route_cmds_joined_with_semicolon(self):
        node = Node.__new__(Node)
        cmd = node._nmcli_fabnet_route_cmds(
            conn_name="fabric-enp7s0",
            ip_version="ipv4",
            gateway="10.128.0.1",
            network_type=ServiceType.FABNetv4,
        )
        self.assertIn("never-default yes", cmd)
        self.assertIn("10.128.0.0/10 10.128.0.1", cmd)
        self.assertIn(" ; ", cmd)
        self.assertNotIn("&&", cmd)

    def test_pbr_cmds_conditional_shape(self):
        node = Node.__new__(Node)
        cmd = node._nmcli_pbr_cmds(
            conn_name="fabric-enp7s0",
            ip_version="ipv4",
            addr="192.168.1.5",
            prefix="24",
            gateway="192.168.1.1",
            subnet="192.168.1.0/24",
        )
        self.assertTrue(cmd.startswith("if [ -n \"$(ip -4 route show default"))
        self.assertIn("; else ", cmd)
        self.assertTrue(cmd.rstrip().endswith("; fi"))


if __name__ == "__main__":
    unittest.main()

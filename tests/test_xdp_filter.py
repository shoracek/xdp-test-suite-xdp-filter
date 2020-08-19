import subprocess
import time
import os
import signal

import unittest

from scapy.all import (Ether, Packet, IP, IPv6, Raw,
                       UDP, TCP, IPv6ExtHdrRouting)

from harness.xdp_case import XDPCase, usingCustomLoader
from harness.utils import XDPFlag

XDP_FILTER_EXEC = "progs/xdp-filter-exec.sh"


def get_mode_string(xdp_mode: XDPFlag):
    if xdp_mode == XDPFlag.SKB_MODE:
        return "skb"
    if xdp_mode == XDPFlag.DRV_MODE:
        return "native"
    if xdp_mode == XDPFlag.HW_MODE:
        return "hw"
    return None


@usingCustomLoader
class LoadUnload(XDPCase):
    def setUp(self):
        self.msg = "WARNING: All tests that follow will likely provide false result.\n"

    def run_wrap(self, cmd):
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.msg += "command: '" + str(cmd) + "'\n"
        self.msg += "stdout: '" + r.stdout.decode().strip() + "'\n"
        if r.stderr is not None:
            self.msg += "stderr: '" + r.stderr.decode().strip() + "'\n"
        self.msg += "\n"
        return r.returncode == 0

    def load(self, mode=None):
        return self.run_wrap([
            XDP_FILTER_EXEC, "load",
            self.get_contexts().get_local_main().iface,
            "--verbose",
            "--mode", get_mode_string(
                mode if mode else self.get_contexts().get_local_main().xdp_mode
            )
        ])

    def unload(self):
        return self.run_wrap([
            XDP_FILTER_EXEC, "unload",
            self.get_contexts().get_local_main().iface,
            "--verbose"
        ])

    def test_load_once(self):
        self.assertFalse(self.unload(), self.msg)
        self.assertTrue(self.load(), self.msg)
        self.assertTrue(self.unload(), self.msg)
        self.assertFalse(self.unload(), self.msg)

    def test_load_twice(self):
        self.assertFalse(self.unload(), self.msg)
        self.assertTrue(self.load(), self.msg)
        self.assertFalse(self.load(), self.msg)
        self.assertTrue(self.unload(), self.msg)
        self.assertFalse(self.unload(), self.msg)

    def test_load_hw(self):
        self.assertFalse(self.unload(), self.msg)
        self.load(mode=XDPFlag.HW_MODE), self.msg
        self.unload(), self.msg
        self.assertFalse(self.unload(), self.msg)


@usingCustomLoader
class Base(XDPCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.src_port = 60001
        cls.dst_port = 60002
        cls.to_send = cls.generate_default_packets(
            src_port=cls.src_port, dst_port=cls.dst_port)
        cls.to_send6 = cls.generate_default_packets(
            src_port=cls.src_port, dst_port=cls.dst_port, use_inet6=True)

    def arrived(self, packets, result):
        self.assertPacketsIn(packets, result.captured_local)
        for i in result.captured_remote:
            self.assertPacketContainerEmpty(i)

    def not_arrived(self, packets, result):
        self.assertPacketsNotIn(packets, result.captured_local)
        for i in result.captured_remote:
            self.assertPacketContainerEmpty(i)

    def setUp(self):
        subprocess.check_output([
            XDP_FILTER_EXEC, "load",
            self.get_contexts().get_local_main().iface,
            "--mode", get_mode_string(
                self.get_contexts().get_local_main().xdp_mode
            )
        ], stderr=subprocess.STDOUT)

    def tearDown(self):
        subprocess.check_output([
            XDP_FILTER_EXEC, "unload", "--all"
        ], stderr=subprocess.STDOUT)


class DirectBase:
    def drop_generic(self, address, target, use_inet6=False):
        to_send = self.to_send6 if use_inet6 else self.to_send

        self.arrived(to_send, self.send_packets(to_send))

        subprocess.run([XDP_FILTER_EXEC, target, address,
                        "--mode", self.get_mode()])

        self.not_arrived(to_send, self.send_packets(to_send))

        subprocess.run([XDP_FILTER_EXEC, target, address,
                        "--mode", self.get_mode(),
                        "--remove"])

        self.arrived(to_send, self.send_packets(to_send))

    def test_none_specified(self):
        self.arrived(self.to_send, self.send_packets(self.to_send))

    def test_ether(self):
        self.drop_generic(self.get_device().ether, "ether")

    def test_ip(self):
        self.drop_generic(self.get_device().inet, "ip")

    def test_port(self):
        self.drop_generic(str(self.get_port()), "port")

    @unittest.skipIf(XDPCase.get_contexts().get_local_main().inet6 is None or
                     XDPCase.get_contexts().get_remote_main().inet6 is None,
                     "no inet6 address available")
    def test_ipv6(self):
        self.drop_generic(self.get_device().inet6, "ip", use_inet6=True)


class BaseSrc:
    def get_device(self):
        return self.get_contexts().get_remote_main()

    def get_port(self):
        return self.src_port

    def get_mode(self):
        return "src"


class DirectDropSrc(Base, DirectBase, BaseSrc):
    pass


class IPv6ExtensionHeader(Base):
    def test(self):
        packets = [Ether() /
                   IPv6() / IPv6ExtHdrRouting() /
                   UDP(dport=55555)] * 5

        self.arrived(packets, self.send_packets(packets))

        subprocess.run([XDP_FILTER_EXEC,
                        "port", "55555",
                        "--mode", "dst"])
        self.not_arrived(packets, self.send_packets(packets))

        subprocess.run([XDP_FILTER_EXEC,
                        "port", "55555",
                        "--mode", "dst",
                        "--remove"])
        self.arrived(packets, self.send_packets(packets))


class IPv4ToIPv6Mapping(Base):
    def setUp(self):
        super().setUp()

        inet = self.get_contexts().get_local_main().inet

        self.address_explicit = "::ffff:" + inet

        inet6_split = [format(int(i), "02x") for i in inet.split(".")]
        self.address_converted = "::ffff:" + \
            inet6_split[0] + inet6_split[1] + ":" + \
            inet6_split[2] + inet6_split[3]

        self.packets = self.generate_default_packets(
            dst_inet=self.address_explicit, use_inet6=True)
        self.packets += self.generate_default_packets(
            dst_inet=self.address_converted, use_inet6=True)

    def test_filter_explicit_address(self):
        self.arrived(self.packets, self.send_packets(self.packets))

        subprocess.run([XDP_FILTER_EXEC,
                        "ip", self.address_explicit,
                        "--mode", "dst"])
        self.not_arrived(self.packets, self.send_packets(self.packets))

        subprocess.run([XDP_FILTER_EXEC,
                        "ip", self.address_explicit,
                        "--mode", "dst",
                        "--remove"])
        self.arrived(self.packets, self.send_packets(self.packets))

    def test_filter_converted_address(self):
        self.arrived(self.packets, self.send_packets(self.packets))

        subprocess.run([XDP_FILTER_EXEC,
                        "ip", self.address_converted,
                        "--mode", "dst"])
        self.not_arrived(self.packets, self.send_packets(self.packets))

        subprocess.run([XDP_FILTER_EXEC,
                        "ip", self.address_converted,
                        "--mode", "dst",
                        "--remove"])
        self.arrived(self.packets, self.send_packets(self.packets))


class MaybeOK(Base):
    def test_add_different_modes(self):
        tcp_packets = self.generate_default_packets(
            src_port=self.src_port, dst_port=self.dst_port, layer_4="tcp")
        udp_packets = self.generate_default_packets(
            src_port=self.src_port, dst_port=self.dst_port, layer_4="udp")

        self.arrived(tcp_packets, self.send_packets(tcp_packets))
        self.arrived(udp_packets, self.send_packets(udp_packets))

        subprocess.run([XDP_FILTER_EXEC,
                        "port", str(self.src_port),
                        "--mode", "src",
                        "--proto", "tcp"])
        self.not_arrived(tcp_packets, self.send_packets(tcp_packets))
        self.arrived(udp_packets, self.send_packets(udp_packets))

        subprocess.run([XDP_FILTER_EXEC,
                        "port", str(self.src_port),
                        "--mode", "dst",
                        "--proto", "udp"])
        self.not_arrived(tcp_packets, self.send_packets(tcp_packets))
        self.arrived(udp_packets, self.send_packets(udp_packets))

    def test_remove_ignores_protocols(self):
        tcp_packets = self.generate_default_packets(
            src_port=self.src_port, dst_port=self.dst_port, layer_4="tcp")
        udp_packets = self.generate_default_packets(
            src_port=self.src_port, dst_port=self.dst_port, layer_4="udp")

        self.arrived(tcp_packets, self.send_packets(tcp_packets))
        self.arrived(udp_packets, self.send_packets(udp_packets))

        subprocess.run([XDP_FILTER_EXEC,
                        "port", str(self.dst_port),
                        "--mode", "dst",
                        "--proto", "tcp"])
        self.not_arrived(tcp_packets, self.send_packets(tcp_packets))
        self.arrived(udp_packets, self.send_packets(udp_packets))

        subprocess.run([XDP_FILTER_EXEC,
                        "port", str(self.dst_port),
                        "--mode", "dst",
                        "--proto", "udp",
                        "--remove"])
        self.not_arrived(tcp_packets, self.send_packets(tcp_packets))
        self.arrived(udp_packets, self.send_packets(udp_packets))

    def test_remove_ignores_mode_inet(self):
        self.arrived(self.to_send, self.send_packets(self.to_send))

        subprocess.run([XDP_FILTER_EXEC,
                        "ip", self.get_contexts().get_local_main().inet,
                        "--mode", "dst"])
        self.not_arrived(self.to_send, self.send_packets(self.to_send))

        subprocess.run([XDP_FILTER_EXEC,
                        "ip", self.get_contexts().get_local_main().inet,
                        "--mode", "src",
                        "--remove"])
        self.not_arrived(self.to_send, self.send_packets(self.to_send))

    def test_remove_ignores_mode_port(self):
        self.arrived(self.to_send, self.send_packets(self.to_send))

        subprocess.run([XDP_FILTER_EXEC,
                        "port", str(self.dst_port),
                        "--mode", "dst"])
        self.not_arrived(self.to_send, self.send_packets(self.to_send))

        subprocess.run([XDP_FILTER_EXEC,
                        "port", str(self.dst_port),
                        "--mode", "src",
                        "--remove"])
        self.not_arrived(self.to_send, self.send_packets(self.to_send))


class Status(Base):
    def setUp(self): 
        pass

    def load(self, features):
        return subprocess.run([
            XDP_FILTER_EXEC, "load",
            self.get_contexts().get_local_main().iface,
            "--mode", get_mode_string(
                self.get_contexts().get_local_main().xdp_mode
            ),
            "--features", features,
        ])

    def get_status(self):
        return subprocess.run(
            [XDP_FILTER_EXEC, "status"], capture_output=True
        ).stdout.decode()

    def test_ethernet_feature(self):
        self.load("ethernet")
        self.check_status("ether", self.get_contexts().get_local_main().ether)

    def test_ipv4_feature(self):
        self.load("ipv4")
        self.check_status("ip", self.get_contexts().get_local_main().inet)

    def test_udp_feature(self):
        self.load("udp")
        self.check_status("port", str(self.dst_port))

    def test_all_features(self):
        self.load("all")
        self.check_status("ether", self.get_contexts().get_local_main().ether)
        self.check_status("ip", self.get_contexts().get_local_main().inet)
        self.check_status("port", str(self.dst_port))

    def check_status(self, subcommand, address):
        self.assertEqual(self.get_status().find(address), -1)

        subprocess.run([XDP_FILTER_EXEC, subcommand, address])
        self.assertNotEqual(self.get_status().find(address), -1)

        subprocess.run([XDP_FILTER_EXEC, subcommand, address, "--remove"])
        self.assertEqual(self.get_status().find(address), -1)

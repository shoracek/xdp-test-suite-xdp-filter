import subprocess
import time
import os
import signal

import unittest

from harness.xdp_case import XDPCase, usingCustomLoader

XDP_FILTER_EXEC = "progs/xdp-filter-exec.sh"


@usingCustomLoader
class _LoadUnload(XDPCase):
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

    def load(self):
        return self.run_wrap([
            XDP_FILTER_EXEC, "load",
            self.get_contexts().get_local_main().iface,
            "--verbose"
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
            self.get_contexts().get_local_main().iface
        ], stderr=subprocess.STDOUT)

    def tearDown(self):
        subprocess.check_output([
            XDP_FILTER_EXEC, "unload", "--all"
        ], stderr=subprocess.STDOUT)


class DirectDropSrc(Base):
    def get_device(self):
        return self.get_contexts().get_remote_main()

    def get_port(self):
        return self.src_port

    def get_mode(self):
        return "src"

    def drop_generic(self, address, target, use_inet6=False):
        to_send = self.to_send6 if use_inet6 else self.to_send

        self.arrived(to_send, self.send_packets(to_send))

        subprocess.call([XDP_FILTER_EXEC, target, address,
                         "--mode", self.get_mode()])

        self.not_arrived(to_send, self.send_packets(to_send))

        subprocess.call([XDP_FILTER_EXEC, target, address,
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


class DirectPassSrc(DirectDropSrc):
    def setUp(self):
        subprocess.call([
            XDP_FILTER_EXEC, "load",
            "--policy", "deny",
            self.get_contexts().get_local_main().iface,
        ])

    arrived = DirectDropSrc.not_arrived
    not_arrived = DirectDropSrc.arrived


class DirectDropDst(DirectPassSrc):
    def get_device(self):
        return self.get_contexts().get_local_main()

    def get_port(self):
        return self.dst_port

    def get_mode(self):
        return "dst"


class DirectPassDst(DirectDropSrc):
    def setUp(self):
        subprocess.call([
            XDP_FILTER_EXEC, "load",
            "--policy", "deny",
            self.get_contexts().get_local_main().iface,
        ])

    arrived = DirectDropSrc.not_arrived
    not_arrived = DirectDropSrc.arrived

    def get_device(self):
        return self.get_contexts().get_local_main()

    def get_port(self):
        return self.dst_port

    def get_mode(self):
        return "dst"


class ManyAddresses(Base):
    def format_number(self, number,
                      delimiter, format_string,
                      part_size, parts_amount):
        splitted = []

        while number > 0:
            splitted.append(int(number % (1 << part_size)))
            number = number >> part_size

        assert(len(splitted) <= parts_amount)
        if (len(splitted) < parts_amount):
            splitted += [0] * (parts_amount - len(splitted))

        splitted.reverse()

        return delimiter.join(format(s, format_string) for s in splitted)

    def generate_addresses(self,
                           delimiter, format_string, parts_amount, full_size):
        AMOUNT = 257

        bits = parts_amount * full_size

        for gen_number in range(0, (1 << bits) - 1, int((1 << bits) / AMOUNT)):
            yield self.format_number(gen_number, delimiter,
                                     format_string, parts_amount, full_size)

    def filter_addresses(self, name,
                         delimiter, format_string, parts_amount, full_size):
        summed = 0
        for address in self.generate_addresses(delimiter, format_string,
                                               parts_amount, full_size):
            summed += 1
            subprocess.call([XDP_FILTER_EXEC, name, address, "--mode", "dst"])

        output = subprocess.check_output([XDP_FILTER_EXEC, "status"])
        self.assertGreaterEqual(len(output.splitlines()), summed)

    def get_invalid_address(self, name,
                            delimiter, format_string,
                            parts_amount, full_size):
        """
        Try to add addresses to xdp-filter,
        return address that does not get added.
        """

        last_length = subprocess.check_output([XDP_FILTER_EXEC, "status"])
        for address in self.generate_addresses(delimiter, format_string,
                                               parts_amount, full_size):
            new_length = subprocess.check_output(
                [XDP_FILTER_EXEC, name, address, "--mode", "dst", "--status"])

            if new_length == last_length:
                return address
            last_length = new_length

        return None

    def test_ip_arrive(self):
        missing = self.get_invalid_address("ip", ".", "d", 8, 4)

        if missing is None:
            return

        to_send = self.generate_default_packets(dst_inet=missing)
        res = self.send_packets(to_send)
        self.not_arrived(to_send, res)

    def test_ether_arrive(self):
        # -> seems to be only a problem in 'status'
        missing = self.get_invalid_address("ether", ":", "02x", 8, 6)

        if missing is None:
            return

        to_send = self.generate_default_packets(dst_ether=missing)
        res = self.send_packets(to_send)
        self.not_arrived(to_send, res)

    def test_port_arrive(self):
        missing = self.get_invalid_address("port", "", "d", 16, 1)

        if missing is None:
            return

        to_send = self.generate_default_packets(dst_port=missing)
        res = self.send_packets(to_send)
        self.not_arrived(to_send, res)

    def test_ip_status(self):
        self.filter_addresses("ip", ".", "d", 8, 4)

    def test_port_status(self):
        self.filter_addresses("port", "", "d", 16, 1)

    def test_ether_status(self):
        self.filter_addresses("ether", ":", "02x", 8, 6)


class ManyAddressesInverted(ManyAddresses):
    def setUp(self):
        subprocess.call([
            XDP_FILTER_EXEC, "load",
            "--policy", "deny",
            self.get_contexts().get_local_main().iface,
        ])

    arrived = DirectDropSrc.not_arrived
    not_arrived = DirectDropSrc.arrived

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
        self.msg = ""

    def get_target_interface(self):
        return self.get_contexts().get_local_main().iface

    def run_wrap(self, cmd):
        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            return True
        except subprocess.CalledProcessError as e:
            self.msg = "CAUTION!: All tests that follow will likely provide false result!. '" + \
                e.output.decode() + "'"
            return False

    def unload(self):
        return self.run_wrap([
            XDP_FILTER_EXEC, "unload",
            self.get_target_interface(),
        ])

    def load(self):
        return self.run_wrap([
            XDP_FILTER_EXEC, "load",
            self.get_target_interface(),
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
    def arrived(self, packets, captured_local, captured_remote):
        self.assertPacketsIn(packets, captured_local)
        for i in captured_remote:
            self.assertPacketContainerEmpty(i)

    def not_arrived(self, packets, captured_local, captured_remote):
        self.assertPacketsNotIn(packets, captured_local)
        for i in captured_remote:
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


class Direct(Base):
    def test_pass_none_specified(self):
        to_send = self.generate_default_packets()

        res = self.send_packets(to_send)

        self.arrived(to_send, res.captured_local, res.captured_remote)

    def generic_drop(**args):
        def inner_decor(func_to_decorate):
            def new_func(self):
                to_send = self.generate_default_packets(**args)

                func_to_decorate(self)

                res = self.send_packets(to_send)

                self.not_arrived(to_send, res.captured_local,
                                 res.captured_remote)

            return new_func
        return inner_decor

    @generic_drop()
    def test_drop_ether_src(self):
        subprocess.call([XDP_FILTER_EXEC, "ether",
                         self.get_contexts().get_remote_main().ether,
                         "--mode", "src"])

    @generic_drop()
    def test_drop_ether_dst(self):
        subprocess.call([XDP_FILTER_EXEC, "ether",
                         self.get_contexts().get_local_main().ether,
                         "--mode", "dst"])

    @generic_drop()
    def test_drop_ip_src(self):
        subprocess.call([XDP_FILTER_EXEC, "ip",
                         self.get_contexts().get_remote_main().inet,
                         "--mode", "src"])

    @generic_drop()
    def test_drop_ip_dst(self):
        subprocess.call([XDP_FILTER_EXEC, "ip",
                         self.get_contexts().get_local_main().inet,
                         "--mode", "dst"])

    @generic_drop(src_port=60000)
    def test_drop_port_src(self):
        subprocess.call([XDP_FILTER_EXEC, "port",
                         "60000",
                         "--mode", "src"])

    @generic_drop(dst_port=60000)
    def test_drop_port_dst(self):
        subprocess.call([XDP_FILTER_EXEC, "port",
                         "60000",
                         "--mode", "dst"])

    @generic_drop()
    def test_drop_ipv4_to_ipv6_mapped(self):
        subprocess.call([XDP_FILTER_EXEC, "ip",
                         "::ffff:" + self.get_contexts().get_local_main().inet,
                         "--mode", "dst"])

    @unittest.skipIf(XDPCase.get_contexts().get_local_main().inet6 is None or
                     XDPCase.get_contexts().get_remote_main().inet6 is None,
                     "no inet6 address available")
    @generic_drop(use_inet6=True)
    def test_drop_ipv6_dst(self):
        subprocess.call([XDP_FILTER_EXEC, "ip",
                         self.get_contexts().get_local_main().inet6,
                         "--mode", "dst"])


class DirectInverted(Direct):
    def setUp(self):
        subprocess.call([
            XDP_FILTER_EXEC, "load",
            "--policy", "deny",
            self.get_contexts().get_local_main().iface,
        ])

    arrived = Direct.not_arrived
    not_arrived = Direct.arrived


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

    def much_generic(self, bits, name,
                     delimiter, format_string, parts_amount, full_size):
        AMOUNT = 257

        summed = 0
        for gen_number in range(0, (1 << bits) - 1, int((1 << bits) / AMOUNT)):
            summed += 1
            subprocess.call([
                XDP_FILTER_EXEC, name,
                self.format_number(gen_number, delimiter,
                                   format_string, parts_amount, full_size),
                "--mode", "dst"])

        output = subprocess.check_output([XDP_FILTER_EXEC, "status"])
        self.assertGreaterEqual(len(output.splitlines()), summed)

    def test_much_ip(self):
        self.much_generic(32, "ip", ".", "d", 8, 4)

    def test_much_port(self):
        self.much_generic(16, "port", "", "d", 16, 1)

    def test_much_ether(self):
        self.much_generic(48, "ether", ":", "02x", 8, 6)

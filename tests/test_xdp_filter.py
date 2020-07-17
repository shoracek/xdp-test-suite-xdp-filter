import subprocess
import time
import os
import signal

import unittest

from harness.xdp_case import XDPCase, usingCustomLoader

XDP_FILTER_EXEC = "progs/xdp-filter-exec.sh"


@usingCustomLoader
class LoadUnload(XDPCase):
    def setUp(self):
        self.msg = ""

    def get_target_interface(self):
        return self.get_contexts().get_local_main().iface

    def safeish(self, cmd):
        test = None
        try:
            test = subprocess.check_output(cmd, stderr=subprocess.STDOUT)

            self.msg = "TODO?"
            return 0
        except subprocess.CalledProcessError as e:
            self.msg = "'" + e.output.decode() + "'"
            return e.returncode

    def unload(self):
        return self.safeish([
            XDP_FILTER_EXEC, "unload",
            self.get_target_interface()
        ])

    def load(self):
        return self.safeish([
            XDP_FILTER_EXEC, "load",
            self.get_target_interface(), "--mode", "skb"
        ])

    def test_load_once(self):
        self.assertNotEqual(self.unload(), 0, "zeroth unload " + self.msg)
        self.assertEqual(self.load(), 0, "first load " + self.msg)
        self.assertEqual(self.unload(), 0, "first unload " + self.msg)
        self.assertNotEqual(self.unload(), 0, "second unload " + self.msg)

    def test_load_twice(self):
        self.assertNotEqual(self.unload(), 0, "zeroth unload " + self.msg)
        self.assertEqual(self.load(), 0, "first load " + self.msg)
        self.assertNotEqual(self.load(), 0, "second load " + self.msg)
        self.assertEqual(self.unload(), 0, "first unload " + self.msg)
        self.assertNotEqual(self.unload(), 0, "second unload " + self.msg)


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
        subprocess.call([
            XDP_FILTER_EXEC, "load",
            self.get_contexts().get_local_main().iface
        ])

    def tearDown(self):
        subprocess.call([
            XDP_FILTER_EXEC, "unload", "--all",
        ])


class Direct(Base):
    def test_pass_ip_none_specified(self):
        to_send = self.generate_default_packets()

        res = self.send_packets(to_send)

        self.arrived(to_send, res.captured_local, res.captured_remote)

    def test_drop_ip(self):
        to_send = self.generate_default_packets()

        subprocess.call([XDP_FILTER_EXEC, "ip",
                         self.get_contexts().get_remote_main().inet,
                         "--mode", "src"])

        res = self.send_packets(self.generate_default_packets())

        self.not_arrived(to_send, res.captured_local, res.captured_remote)

    def test_drop_ip_dst(self):
        to_send = self.generate_default_packets()

        subprocess.call([XDP_FILTER_EXEC, "ip",
                         self.get_contexts().get_local_main().inet,
                         "--mode", "dst"])

        res = self.send_packets(to_send)

        self.not_arrived(to_send, res.captured_local, res.captured_remote)

    def test_drop_port_2(self):
        to_send = self.generate_default_packets()

        subprocess.call([XDP_FILTER_EXEC, "port",
                         str(1 << 16), "--mode", "src"])

        res = self.send_packets(to_send)

        self.arrived(to_send, res.captured_local, res.captured_remote)

    def test_drop_ipv4_to_ipv6_mapped(self):
        to_send = self.generate_default_packets()

        subprocess.call([XDP_FILTER_EXEC, "ip",
                         "::ffff:" + self.get_contexts().get_local_main().inet,
                         "--mode", "dst"])

        res = self.send_packets(to_send)

        self.not_arrived(to_send, res.captured_local, res.captured_remote)


class DirectSKB(Direct):
    def setUp(self):
        subprocess.call([
            XDP_FILTER_EXEC, "load",
            "--mode", "skb",
            self.get_contexts().get_local_main().iface,
        ])


class DirectInverted(Direct):
    def setUp(self):
        subprocess.call([
            XDP_FILTER_EXEC, "load",
            "--policy", "deny",
            self.get_contexts().get_local_main().iface,
        ])

    def arrived(self, packets, captured_local, captured_remote):
        self.assertPacketsNotIn(packets, captured_local)
        for i in captured_remote:
            self.assertPacketContainerEmpty(i)

    def not_arrived(self, packets, captured_local, captured_remote):
        self.assertPacketsIn(packets, captured_local)
        for i in captured_remote:
            self.assertPacketContainerEmpty(i)


class ManyAddresses(Base):
    def format_number(self, number,
                      delimiter, format_string,
                      part_size, full_size):
        splitted = []

        while number > 0:
            splitted.append(int(number % (1 << part_size)))
            number = number >> part_size

        assert(len(splitted) <= full_size)
        if (len(splitted) < full_size):
            splitted += [0] * (full_size - len(splitted))

        splitted.reverse()

        return delimiter.join(format(s, format_string) for s in splitted)

    def much_generic(self, bits, name,
                     delimiter, format_string, part_size, full_size):
        AMOUNT = 256

        summed = 0
        for gen_number in range(0, (1 << bits) - 1, int((1 << bits) / AMOUNT)):
            summed += 1
            subprocess.call([
                XDP_FILTER_EXEC, name,
                self.format_number(gen_number, delimiter,
                                   format_string, part_size, full_size),
                "--mode", "dst"])

        output = subprocess.check_output([XDP_FILTER_EXEC, "status"])
        self.assertGreaterEqual(len(output.splitlines()), summed)

    def test_much_ip(self):
        self.much_generic(32, "ip", ".", "d", 8, 4)

    def test_much_port(self):
        self.much_generic(16, "port", "", "d", 16, 1)

    def test_much_ether(self):
        self.much_generic(48, "ether", ":", "02x", 8, 6)

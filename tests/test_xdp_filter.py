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
    def test_much_ip(self):
        ip_list = []
        s = 0
        step = 70
        for a in range(0, 255, step):
            for b in range(0, 255, step):
                for c in range(0, 255, step):
                    for d in range(0, 255, step):
                        new_ip = str(a) + "." + str(b) + "." + \
                            str(c) + "." + str(d)
                        ip_list.append(new_ip)
                        s += 1
                        subprocess.call([
                            XDP_FILTER_EXEC, "ip",
                            new_ip,
                            "--mode", "dst"])
                output = subprocess.check_output([XDP_FILTER_EXEC, "status"])
                print(len(output.splitlines()))

        print("-----")

        for a in range(0, 255, step):
            for b in range(0, 255, step):
                output = subprocess.check_output([XDP_FILTER_EXEC, "status"])
                print(len(output.splitlines()), "->")
                for c in range(0, 255, step):
                    for d in range(0, 255, step):
                        new_ip = str(a) + "." + str(b) + "." + \
                            str(c) + "." + str(d)
                        subprocess.call([
                            XDP_FILTER_EXEC, "ip",
                            new_ip,
                            "--mode", "dst", "--remove"])
                output = subprocess.check_output([XDP_FILTER_EXEC, "status"])
                print(len(output.splitlines()))
        print("-----")
        # some ip addresses are not added, and can not be added in future
        for a in range(0, 255, step):
            for b in range(0, 255, step):
                for c in range(0, 255, step):
                    for d in range(0, 255, step):
                        new_ip = str(a) + "." + str(b) + "." + \
                            str(c) + "." + str(d)
                        subprocess.call([
                            XDP_FILTER_EXEC, "ip",
                            new_ip,
                            "--mode", "dst"])
                output = subprocess.check_output([XDP_FILTER_EXEC, "status"])
                print(len(output.splitlines()))

        time.sleep(1)

        output = subprocess.check_output([XDP_FILTER_EXEC, "status"])
        output2 = output.decode()
        print(output2.splitlines())
        print("--------")
        for ip in ip_list:
            if output2.find(ip) == -1:
                print(ip)

        self.assertGreaterEqual(len(output.splitlines()), s)

    def test_much_port(self):
        AMOUNT = 2048

        summed = 0
        for a in range(0, 1 << 16, int((1 << 16) / AMOUNT)):
            summed += 1
            subprocess.call([
                XDP_FILTER_EXEC, "port",
                str(a),
                "--mode", "dst"])
            # time.sleep(0.1)

        time.sleep(1)
        output = subprocess.check_output([XDP_FILTER_EXEC, "status"])
        self.assertGreaterEqual(
            len(output.splitlines()), summed, output.splitlines())

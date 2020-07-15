import subprocess
import time
import os
import signal

import unittest

from harness.xdp_case import XDPCase, usingCustomLoader

XDP_FILTER_EXEC = "progs/xdp-filter-exec.sh"

@usingCustomLoader
class XDPFilter(XDPCase):
    def setUp(self):
        super().setUp()

        subprocess.call([XDP_FILTER_EXEC, "load",
                         self.get_contexts().get_local_main().iface])


    def tearDown(self):
        subprocess.call([XDP_FILTER_EXEC, "unload",
                         self.get_contexts().get_local_main().iface])

        super().tearDown()


    def test_first(self):
        subprocess.call([XDP_FILTER_EXEC, "ip",
                         self.get_contexts().get_remote_main().inet,
                         "--mode", "src"])

        res = self.send_packets(self.generate_default_packets())

        self.assertPacketContainerEmpty(res.captured_local)
        for i in res.captured_remote:
            self.assertPacketContainerEmpty(i)


@usingCustomLoader
class XDPFilterLoadUnload(XDPCase):
    def get_target_interface(self):
        return self.get_contexts().get_local_main().iface

    def unload(self):
        return subprocess.call([XDP_FILTER_EXEC, "unload",
                                self.get_target_interface()])

    def load(self):
        return subprocess.call([XDP_FILTER_EXEC, "load",
                                self.get_target_interface(),
                                "--mode", "skb"])

    def test_load_once(self):
        self.assertNotEqual(self.unload(), 0, "zeroth unload")
        self.assertEqual(self.load(), 0, "first load")
        self.assertEqual(self.unload(), 0, "first unload")
        self.assertNotEqual(self.unload(), 0, "second unload")

    def test_load_twice(self):
        self.assertNotEqual(self.unload(), 0, "zeroth unload")
        self.assertEqual(self.load(), 0, "first load")
        self.assertNotEqual(self.load(), 0, "second load")
        self.assertEqual(self.unload(), 0, "first unload")
        self.assertNotEqual(self.unload(), 0, "second unload")

class XDPFilterLoopbackLoadUnload(XDPFilterLoadUnload):
    def get_target_interface(self):
        return "lo"

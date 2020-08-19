
class BaseDst:
    def get_device(self):
        return self.get_contexts().get_local_main()

    def get_port(self):
        return self.dst_port

    def get_mode(self):
        return "dst"


class BaseInvert:
    def setUp(self):
        subprocess.run([
            XDP_FILTER_EXEC, "load",
            "--policy", "deny",
            self.get_contexts().get_local_main().iface,
            "--mode", get_mode_string(
                self.get_contexts().get_local_main().xdp_mode
            )
        ])

    arrived = Base.not_arrived
    not_arrived = Base.arrived


class DirectPassSrc(Base, DirectBase, BaseSrc, BaseInvert):
    pass


class DirectDropDst(Base, DirectBase, BaseDst):
    pass


class DirectPassDst(Base, DirectBase, BaseDst, BaseInvert):
    pass


class ManyAddressesInverted(ManyAddresses):
    def setUp(self):
        subprocess.run([
            XDP_FILTER_EXEC, "load",
            "--policy", "deny",
            self.get_contexts().get_local_main().iface,
            "--mode", get_mode_string(
                self.get_contexts().get_local_main().xdp_mode
            )
        ])

    arrived = Base.not_arrived
    not_arrived = Base.arrived

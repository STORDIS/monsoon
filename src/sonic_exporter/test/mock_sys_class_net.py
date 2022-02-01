from sonic_exporter.sys_class_net import SystemClassNetworkInfo


class MockSystemClassNetworkInfo(SystemClassNetworkInfo):
    def get_attribute_info(
        self, interface: str, attribute: SystemClassNetworkInfo.NetworkInfoAttribute
    ) -> str:
        match attribute:
            case SystemClassNetworkInfo.NetworkInfoAttribute.FLAGS:
                return "0x1003"
            case SystemClassNetworkInfo.NetworkInfoAttribute.CARRIER:
                return "1"
            case _:
                raise NotImplementedError(
                    f"The NetworkInfoAttribute: [{attribute}] is not implemented in {self.__class__.__name__}"
                )

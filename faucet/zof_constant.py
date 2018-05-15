import ipaddress


class ether(object):
    ether = 'ETHERNET'
    ETH_TYPE_8021Q = 0x8100
    ETH_TYPE_ARP = 0x0806
    ETH_TYPE_IP = 0x0800
    ETH_TYPE_IPV6 = 0x86dd
    ETH_TYPE_LLDP = 0x88cc
    ETH_TYPE_SLOW = 0x8809


class ofp(object):
    OFP_VERSION = 0x04
    OFPVID_NONE = 0x0000
    OFPVID_PRESENT = 0x1000
    OFP_NO_BUFFER = 'NO_BUFFER'

    OFPFC_ADD = 'ADD'
    OFPFC_MODIFY = 'MODIFY'
    OFPFC_MODIFY_STRICT = 'MODIFY_STRICT'
    OFPFC_DELETE = 'DELETE'
    OFPFC_DELETE_STRICT = 'DELETE_STRICT'
    OFPFF_SEND_FLOW_REM = 'SEND_FLOW_REM'
    OFPRR_IDLE_TIMEOUT = 'IDLE_TIMEOUT'
    OFPP_ANY = 'ANY'
    OFPG_ANY = 'ANY'
    OFPG_ALL = 'ALL'
    OFPGT_ALL = 'ALL'
    OFPGT_FF = 'FF'
    OFPR_ACTION = 'APPLY_ACTION'

    OFPP_IN_PORT = 'IN_PORT'
    OFPP_CONTROLLER = 'CONTROLLER'
    OFPP_LOCAL = 0xfffffffe    # 'LOCAL'; mininet test expects int
    
    OFPTT_ALL = 'ALL'
    OFPPC_PORT_DOWN = 1   # 'PORT_DOWN'; mininet test expects int

    OFPGC_ADD = 'ADD'
    OFPGC_MODIFY = 'MODIFY'
    OFPGC_DELETE = 'DELETE'

    OFPPR_ADD = 'ADD'
    OFPPR_MODIFY = 'MODIFY'
    OFPPR_DELETE = 'DELETE'

    @staticmethod
    def port_reason(value):
        """Convert OFPPR reason string to integer."""
        assert isinstance(value, (str, int)), repr(value)
        reasons = {'ADD': 0, 'DELETE': 1, 'MODIFY': 2}
        if value in reasons:
            return reasons[value]
        return int(value, 0)

    @staticmethod
    def port_state(value):
        """Convert OFPPS port state to integer (0 or 1)."""
        assert isinstance(value, list), repr(value)
        return 1 if 'LINK_DOWN' in value else 0

    OFPMC_ADD = 'ADD'
    OFPMC_DELETE = 'DELETE'
    
    OFPM_ALL = 'ALL'


class mac(object):
    BROADCAST_STR = 'ff:ff:ff:ff:ff:ff'
    DONTCARE_STR = '00:00:00:00:00:00'

    @staticmethod
    def text_to_bin(val):
        return bytes.fromhex(val.replace(':', ''))


class inet(object):
    IPPROTO_ICMP = 1
    IPPROTO_ICMPV6 = 58


class ipv4(object):
    ipv4 = 'IPV4'

    @staticmethod
    def text_to_bin(val):
        return ipaddress.ip_address(val).packed


class ipv6(object):
    ipv6 = 'IPV6'

    @staticmethod
    def text_to_bin(val):
        return ipaddress.ip_address(val).packed


class arp(object):
    arp = 'ARP'
    ARP_REQUEST = 1
    ARP_REPLY = 2


class icmp(object):
    icmp = 'ICMPV4'
    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    ICMP_ECHO_CODE = 0


class icmpv6(object):
    icmpv6 = 'ICMPV6'
    ICMPV6_ECHO_REQUEST = 128
    ICMPV6_ECHO_REPLY = 129
    ND_NEIGHBOR_SOLICIT = 135
    ND_NEIGHBOR_ADVERT = 136
    ND_ROUTER_SOLICIT = 133
    ND_ROUTER_ADVERT = 134


class slow(object):
    lacp = 'LACP'
    SLOW_PROTOCOL_MULTICAST = '01:80:c2:00:00:02'


class bpdu(object):
    BRIDGE_GROUP_ADDRESS = '01:80:c2:00:00:00'


class lldp(object):
    lldp = 'LLDP'
    LLDP_MAC_NEAREST_BRIDGE = '01:80:c2:00:00:0e'

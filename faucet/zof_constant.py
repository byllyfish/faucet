"""Compatibility constants for zof port."""

import ipaddress

# pylint: disable=missing-docstring,invalid-name,too-few-public-methods

class ether:
    ether = 'ETHERNET'
    ETH_TYPE_8021Q = 0x8100
    ETH_TYPE_ARP = 0x0806
    ETH_TYPE_IP = 0x0800
    ETH_TYPE_IPV6 = 0x86dd
    ETH_TYPE_LLDP = 0x88cc
    ETH_TYPE_SLOW = 0x8809


class ofp:
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
        if isinstance(value, int):
            return value
        assert isinstance(value, str)
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


class mac:
    BROADCAST_STR = 'ff:ff:ff:ff:ff:ff'
    DONTCARE_STR = '00:00:00:00:00:00'

    @staticmethod
    def text_to_bin(val):
        mac_bin = bytes(int(x, 16) for x in val.split(':'))
        if len(mac_bin) != 6:
            raise ValueError('Invalid mac address: %s' % val)
        return mac_bin

    @staticmethod
    def is_multicast(val):
        """Return true if value is a multicast MAC address."""
        mac_bin = mac.text_to_bin(val)
        return (mac_bin[0] & 0x01) != 0


class inet:
    IPPROTO_IP = 0
    IPPROTO_ICMP = 1
    IPPROTO_ICMPV6 = 58


class ipv4:
    ipv4 = 'IPV4'

    @staticmethod
    def text_to_bin(val):
        return ipaddress.ip_address(val).packed


class ipv6:
    ipv6 = 'IPV6'

    @staticmethod
    def text_to_bin(val):
        return ipaddress.ip_address(val).packed


class arp:
    arp = 'ARP'
    ARP_REQUEST = 1
    ARP_REPLY = 2


class icmp:
    icmp = 'ICMPV4'
    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    ICMP_ECHO_CODE = 0


class icmpv6:
    icmpv6 = 'ICMPV6'
    ICMPV6_ECHO_REQUEST = 128
    ICMPV6_ECHO_REPLY = 129
    ND_NEIGHBOR_SOLICIT = 135
    ND_NEIGHBOR_ADVERT = 136
    ND_ROUTER_SOLICIT = 133
    ND_ROUTER_ADVERT = 134


class slow:
    lacp = 'LACP'
    SLOW_PROTOCOL_MULTICAST = '01:80:c2:00:00:02'


class bpdu:
    BRIDGE_GROUP_ADDRESS = '01:80:c2:00:00:00'


class lldp:
    lldp = 'LLDP'
    LLDP_MAC_NEAREST_BRIDGE = '01:80:c2:00:00:0e'
    LLDP_TLV_ORGANIZATIONALLY_SPECIFIC = 'x_lldp_org_specific'
    LLDP_TLV_PORT_ID = 'x_lldp_port_id'
    LLDP_TLV_SYSTEM_NAME = 'x_lldp_sys_name'

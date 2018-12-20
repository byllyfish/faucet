"""Utility functions for parsing and building Ethernet packet/contents."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ipaddress
import struct
from netaddr import EUI
from collections import namedtuple

from zof.pktview import make_pktview

from faucet import valve_util
from faucet.zof_constant import ether, mac, arp, inet, icmp, icmpv6, ofp, slow, bpdu, ipv4, ipv6, lldp

FAUCET_MAC = '0e:00:00:00:00:01' # Default FAUCET MAC address

ETH_HEADER_SIZE = 14
ETH_VLAN_HEADER_SIZE = ETH_HEADER_SIZE + 4 # https://en.wikipedia.org/wiki/IEEE_802.1Q#Frame_format
IPV4_HEADER_SIZE = 20 # https://en.wikipedia.org/wiki/IPv4#Header
ICMP_ECHO_REQ_SIZE = 8 + 64 # https://en.wikipedia.org/wiki/Ping_(networking_utility)#ICMP_packet
IPV6_HEADER_SIZE = 40 # https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
ARP_REQ_PKT_SIZE = 28
ARP_PKT_SIZE = 46 # https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure
VLAN_ARP_REQ_PKT_SIZE = ETH_VLAN_HEADER_SIZE + ARP_REQ_PKT_SIZE
VLAN_ARP_PKT_SIZE = ETH_VLAN_HEADER_SIZE + ARP_PKT_SIZE
VLAN_ICMP_ECHO_REQ_SIZE = ETH_VLAN_HEADER_SIZE + IPV4_HEADER_SIZE + ICMP_ECHO_REQ_SIZE

ETH_EAPOL = 0x888e
SLOW_PROTOCOL_MULTICAST = slow.SLOW_PROTOCOL_MULTICAST
BRIDGE_GROUP_ADDRESS = bpdu.BRIDGE_GROUP_ADDRESS
BRIDGE_GROUP_MASK = 'ff:ff:ff:ff:ff:f0'
LLDP_MAC_NEAREST_BRIDGE = lldp.LLDP_MAC_NEAREST_BRIDGE
CISCO_SPANNING_GROUP_ADDRESS = '01:00:0c:cc:cc:cd'
IPV6_ALL_NODES_MCAST = '33:33:00:00:00:01'
IPV6_ALL_ROUTERS_MCAST = '33:33:00:00:00:02'
IPV6_ALL_NODES = ipaddress.IPv6Address('ff02::1')
IPV6_MAX_HOP_LIM = 255
IPV6_RA_HOP_LIM = 64

LLDP_FAUCET_DP_ID = 1
LLDP_FAUCET_STACK_STATE = 2

LACP_SIZE = 124

EUI_BITS = len(EUI(0).packed*8)
MAC_MASK_BITMAP = {(2**EUI_BITS - 2**i): (EUI_BITS - i) for i in range(0, EUI_BITS + 1)}


def mac_mask_bits(mac_mask):
    """Return number of bits in MAC mask or 0."""
    if mac_mask is not None:
        return MAC_MASK_BITMAP.get(EUI(mac_mask).value, 0)
    return 0


def int_from_mac(mac):
    int_hi, int_lo = [int(i, 16) for i in mac.split(':')[-2:]]
    return (int_hi << 8) + int_lo


def int_in_mac(mac, to_int):
    int_mac = mac.split(':')[:4] + [
        '%x' % (to_int >> 8), '%x' % (to_int & 0xff)]
    return ':'.join(int_mac)


def mac_byte_mask(mask_bytes=0):
    """Return a MAC address mask with n bytes masked out."""
    assert mask_bytes <= 6
    return ':'.join(['ff'] * mask_bytes + (['00'] * (6 - mask_bytes)))


def parse_eth_pkt(pkt):
    """Return parsed Ethernet packet.

    Args:
        pkt (ryu.lib.packet.packet): packet received from dataplane.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet.
    """
    return pkt.get_protocol(ether.ether)


def parse_lacp_pkt(pkt):
    """Return parsed LACP packet.

    Args:
        pkt (ryu.lib.packet.packet): packet received from dataplane.
    Returns:
        ryu.lib.packet.lacp: LACP packet.
    """
    return _lacp_slow_parse(pkt)


LLDPPortID = namedtuple('LLDPPortID', 'port_id')
LLDPOrgSpecific = namedtuple('LLDPOrgSpecific', 'oui subtype info')

def _convert_lldp_port_id(pkt):
    tlv = pkt('x_lldp_port_id')
    if not tlv:
        return
    if tlv.startswith('ifname '):
        try:
            port_id = int(tlv[7:])
        except ValueError:
            port_id = tlv[7:]
        pkt['x_lldp_port_id'] = LLDPPortID(port_id)

def _convert_lldp_org_specific(pkt):
    tlvs = pkt('x_lldp_org_specific')
    if not tlvs:
        return
    if not isinstance(tlvs, list):
        tlvs = [tlvs]
    converted_tlvs = []
    for tlv in tlvs:
        oui, subtype, info = tlv.split(maxsplit=2)
        assert oui.startswith('0x'), repr(oui)
        oui = oui[2:]
        if (len(oui) % 2) == 1:
            oui = '0%s' % oui
        oui = bytes.fromhex(oui)
        subtype = int(subtype, 0)
        info = bytes.fromhex(info)
        converted_tlvs.append(LLDPOrgSpecific(oui, subtype, info))
    pkt['x_lldp_org_specific'] = converted_tlvs


def parse_lldp(pkt):
    """Return parsed LLDP packet.

    Args:
        pkt (ryu.lib.packet.packet): packet received from dataplane.
    Returns:
        ryu.lib.packet.lldp: LLDP packet.
    """
    result = pkt.get_protocol(lldp.lldp)
    _convert_lldp_port_id(result)
    _convert_lldp_org_specific(result)
    return result


def parse_packet_in_pkt(data, max_len, eth_pkt=None, vlan_pkt=None):
    """Parse a packet received via packet in from the dataplane.

    Args:
        data (bytearray): packet data from dataplane.
        max_len (int): max number of packet data bytes to parse.
    Returns:
        ryu.lib.packet.packet: raw packet
        ryu.lib.packet.ethernet: parsed Ethernet packet.
        int: Ethernet type of packet (inside VLAN)
        int: VLAN VID (or None if no VLAN)
    """
    vid = data.get('vlan_vid')
    if vid is not None:
        vid &= ~4096
    return (data, data, data['eth_type'], data, vid)


def mac_addr_is_unicast(mac_addr):
    """Returns True if mac_addr is a unicast Ethernet address.

    Args:
        mac_addr (str): MAC address.
    Returns:
        bool: True if a unicast Ethernet address.
    """
    return not mac.is_multicast(mac_addr)


def build_pkt_header(vid, eth_src, eth_dst, dl_type):
    """Return an Ethernet packet header.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): destination Ethernet MAC address.
        dl_type (int): EtherType.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet with header.
    """
    pkt_header = make_pktview(eth_dst=eth_dst, eth_src=eth_src, eth_type=dl_type)
    if vid is not None:
        pkt_header.vlan_vid = vid | ofp.OFPVID_PRESENT
    return pkt_header


def lldp_beacon(eth_src, chassis_id, port_id, ttl, org_tlvs=None,
                system_name=None, port_descr=None):
    """Return an LLDP frame suitable for a host/access port.

    Args:
        eth_src (str): source Ethernet MAC address.
        chassis_id (str): Chassis ID.
        port_id (int): port ID,
        TTL (int): TTL for payload.
        org_tlvs (list): list of tuples of (OUI, subtype, info).
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet with header.
    """
    pkt = build_pkt_header(
        None, eth_src, lldp.LLDP_MAC_NEAREST_BRIDGE, ether.ETH_TYPE_LLDP)
    pkt.x_lldp_chassis_id = 'mac %s' % chassis_id
    pkt.x_lldp_port_id = 'ifname %s' % port_id
    pkt.x_lldp_ttl = ttl
    pkt.x_lldp_sys_name = system_name
    pkt.x_lldp_port_descr = port_descr
    org_specific = []
    if org_tlvs:
        for oui, subtype, info in org_tlvs:
            org_specific.append('0x%s %#x %s' % (oui.hex(), subtype, info.hex()))
    pkt.x_lldp_org_specific = org_specific
    return pkt


def faucet_oui(mac_addr):
    """Return first 3 bytes of MAC address (given as str)."""
    return mac.text_to_bin(mac_addr)[:3]


def faucet_lldp_tlvs(dp):
    """Return LLDP TLVs for a datapath."""
    tlvs = []
    tlvs.append(
        (faucet_oui(dp.faucet_dp_mac), LLDP_FAUCET_DP_ID, str(dp.dp_id).encode('utf-8')))
    return tlvs


def faucet_lldp_stack_state_tlvs(dp, port):
    """Return a LLDP TLV for state of a stack port."""
    tlvs = []
    if not port.stack:
        return []
    tlvs.append(
        (
            faucet_oui(dp.faucet_dp_mac),
            LLDP_FAUCET_STACK_STATE,
            str(port.dyn_stack_current_state).encode('utf-8')))
    return tlvs


def tlvs_by_type(lldp_pkt, tlv_type):
    """Return list of TLVs with matching type."""
    tlvs = lldp_pkt(tlv_type)
    if not tlvs:
        return []
    if not isinstance(tlvs, list):
        tlvs = [tlvs]
    return tlvs


def tlvs_by_subtype(tlvs, subtype):
    """Return list of TLVs with matching type."""
    return [tlv for tlv in tlvs if tlv.subtype == subtype]


def tlv_cast(tlvs, tlv_attr, cast_func):
    """Return cast'd attribute of first TLV or None."""
    tlv_val = None
    if tlvs:
        try:
            if tlv_attr:
                tlv_val = getattr(tlvs[0], tlv_attr)
            else:
                tlv_val = tlvs[0]
            tlv_val = cast_func(tlv_val)
        except (AttributeError, ValueError, TypeError):
            pass
    return tlv_val


def faucet_tlvs(lldp_pkt, faucet_dp_mac):
    """Return list of TLVs with FAUCET OUI."""
    return [tlv for tlv in tlvs_by_type(
        lldp_pkt, lldp.LLDP_TLV_ORGANIZATIONALLY_SPECIFIC)
            if tlv.oui == faucet_oui(faucet_dp_mac)]


def parse_faucet_lldp(lldp_pkt, faucet_dp_mac):
    """Parse and return FAUCET TLVs from LLDP packet."""
    remote_dp_id = None
    remote_dp_name = None
    remote_port_id = None
    remote_port_state = None

    tlvs = faucet_tlvs(lldp_pkt, faucet_dp_mac)
    if tlvs:
        dp_id_tlvs = tlvs_by_subtype(tlvs, LLDP_FAUCET_DP_ID)
        dp_name_tlvs = tlvs_by_type(lldp_pkt, lldp.LLDP_TLV_SYSTEM_NAME)
        port_id_tlvs = tlvs_by_type(lldp_pkt, lldp.LLDP_TLV_PORT_ID)
        port_state_tlvs = tlvs_by_subtype(tlvs, LLDP_FAUCET_STACK_STATE)
        remote_dp_id = tlv_cast(dp_id_tlvs, 'info', int)
        remote_port_id = tlv_cast(port_id_tlvs, 'port_id', int)
        remote_port_state = tlv_cast(port_state_tlvs, 'info', int)
        remote_dp_name = tlv_cast(dp_name_tlvs, None, str)
    return (remote_dp_id, remote_dp_name, remote_port_id, remote_port_state)


def lacp_reqreply(eth_src,
                  actor_system, actor_key, actor_port,
                  actor_state_synchronization=0,
                  actor_state_activity=0,
                  partner_system='00:00:00:00:00:00',
                  partner_key=0,
                  partner_port=0,
                  partner_system_priority=0,
                  partner_port_priority=0,
                  partner_state_defaulted=0,
                  partner_state_expired=0,
                  partner_state_timeout=0,
                  partner_state_collecting=0,
                  partner_state_distributing=0,
                  partner_state_aggregation=0,
                  partner_state_synchronization=0,
                  partner_state_activity=0):
    """Return a LACP frame.

    Args:
        eth_src (str): source Ethernet MAC address.
        actor_system (str): actor system ID (MAC address)
        actor_key (int): actor's LACP key assigned to this port.
        actor_port (int): actor port number.
        actor_state_synchronization (int): 1 if we will use this link.
        actor_state_activity (int): 1 if actively sending LACP.
        partner_system (str): partner system ID (MAC address)
        partner_key (int): partner's LACP key assigned to this port.
        partner_port (int): partner port number.
        partner_system_priority (int): partner's system priority.
        partner_port_priority (int): partner's port priority.
        partner_state_defaulted (int): 1 if partner reverted to defaults.
        partner_state_expired (int): 1 if partner thinks LACP expired.
        partner_state_timeout (int): 1 if partner has short timeout.
        partner_state_collecting (int): 1 if partner receiving on this link.
        partner_state_distributing (int): 1 if partner transmitting on this link.
        partner_state_aggregation (int): 1 if partner can aggregate this link.
        partner_state_synchronization (int): 1 if partner will use this link.
        partner_state_activity (int): 1 if partner actively sends LACP.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet with header.
    """
    pkt = build_pkt_header(
        None, eth_src, slow.SLOW_PROTOCOL_MULTICAST, ether.ETH_TYPE_SLOW)
    pkt.payload = lacp_payload(
        version=1,
        actor_system=actor_system,
        actor_port=actor_port,
        partner_system=partner_system,
        partner_port=partner_port,
        actor_key=actor_key,
        partner_key=partner_key,
        actor_system_priority=65535,
        partner_system_priority=partner_system_priority,
        actor_port_priority=255,
        partner_port_priority=partner_port_priority,
        actor_state_defaulted=0,
        partner_state_defaulted=partner_state_defaulted,
        actor_state_expired=0,
        partner_state_expired=partner_state_expired,
        actor_state_timeout=1,
        partner_state_timeout=partner_state_timeout,
        actor_state_collecting=1,
        partner_state_collecting=partner_state_collecting,
        actor_state_distributing=1,
        partner_state_distributing=partner_state_distributing,
        actor_state_aggregation=1,
        partner_state_aggregation=partner_state_aggregation,
        actor_state_synchronization=actor_state_synchronization,
        partner_state_synchronization=partner_state_synchronization,
        actor_state_activity=actor_state_activity,
        partner_state_activity=partner_state_activity)
    return pkt


def lacp_payload(*,
                 version,
                 actor_system,
                 actor_port,
                 partner_system,
                 partner_port,
                 actor_key,
                 partner_key,
                 actor_system_priority,
                 partner_system_priority,
                 actor_port_priority,
                 partner_port_priority,
                 actor_state_defaulted,
                 partner_state_defaulted,
                 actor_state_expired,
                 partner_state_expired,
                 actor_state_timeout,
                 partner_state_timeout,
                 actor_state_collecting,
                 partner_state_collecting,
                 actor_state_distributing,
                 partner_state_distributing,
                 actor_state_aggregation,
                 partner_state_aggregation,
                 actor_state_synchronization,
                 partner_state_synchronization,
                 actor_state_activity,
                 partner_state_activity):
    """Helper function to construct LACP payload.
    """
    actor_state = _lacp_state(
        actor_state_defaulted,
        actor_state_expired,
        actor_state_timeout,
        actor_state_collecting,
        actor_state_distributing,
        actor_state_aggregation,
        actor_state_synchronization,
        actor_state_activity)
    partner_state = _lacp_state(
        partner_state_defaulted,
        partner_state_expired,
        partner_state_timeout,
        partner_state_collecting,
        partner_state_distributing,
        partner_state_aggregation,
        partner_state_synchronization,
        partner_state_activity)
    payload = _lacp_header()
    payload += _lacp_peer_info(
        tlv_type=1,     # actor
        system_priority=actor_system_priority,
        system=actor_system,
        key=actor_key,
        port_priority=actor_port_priority,
        port=actor_port,
        state=actor_state)
    payload += _lacp_peer_info(
        tlv_type=2,     # partner
        system_priority=partner_system_priority,
        system=partner_system,
        key=partner_key,
        port_priority=partner_port_priority,
        port=partner_port,
        state=partner_state)
    payload += _lacp_collector_info_terminator(max_delay=0)
    return payload


def _lacp_state(defaulted, expired, timeout, collecting, distributing, aggregation, synchronization, activity):
    state = 0
    if defaulted:
        state |= LACP_DFLT
    if expired:
        state |= LACP_EXPR
    if timeout:
        state |= LACP_TMO
    if collecting:
        state |= LACP_CLCT
    if distributing:
        state |= LACP_DIST
    if aggregation:
        state |= LACP_AGGR
    if synchronization:
        state |= LACP_SYNC
    if activity:
        state |= LACP_ACT
    return state


def arp_request(vid, eth_src, eth_dst, src_ip, dst_ip):
    """Return an ARP request packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): Ethernet source address.
        eth_dst (str): Ethernet destination address.
        src_ip (ipaddress.IPv4Address): source IPv4 address.
        dst_ip (ipaddress.IPv4Address): requested IPv4 address.
    Returns:
        ryu.lib.packet.arp: serialized ARP request packet.
    """
    pkt = build_pkt_header(vid, eth_src, eth_dst, ether.ETH_TYPE_ARP)
    pkt.arp_op = arp.ARP_REQUEST
    pkt.arp_sha = eth_src
    pkt.arp_tha = mac.DONTCARE_STR
    pkt.arp_spa = src_ip
    pkt.arp_tpa = dst_ip
    return pkt


def arp_reply(vid, eth_src, eth_dst, src_ip, dst_ip):
    """Return an ARP reply packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): Ethernet source address.
        eth_dst (str): destination Ethernet MAC address.
        src_ip (ipaddress.IPv4Address): source IPv4 address.
        dst_ip (ipaddress.IPv4Address): destination IPv4 address.
    Returns:
        ryu.lib.packet.arp: serialized ARP reply packet.
    """
    pkt = build_pkt_header(vid, eth_src, eth_dst, ether.ETH_TYPE_ARP)
    pkt.arp_op = arp.ARP_REPLY
    pkt.arp_sha = eth_src
    pkt.arp_tha = eth_dst
    pkt.arp_spa = src_ip
    pkt.arp_tpa = dst_ip
    return pkt


def echo_reply(vid, eth_src, eth_dst, src_ip, dst_ip, data):
    """Return an ICMP echo reply packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): Ethernet source address.
        eth_dst (str): destination Ethernet MAC address.
        src_ip (ipaddress.IPv4Address): source IPv4 address.
        dst_ip (ipaddress.IPv4Address): destination IPv4 address.
    Returns:
        ryu.lib.packet.icmp: serialized ICMP echo reply packet.
    """
    pkt = build_pkt_header(vid, eth_src, eth_dst, ether.ETH_TYPE_IP)
    pkt.ip_proto = inet.IPPROTO_ICMP
    pkt.ipv4_src = src_ip
    pkt.ipv4_dst = dst_ip
    pkt.icmpv4_type = icmp.ICMP_ECHO_REPLY
    pkt.icmpv4_code = icmp.ICMP_ECHO_CODE
    pkt.payload = data
    return pkt


def ipv6_link_eth_mcast(dst_ip):
    """Return an Ethernet multicast address from an IPv6 address.

    See RFC 2464 section 7.

    Args:
        dst_ip (ipaddress.IPv6Address): IPv6 address.
    Returns:
        str: Ethernet multicast address.
    """
    mcast_mac_bytes = b'\x33\x33\xff' + dst_ip.packed[-3:]
    mcast_mac = ':'.join(['%02X' % x for x in mcast_mac_bytes])
    return mcast_mac


def ipv6_solicited_node_from_ucast(ucast):
    """Return IPv6 solicited node multicast address from IPv6 unicast address.

    See RFC 3513 section 2.7.1.

    Args:
       ucast (ipaddress.IPv6Address): IPv6 unicast address.
    Returns:
       ipaddress.IPv6Address: IPv6 solicited node multicast address.
    """
    link_mcast_prefix = ipaddress.ip_interface('ff02::1:ff00:0/104')
    mcast_bytes = link_mcast_prefix.packed[:13] + ucast.packed[-3:]
    link_mcast = ipaddress.IPv6Address(mcast_bytes)
    return link_mcast


def nd_request(vid, eth_src, eth_dst, src_ip, dst_ip):
    """Return IPv6 neighbor discovery request packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): Ethernet destination address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        dst_ip (ipaddress.IPv6Address): requested IPv6 address.
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 neighbor discovery packet.
    """
    if mac_addr_is_unicast(eth_dst):
        nd_mac = eth_dst
        nd_ip = dst_ip
    else:
        nd_mac = ipv6_link_eth_mcast(dst_ip)
        nd_ip = ipv6_solicited_node_from_ucast(dst_ip)
    pkt = build_pkt_header(vid, eth_src, nd_mac, ether.ETH_TYPE_IPV6)
    pkt.ipv6_src = src_ip
    pkt.ipv6_dst = nd_ip
    pkt.ip_proto = inet.IPPROTO_ICMPV6
    pkt.hop_limit = IPV6_MAX_HOP_LIM
    pkt.icmpv6_type = icmpv6.ND_NEIGHBOR_SOLICIT
    pkt.ipv6_nd_target = dst_ip
    pkt.ipv6_nd_sll = eth_src
    return pkt


def nd_advert(vid, eth_src, eth_dst, src_ip, dst_ip):
    """Return IPv6 neighbor avertisement packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): destination Ethernet MAC address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        dst_ip (ipaddress.IPv6Address): destination IPv6 address.
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 neighbor discovery packet.
    """
    pkt = build_pkt_header(vid, eth_src, eth_dst, ether.ETH_TYPE_IPV6)
    pkt.ipv6_src = src_ip
    pkt.ipv6_dst = dst_ip
    pkt.ip_proto = inet.IPPROTO_ICMPV6
    pkt.hop_limit = IPV6_MAX_HOP_LIM
    pkt.icmpv6_type = icmpv6.ND_NEIGHBOR_ADVERT
    pkt.ipv6_nd_target = src_ip
    pkt.ipv6_nd_tll = eth_src
    pkt.ipv6_nd_res = (7 << 29)
    return pkt


def icmpv6_echo_reply(vid, eth_src, eth_dst, src_ip, dst_ip, hop_limit, data):
    r"""Return IPv6 ICMP echo reply packet.

        Args:
            vid (int or None): VLAN VID to use (or None).
            eth_src (str): source Ethernet MAC address.
            eth_dst (str): destination Ethernet MAC address.
            src_ip (ipaddress.IPv6Address): source IPv6 address.
            dst_ip (ipaddress.IPv6Address): destination IPv6 address.
            hop_limit (int): IPv6 hop limit.
            id_ (int): identifier for echo reply.
            seq (int): sequence number for echo reply.
            data (str): payload for echo reply.
        Returns:
            ryu.lib.packet.ethernet: Serialized IPv6 ICMP echo reply packet.
    """
    pkt = build_pkt_header(vid, eth_src, eth_dst, ether.ETH_TYPE_IPV6)
    pkt.ipv6_src = src_ip
    pkt.ipv6_dst = dst_ip
    pkt.ip_proto = inet.IPPROTO_ICMPV6
    pkt.hop_limit = hop_limit
    pkt.icmpv6_type = icmpv6.ICMPV6_ECHO_REPLY
    # N.B. we assume data already contains the id_ and seq.
    pkt.payload = data
    return pkt


def router_advert(vid, eth_src, eth_dst, src_ip, dst_ip,
                  vips, pi_flags=0x6):
    """Return IPv6 ICMP Router Advert.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        eth_dst (str): dest Ethernet MAC address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        vips (list): prefixes (ipaddress.IPv6Address) to advertise.
        pi_flags (int): flags to set in prefix information field (default set A and L)
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 ICMP RA packet.
    """
    pkt = build_pkt_header(vid, eth_src, eth_dst, ether.ETH_TYPE_IPV6)
    pkt.ipv6_src = src_ip
    pkt.ipv6_dst = dst_ip
    pkt.ip_proto = inet.IPPROTO_ICMPV6
    pkt.hop_limit = IPV6_MAX_HOP_LIM
    pkt.icmpv6_type = icmpv6.ND_ROUTER_ADVERT
    options = b''.join(
        _ra_pio_encode(network=vip.network,
                       flags=pi_flags << 5,
                       valid_lifetime=86400,
                       preferred_lifetime=14400)
        for vip in vips)
    options += _ra_sll_encode(sll=eth_src)
    pkt.payload = _ra_encode(cur_hop_limit=IPV6_RA_HOP_LIM,
                             flags=0,
                             router_lifetime=1800,
                             reachable_time=0,
                             retrans_timer=0,
                             options=options)
    return pkt


class PacketMeta:
    """Original, and parsed Ethernet packet metadata."""

    __slots__ = [
        'data',
        'orig_len',
        'pkt',
        'eth_pkt',
        'vlan_pkt',
        'port',
        'vlan',
        'eth_src',
        'eth_dst',
        'eth_type',
        'l3_pkt',
        'l3_src',
        'l3_dst',
    ]

    ETH_TYPES_PARSERS = {
        ether.ETH_TYPE_IP: ipv4.ipv4,
        ether.ETH_TYPE_ARP: arp.arp,
        ether.ETH_TYPE_IPV6: ipv6.ipv6
    }

    MAX_ETH_TYPE_PKT_SIZE = {
        ether.ETH_TYPE_ARP: VLAN_ARP_PKT_SIZE,
        ether.ETH_TYPE_IP: VLAN_ICMP_ECHO_REQ_SIZE,
    }

    def __init__(self, data, orig_len, pkt, eth_pkt, vlan_pkt, port, valve_vlan,
                 eth_src, eth_dst, eth_type):
        self.data = data
        self.orig_len = orig_len
        self.pkt = pkt
        self.eth_pkt = eth_pkt
        self.vlan_pkt = vlan_pkt
        self.port = port
        self.vlan = valve_vlan
        self.eth_src = eth_src
        self.eth_dst = eth_dst
        self.eth_type = eth_type
        self.l3_pkt = None
        self.l3_src = None
        self.l3_dst = None

    def log(self):
        vlan_msg = ''
        if self.vlan:
            vlan_msg = 'VLAN %u' % self.vlan.vid
        return '%s (L2 type 0x%4.4x, L3 src %s, L3 dst %s) %s %s' % (
            self.eth_src, self.eth_type, self.l3_src, self.l3_dst,
            self.port, vlan_msg)

    def reparse(self, max_len):
        """Reparse packet using data up to the specified maximum length."""
        pass

    def reparse_all(self):
        """Reparse packet with all available data."""
        pass

    def reparse_ip(self, payload=0):
        """Reparse packet with specified IP header type and optionally payload."""
        if self.eth_type in self.ETH_TYPES_PARSERS:
            self.l3_pkt = self.pkt.get_protocol(self.ETH_TYPES_PARSERS[self.eth_type])
            if self.l3_pkt:
                if hasattr(self.l3_pkt, 'arp_spa'):
                    self.l3_src = self.l3_pkt.arp_spa
                    self.l3_dst = self.l3_pkt.arp_tpa
                elif hasattr(self.l3_pkt, 'ipv4_src'):
                    self.l3_src = self.l3_pkt.ipv4_src
                    self.l3_dst = self.l3_pkt.ipv4_dst
                elif hasattr(self.l3_pkt, 'ipv6_src'):
                    self.l3_src = self.l3_pkt.ipv6_src
                    self.l3_dst = self.l3_pkt.ipv6_dst
                self.l3_src = ipaddress.ip_address(self.l3_src)
                self.l3_dst = ipaddress.ip_address(self.l3_dst)

    def packet_complete(self):
        """True if we have the complete packet."""
        assert self.orig_len == 0 and self.data == b''
        return len(self.data) == self.orig_len


def _ra_encode(*, cur_hop_limit, flags, router_lifetime, reachable_time, retrans_timer, options):
    """Return byte string encoding a Router Advertisement.

    Reference: https://tools.ietf.org/html/rfc4861#section-4.2
    """
    return struct.pack('!BBHLL', cur_hop_limit, flags, router_lifetime,
                       reachable_time, retrans_timer) + options


def _ra_pio_encode(*, network, flags, valid_lifetime, preferred_lifetime):
    """Return byte string encoding a Prefix Information Option.

    Reference: https://tools.ietf.org/html/rfc4861#section-4.6.2
    """
    assert isinstance(network, ipaddress.IPv6Network)
    return struct.pack('!BBBBLLL16s', 3, 4, network.prefixlen, flags,
                       valid_lifetime, preferred_lifetime, 0,
                       network.network_address.packed)


def _ra_sll_encode(*, sll):
    """Return byte string encoding a Source link-layer address option.

    Reference: https://tools.ietf.org/html/rfc4861#section-4.6.1
    """
    data = bytes.fromhex(sll.replace(':', ''))
    assert len(data) == 6
    return struct.pack('!BB6s', 1, 1, data)


LACP_ACT = 0x01
LACP_TMO = 0x02
LACP_AGGR = 0x04
LACP_SYNC = 0x08
LACP_CLCT = 0x10
LACP_DIST = 0x20
LACP_DFLT = 0x40
LACP_EXPR = 0x80


def _lacp_header():
    return struct.pack('!BB', 1, 1)


def _lacp_peer_info(*, tlv_type, system_priority, system, key, port_priority, port, state):
    """Return byte string encoding a TLV section for LACP actor/partner .

    Reference: IEEE Std 802.1AX-2008 (Section 5.4.2)
    """
    if isinstance(system, str):
        system = bytes.fromhex(system.replace(':', ''))
    assert len(system) == 6
    return struct.pack('!BBH6sHHHB3x', tlv_type, 20, system_priority, system,
                       key, port_priority, port, state)


def _lacp_collector_info_terminator(*, max_delay):
    return struct.pack('!BBH64x', 3, 16, max_delay)


def _lacp_slow_parse(pkt):
    if pkt.eth_type != ether.ETH_TYPE_SLOW:
        raise ValueError('invalid eth_type: %r' % pkt.eth_type)

    data = pkt.payload
    offset = 0
    # Check header prefix.
    if data[0:2] != b'\x01\x01':
        raise ValueError('invalid lacp header prefix')
    offset += 2

    (tlv_type, tlv_len, pkt.actor_system_priority, pkt.actor_system,
     pkt.actor_key, pkt.actor_port_priority, pkt.actor_port,
     pkt.actor_state) = struct.unpack_from('!BBH6sHHHB3x', data, offset)
    if tlv_type != 1 and tlv_len != 20:
        raise ValueError('invalid lacp actor info')
    offset += 20

    (tlv_type, tlv_len, pkt.partner_system_priority, pkt.partner_system,
     pkt.partner_key, pkt.partner_port_priority, pkt.partner_port,
     pkt.partner_state) = struct.unpack_from('!BBH6sHHHB3x', data, offset)
    if tlv_type != 2 and tlv_len != 20:
        raise ValueError('invalid lacp partner info')
    offset += 20

    tlv_type, tlv_len, pkt.collector_max_delay = struct.unpack_from('!BBH12x', data, offset)
    if tlv_type != 3 and tlv_len != 16:
        raise ValueError('invalid lacp collector info')
    offset += 16

    tlv_type, tlv_len = struct.unpack_from('!BB', data, offset)
    if tlv_type != 0 and tlv_len != 0:
        raise ValueError('invalid lacp termination')

    # The remaining 50 reserved octets are ignored on receipt.

    # Break out the individual actor_state bits. Don't bother with the partner
    # state bits because they aren't used.
    actor_state = pkt.actor_state
    pkt.actor_state_activity = (actor_state & LACP_ACT) != 0
    pkt.actor_state_timeout = (actor_state & LACP_TMO) != 0
    pkt.actor_state_aggregation = (actor_state & LACP_AGGR) != 0
    pkt.actor_state_synchronization = (actor_state & LACP_SYNC) != 0
    pkt.actor_state_collecting = (actor_state & LACP_CLCT) != 0
    pkt.actor_state_distributing = (actor_state & LACP_DIST) != 0
    pkt.actor_state_defaulted = (actor_state & LACP_DFLT) != 0
    pkt.actor_state_expired = (actor_state & LACP_EXPR) != 0

    # The actor_system and partner_system are left encoded as bytes. They
    # could be translated to a string representing the MAC address.
    del pkt['payload']
    return pkt

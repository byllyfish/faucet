"""Utility functions for parsing and building Ethernet packet/contents."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
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

#from ryu.lib.packet import arp, bpdu, ethernet, icmp, icmpv6, ipv4, ipv6, slow, stream_parser, packet, vlan

from faucet.valve_util import btos

from zof.pktview import make_pktview
from faucet.zof_constant import ether, mac, arp, inet, icmp, icmpv6, ofp, slow, bpdu

SLOW_PROTOCOL_MULTICAST = slow.SLOW_PROTOCOL_MULTICAST
ETH_VLAN_HEADER_SIZE = 14 + 4
BRIDGE_GROUP_ADDRESS = bpdu.BRIDGE_GROUP_ADDRESS
CISCO_SPANNING_GROUP_ADDRESS = '01:00:0c:cc:cc:cd'
IPV6_ALL_NODES_MCAST = '33:33:00:00:00:01'
IPV6_ALL_ROUTERS_MCAST = '33:33:00:00:00:02'
IPV6_LINK_LOCAL = ipaddress.IPv6Network(btos('fe80::/10'))
IPV6_ALL_NODES = ipaddress.IPv6Address(btos('ff02::1'))
IPV6_MAX_HOP_LIM = 255



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


def parse_packet_in_pkt(data, max_len):
    """Parse a packet received via packet in from the dataplane.

    Args:
        data (bytearray): packet data from dataplane.
        max_len (int): max number of packet data bytes to parse.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet.
        int: VLAN VID.
        int: Ethernet type of packet (inside VLAN)
    """
    raise NotImplementedError


def mac_addr_is_unicast(mac_addr):
    """Returns True if mac_addr is a unicast Ethernet address.

    Args:
        mac_addr (str): MAC address.
    Returns:
        bool: True if a unicast Ethernet address.
    """
    msb = mac_addr.split(':')[0]
    return msb[-1] in '02468aAcCeE'


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


def lacp_reqreply(eth_src,
                  actor_system, actor_key, actor_port,
                  partner_system, partner_key, partner_port,
                  partner_system_priority, partner_port_priority,
                  partner_state_defaulted,
                  partner_state_expired,
                  partner_state_timeout,
                  partner_state_collecting,
                  partner_state_distributing,
                  partner_state_aggregation,
                  partner_state_synchronization,
                  partner_state_activity):
    """Return a LACP frame.

    Args:
        eth_src (str): source Ethernet MAC address.
        actor_system (str): actor system ID (MAC address)
        actor_key (int): actor's LACP key assigned to this port.
        actor_port (int): actor port number.
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
    pkt.payload = _lacp(
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
        actor_state_synchronization=1,
        partner_state_synchronization=partner_state_synchronization,
        actor_state_activity=0,
        partner_state_activity=partner_state_activity)
    return pkt


def _lacp(*, 
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


def arp_request(vid, eth_src, src_ip, dst_ip):
    """Return an ARP request packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): Ethernet source address.
        src_ip (ipaddress.IPv4Address): source IPv4 address.
        dst_ip (ipaddress.IPv4Address): requested IPv4 address.
    Returns:
        ryu.lib.packet.arp: serialized ARP request packet.
    """
    pkt = build_pkt_header(vid, eth_src, mac.BROADCAST_STR, ether.ETH_TYPE_ARP)
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
    mcast_mac_octets = []
    for i in mcast_mac_bytes:
        if isinstance(i, int):
            mcast_mac_octets.append(i)
        else:
            mcast_mac_octets.append(ord(i))
    mcast_mac = ':'.join(['%02X' % x for x in mcast_mac_octets])
    return mcast_mac


def ipv6_solicited_node_from_ucast(ucast):
    """Return IPv6 solicited node multicast address from IPv6 unicast address.

    See RFC 3513 section 2.7.1.

    Args:
       ucast (ipaddress.IPv6Address): IPv6 unicast address.
    Returns:
       ipaddress.IPv6Address: IPv6 solicited node multicast address.
    """
    link_mcast_prefix = ipaddress.ip_interface(btos('ff02::1:ff00:0/104'))
    mcast_bytes = link_mcast_prefix.packed[:13] + ucast.packed[-3:]
    link_mcast = ipaddress.IPv6Address(mcast_bytes)
    return link_mcast


def nd_request(vid, eth_src, src_ip, dst_ip):
    """Return IPv6 neighbor discovery request packet.

    Args:
        vid (int or None): VLAN VID to use (or None).
        eth_src (str): source Ethernet MAC address.
        src_ip (ipaddress.IPv6Address): source IPv6 address.
        dst_ip (ipaddress.IPv6Address): requested IPv6 address.
    Returns:
        ryu.lib.packet.ethernet: Serialized IPv6 neighbor discovery packet.
    """
    nd_mac = ipv6_link_eth_mcast(dst_ip)
    ip_gw_mcast = ipv6_solicited_node_from_ucast(dst_ip)
    pkt = build_pkt_header(vid, eth_src, nd_mac, ether.ETH_TYPE_IPV6)
    pkt.ipv6_src = src_ip
    pkt.ipv6_dst = ip_gw_mcast
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
    """Return IPv6 ICMP echo reply packet.

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


def router_advert(_vlan, vid, eth_src, eth_dst, src_ip, dst_ip,
                  vips, pi_flags=0x6):
    """Return IPv6 ICMP echo reply packet.

    Args:
        _vlan (VLAN): VLAN instance.
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
    pkt.payload = _ra_encode(cur_hop_limit=IPV6_MAX_HOP_LIM, 
                             flags=0, 
                             router_lifetime=1800,
                             reachable_time=0, 
                             retrans_timer=0, 
                             options=options)
    return pkt


class PacketMeta(object):
    """Original, and parsed Ethernet packet metadata."""

    def __init__(self, data, pkt, eth_pkt, port, valve_vlan, eth_src, eth_dst, eth_type):
        self.data = data
        self.pkt = pkt
        self.eth_pkt = eth_pkt
        self.port = port
        self.vlan = valve_vlan
        self.eth_src = eth_src
        self.eth_dst = eth_dst
        self.eth_type = eth_type

    def reparse(self, max_len):
        """Reparse packet using data up to the specified maximum length."""
        pass

    def reparse_all(self):
        """Reparse packet with all available data."""
        pass

    def reparse_ip(self, eth_type, payload=0):
        """Reparse packet with specified IP header type and optionally payload."""
        pass


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

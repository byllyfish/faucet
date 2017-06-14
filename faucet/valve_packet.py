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

from zof.pktview import make_pktview

try:
    from zof_constant import ether, mac, arp, inet, icmp, icmpv6, ofp
    from valve_util import btos
except ImportError:
    from faucet.zof_constant import ether, mac, arp, inet, icmp, icmpv6, ofp
    from faucet.valve_util import btos


IPV6_ALL_NODES_MCAST = '33:33:00:00:00:01'
IPV6_ALL_ROUTERS_MCAST = '33:33:00:00:00:02'
IPV6_LINK_LOCAL = ipaddress.IPv6Network(btos('fe80::/10'))
IPV6_ALL_NODES = ipaddress.IPv6Address(btos('ff02::1'))
IPV6_MAX_HOP_LIM = 255


def parse_pkt(pkt):
    """Return parsed Ethernet packet.

    Args:
        pkt (ryu.lib.packet.packet): packet received from dataplane.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet.
    """
    return pkt.get_protocol(ether.ether)


def parse_packet_in_pkt(data, max_len):
    """Parse a packet received via packet in from the dataplane.

    Args:
        data (bytearray): packet data from dataplane.
        max_len (int): max number of packet data bytes to parse.
    Returns:
        ryu.lib.packet.ethernet: Ethernet packet.
        int: VLAN VID.
    """
    pkt = None
    vlan_vid = None

    if max_len:
        data = data[:max_len]

    try:
        pkt = packet.Packet(data)
    except stream_parser.StreamParser.TooSmallException:
        return (pkt, vlan_vid)

    eth_pkt = parse_pkt(pkt)
    eth_type = eth_pkt.ethertype
    # Packet ins, can only come when a VLAN header has already been pushed
    # (ie. when we have progressed past the VLAN table). This gaurantees
    # a VLAN header will always be present, so we know which VLAN the packet
    # belongs to.
    if eth_type == ether.ETH_TYPE_8021Q:
        # tagged packet
        vlan_proto = pkt.get_protocols(vlan.vlan)[0]
        vlan_vid = vlan_proto.vid
    return (pkt, vlan_vid)


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


def _format_mac(value):  # FIXME(bfish): Unused...
    if isinstance(value, str):  # for python 2.7 compatibility
        return ':'.join('%02X' % ord(x) for x in value)
    return ':'.join('%02X' % x for x in value)


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
    pkt.hop_limit = 255
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
    # N.B. we assume data already contains them id_ and seq.
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

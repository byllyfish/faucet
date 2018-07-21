import unittest
from faucet.valve_packet import lacp_reqreply, parse_lacp_pkt, router_advert
import ipaddress
from zof.pktview import make_pktview


class ValvePacketTestCase(unittest.TestCase):

    def test_router_advert(self):
        args = dict(
            vid=None,
            eth_src='00:00:00:00:00:01',
            eth_dst='00:00:00:00:00:02',
            src_ip='2000::1',
            dst_ip='2000::2',
            vips=[ipaddress.ip_interface('1234:1234::1/80')]
        )
        pkt = router_advert(**args)
        self.assertEqual(pkt.eth_dst, '00:00:00:00:00:02')
        self.assertEqual(pkt.eth_src, '00:00:00:00:00:01')
        self.assertEqual(pkt.eth_type, 0x86dd)
        self.assertEqual(pkt.ipv6_src, '2000::1')
        self.assertEqual(pkt.ipv6_dst, '2000::2')
        self.assertEqual(pkt.ip_proto, 58)
        self.assertEqual(pkt.nx_ip_ttl, 255)
        self.assertEqual(pkt.icmpv6_type, 134)
        self.assertEqual(pkt.payload.hex(), 'ff0007080000000000000000030450c0000151800000384000000000123412340000000000000000000000000101000000000001')

    def test_lacp(self):
        args = dict(
            eth_src='00:00:00:00:00:01', 
            actor_system='00:00:00:00:00:02',
            actor_key=4,
            actor_port=5,
            partner_system='00:00:00:00:00:03',
            partner_key=6,
            partner_port=7,
            partner_system_priority=8,
            partner_port_priority=9,
            partner_state_defaulted=1,
            partner_state_expired=1,
            partner_state_timeout=1,
            partner_state_collecting=1,
            partner_state_distributing=1,
            partner_state_aggregation=1,
            partner_state_synchronization=1,
            partner_state_activity=1
        )
        pkt = lacp_reqreply(**args)
        self.assertEqual(pkt.eth_dst, '01:80:c2:00:00:02')
        self.assertEqual(pkt.eth_src, '00:00:00:00:00:01')
        self.assertEqual(pkt.eth_type, 0x8809)
        self.assertEqual(len(pkt.payload), 110)
        self.assertEqual(pkt.payload.hex(), '01010114ffff000000000002000400ff00053e00000002140008000000000003000600090007ff0000000310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')

        pkt = parse_lacp_pkt(pkt)
        self.assertEqual(pkt.actor_system_priority, 65535)
        self.assertEqual(pkt.actor_system, bytes.fromhex('000000000002'))
        self.assertEqual(pkt.actor_key, 4)
        self.assertEqual(pkt.actor_port_priority, 255)
        self.assertEqual(pkt.actor_port, 5)
        self.assertEqual(pkt.actor_state, 62)
        self.assertEqual(pkt.partner_system_priority, 8)
        self.assertEqual(pkt.partner_system, bytes.fromhex('000000000003'))
        self.assertEqual(pkt.partner_key, 6)
        self.assertEqual(pkt.partner_port_priority, 9)
        self.assertEqual(pkt.partner_port, 7)
        self.assertEqual(pkt.partner_state, 255)
        self.assertEqual(pkt.collector_max_delay, 0)

        self.assertEqual(pkt.actor_state_activity, 0)
        self.assertEqual(pkt.actor_state_timeout, 1)
        self.assertEqual(pkt.actor_state_aggregation, 1)
        self.assertEqual(pkt.actor_state_synchronization, 1)
        self.assertEqual(pkt.actor_state_collecting, 1)
        self.assertEqual(pkt.actor_state_distributing, 1)
        self.assertEqual(pkt.actor_state_defaulted, 0)
        self.assertEqual(pkt.actor_state_expired, 0)

    def test_parse_lacp_pkt(self):
        pkt = make_pktview(
            eth_type=34825, 
            vlan_pcp=0, 
            x_pkt_pos=18, 
            vlan_vid=4196, 
            eth_src='ca:8f:a8:99:89:d9', 
            payload=b'\x01\x01\x01\x14\xff\xff\x0e\x00\x00\x00\x00\x99\x00\r\x00\xff\x00\x01\xc7\x00\x00\x00\x02\x14\xff\xff\x00\x00\x00\x00\x00\x00\x00\x01\x00\xff\x00\x01\x03\x00\x00\x00\x03\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 
            eth_dst='01:80:c2:00:00:02'
        )
        self.assertEqual(len(pkt.payload), 78)
        
        pkt = parse_lacp_pkt(pkt)
        self.assertEqual(pkt, {'eth_type': 34825, 'vlan_pcp': 0, 'x_pkt_pos': 18, 'vlan_vid': 4196, 'eth_src': 'ca:8f:a8:99:89:d9', 'eth_dst': '01:80:c2:00:00:02', 'actor_system_priority': 65535, 'actor_system': b'\x0e\x00\x00\x00\x00\x99', 'actor_key': 13, 'actor_port_priority': 255, 'actor_port': 1, 'actor_state': 199, 'partner_system_priority': 65535, 'partner_system': b'\x00\x00\x00\x00\x00\x00', 'partner_key': 1, 'partner_port_priority': 255, 'partner_port': 1, 'partner_state': 3, 'collector_max_delay': 0, 'actor_state_activity': True, 'actor_state_timeout': True, 'actor_state_aggregation': True, 'actor_state_synchronization': False, 'actor_state_collecting': False, 'actor_state_distributing': False, 'actor_state_defaulted': True, 'actor_state_expired': True})

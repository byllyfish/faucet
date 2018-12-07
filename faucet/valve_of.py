"""Utility functions to parse/create OpenFlow messages."""

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
import random

from zof.pktview import pktview_to_list, pktview_from_ofctl, PktView
from zof.ofctl import MATCH_FIELDS

from faucet.conf import test_config_condition, InvalidConfigError
from faucet.zof_constant import ofp, ether, mac, inet
from faucet.valve_of_old import OLD_MATCH_FIELDS

MIN_VID = 1
MAX_VID = 4095
VLAN_GROUP_OFFSET = MAX_VID + 1
ROUTE_GROUP_OFFSET = VLAN_GROUP_OFFSET * 2
OFP_VERSIONS = [ofp.OFP_VERSION]
OFP_IN_PORT = ofp.OFPP_IN_PORT
MAX_PACKET_IN_BYTES = 128
ECTP_ETH_TYPE = 0x9000

'''
OFERROR_TYPE_CODE = {
    0: ('OFPET_HELLO_FAILED', {
        ofp.OFPHFC_INCOMPATIBLE: 'OFPHFC_INCOMPATIBLE',
        ofp.OFPHFC_EPERM: 'OFPHFC_EPERM'}),
    1: ('OFPET_BAD_REQUEST', {
        ofp.OFPBRC_BAD_VERSION: 'OFPBRC_BAD_VERSION',
        ofp.OFPBRC_BAD_TYPE: 'OFPBRC_BAD_TYPE',
        ofp.OFPBRC_BAD_MULTIPART: 'OFPBRC_BAD_MULTIPART',
        ofp.OFPBRC_BAD_EXPERIMENTER: 'OFPBRC_BAD_EXPERIMENTER',
        ofp.OFPBRC_BAD_EXP_TYPE: 'OFPBRC_BAD_EXP_TYPE',
        ofp.OFPBRC_EPERM: 'OFPBRC_EPERM',
        ofp.OFPBRC_BAD_LEN: 'OFPBRC_BAD_LEN',
        ofp.OFPBRC_BUFFER_EMPTY: 'OFPBRC_BUFFER_EMPTY',
        ofp.OFPBRC_BUFFER_UNKNOWN: 'OFPBRC_BUFFER_UNKNOWN',
        ofp.OFPBRC_BAD_TABLE_ID: 'OFPBRC_BAD_TABLE_ID',
        ofp.OFPBRC_IS_SLAVE: 'OFPBRC_IS_SLAVE',
        ofp.OFPBRC_BAD_PORT: 'OFPBRC_BAD_PORT',
        ofp.OFPBRC_BAD_PACKET: 'OFPBRC_BAD_PACKET',
        ofp.OFPBRC_MULTIPART_BUFFER_OVERFLOW: 'OFPBRC_MULTIPART_BUFFER_OVERFLOW'}),
    2: ('OFPET_BAD_ACTION', {
        ofp.OFPBAC_BAD_TYPE: 'OFPBAC_BAD_TYPE',
        ofp.OFPBAC_BAD_LEN: 'OFPBAC_BAD_LEN',
        ofp.OFPBAC_BAD_EXPERIMENTER: 'OFPBAC_BAD_EXPERIMENTER',
        ofp.OFPBAC_BAD_EXP_TYPE: 'OFPBAC_BAD_EXP_TYPE',
        ofp.OFPBAC_BAD_OUT_PORT: 'OFPBAC_BAD_OUT_PORT',
        ofp.OFPBAC_BAD_ARGUMENT: 'OFPBAC_BAD_ARGUMENT',
        ofp.OFPBAC_EPERM: 'OFPBAC_EPERM',
        ofp.OFPBAC_TOO_MANY: 'OFPBAC_TOO_MANY',
        ofp.OFPBAC_BAD_QUEUE: 'OFPBAC_BAD_QUEUE',
        ofp.OFPBAC_BAD_OUT_GROUP: 'OFPBAC_BAD_OUT_GROUP',
        ofp.OFPBAC_MATCH_INCONSISTENT: 'OFPBAC_MATCH_INCONSISTENT',
        ofp.OFPBAC_UNSUPPORTED_ORDER: 'OFPBAC_UNSUPPORTED_ORDER',
        ofp.OFPBAC_BAD_TAG: 'OFPBAC_BAD_TAG',
        ofp.OFPBAC_BAD_SET_TYPE: 'OFPBAC_BAD_SET_TYPE',
        ofp.OFPBAC_BAD_SET_LEN: 'OFPBAC_BAD_SET_LEN',
        ofp.OFPBAC_BAD_SET_ARGUMENT: 'OFPBAC_BAD_SET_ARGUMENT'}),
    3: ('OFPET_BAD_INSTRUCTION', {
        ofp.OFPBIC_UNKNOWN_INST: 'OFPBIC_UNKNOWN_INST',
        ofp.OFPBIC_UNSUP_INST: 'OFPBIC_UNSUP_INST',
        ofp.OFPBIC_BAD_TABLE_ID: 'OFPBIC_BAD_TABLE_ID',
        ofp.OFPBIC_UNSUP_METADATA: 'OFPBIC_UNSUP_METADATA',
        ofp.OFPBIC_UNSUP_METADATA_MASK: 'OFPBIC_UNSUP_METADATA_MASK',
        ofp.OFPBIC_BAD_EXPERIMENTER: 'OFPBIC_BAD_EXPERIMENTER',
        ofp.OFPBIC_BAD_EXP_TYPE: 'OFPBIC_BAD_EXP_TYPE',
        ofp.OFPBIC_BAD_LEN: 'OFPBIC_BAD_LEN',
        ofp.OFPBIC_EPERM: 'OFPBIC_EPERM'}),
    4: ('OFPET_BAD_MATCH', {
        ofp.OFPBMC_BAD_TYPE: 'OFPBMC_BAD_TYPE',
        ofp.OFPBMC_BAD_LEN: 'OFPBMC_BAD_LEN',
        ofp.OFPBMC_BAD_TAG: 'OFPBMC_BAD_TAG',
        ofp.OFPBMC_BAD_DL_ADDR_MASK: 'OFPBMC_BAD_DL_ADDR_MASK',
        ofp.OFPBMC_BAD_NW_ADDR_MASK: 'OFPBMC_BAD_NW_ADDR_MASK',
        ofp.OFPBMC_BAD_WILDCARDS: 'OFPBMC_BAD_WILDCARDS',
        ofp.OFPBMC_BAD_FIELD: 'OFPBMC_BAD_FIELD',
        ofp.OFPBMC_BAD_VALUE: 'OFPBMC_BAD_VALUE',
        ofp.OFPBMC_BAD_MASK: 'OFPBMC_BAD_MASK',
        ofp.OFPBMC_BAD_PREREQ: 'OFPBMC_BAD_PREREQ',
        ofp.OFPBMC_DUP_FIELD: 'OFPBMC_DUP_FIELD',
        ofp.OFPBMC_EPERM: 'OFPBMC_EPERM'}),
    5: ('OFPET_FLOW_MOD_FAILED', {
        ofp.OFPFMFC_UNKNOWN: 'OFPFMFC_UNKNOWN',
        ofp.OFPFMFC_TABLE_FULL: 'OFPFMFC_TABLE_FULL',
        ofp.OFPFMFC_BAD_TABLE_ID: 'OFPFMFC_BAD_TABLE_ID',
        ofp.OFPFMFC_OVERLAP: 'OFPFMFC_OVERLAP',
        ofp.OFPFMFC_EPERM: 'OFPFMFC_EPERM',
        ofp.OFPFMFC_BAD_TIMEOUT: 'OFPFMFC_BAD_TIMEOUT',
        ofp.OFPFMFC_BAD_COMMAND: 'OFPFMFC_BAD_COMMAND',
        ofp.OFPFMFC_BAD_FLAGS: 'OFPFMFC_BAD_FLAGS'}),
    6: ('OFPET_GROUP_MOD_FAILED', {
        ofp.OFPGMFC_GROUP_EXISTS: 'OFPGMFC_GROUP_EXISTS',
        ofp.OFPGMFC_INVALID_GROUP: 'OFPGMFC_INVALID_GROUP',
        ofp.OFPGMFC_WEIGHT_UNSUPPORTED: 'OFPGMFC_WEIGHT_UNSUPPORTED',
        ofp.OFPGMFC_OUT_OF_GROUPS: 'OFPGMFC_OUT_OF_GROUPS',
        ofp.OFPGMFC_OUT_OF_BUCKETS: 'OFPGMFC_OUT_OF_BUCKETS',
        ofp.OFPGMFC_CHAINING_UNSUPPORTED: 'OFPGMFC_CHAINING_UNSUPPORTED',
        ofp.OFPGMFC_WATCH_UNSUPPORTED: 'OFPGMFC_WATCH_UNSUPPORTED',
        ofp.OFPGMFC_LOOP: 'OFPGMFC_LOOP',
        ofp.OFPGMFC_UNKNOWN_GROUP: 'OFPGMFC_UNKNOWN_GROUP',
        ofp.OFPGMFC_CHAINED_GROUP: 'OFPGMFC_CHAINED_GROUP',
        ofp.OFPGMFC_BAD_TYPE: 'OFPGMFC_BAD_TYPE',
        ofp.OFPGMFC_BAD_COMMAND: 'OFPGMFC_BAD_COMMAND',
        ofp.OFPGMFC_BAD_BUCKET: 'OFPGMFC_BAD_BUCKET',
        ofp.OFPGMFC_BAD_WATCH: 'OFPGMFC_BAD_WATCH',
        ofp.OFPGMFC_EPERM: 'OFPGMFC_EPERM'}),
    7: ('OFPET_PORT_MOD_FAILED', {
        ofp.OFPPMFC_BAD_PORT: 'OFPPMFC_BAD_PORT',
        ofp.OFPPMFC_BAD_HW_ADDR: 'OFPPMFC_BAD_HW_ADDR',
        ofp.OFPPMFC_BAD_CONFIG: 'OFPPMFC_BAD_CONFIG',
        ofp.OFPPMFC_BAD_ADVERTISE: 'OFPPMFC_BAD_ADVERTISE',
        ofp.OFPPMFC_EPERM: 'OFPPMFC_EPERM'}),
    8: ('OFPET_TABLE_MOD_FAILED', {
        ofp.OFPTMFC_BAD_TABLE: 'OFPTMFC_BAD_TABLE',
        ofp.OFPTMFC_BAD_CONFIG: 'OFPTMFC_BAD_CONFIG',
        ofp.OFPTMFC_EPERM: 'OFPTMFC_EPERM'}),
    9: ('OFPET_QUEUE_OP_FAILED', {
        ofp.OFPQOFC_BAD_PORT: 'OFPQOFC_BAD_PORT',
        ofp.OFPQOFC_BAD_QUEUE: 'OFPQOFC_BAD_QUEUE',
        ofp.OFPQOFC_EPERM: 'OFPQOFC_EPERM'}),
    10: ('OFPET_SWITCH_CONFIG_FAILED', {
        ofp.OFPSCFC_BAD_FLAGS: 'OFPSCFC_BAD_FLAGS',
        ofp.OFPSCFC_BAD_LEN: 'OFPSCFC_BAD_LEN',
        ofp.OFPSCFC_EPERM: 'OFPSCFC_EPERM'}),
    11: ('OFPET_ROLE_REQUEST_FAILED', {
        ofp.OFPRRFC_STALE: 'OFPRRFC_STALE',
        ofp.OFPRRFC_UNSUP: 'OFPRRFC_UNSUP',
        ofp.OFPRRFC_BAD_ROLE: 'OFPRRFC_BAD_ROLE'}),
    12: ('OFPET_METER_MOD_FAILED', {
        ofp.OFPMMFC_UNKNOWN: 'OFPMMFC_UNKNOWN',
        ofp.OFPMMFC_METER_EXISTS: 'OFPMMFC_METER_EXISTS',
        ofp.OFPMMFC_INVALID_METER: 'OFPMMFC_INVALID_METER',
        ofp.OFPMMFC_UNKNOWN_METER: 'OFPMMFC_UNKNOWN_METER',
        ofp.OFPMMFC_BAD_COMMAND: 'OFPMMFC_BAD_COMMAND',
        ofp.OFPMMFC_BAD_FLAGS: 'OFPMMFC_BAD_FLAGS',
        ofp.OFPMMFC_BAD_RATE: 'OFPMMFC_BAD_RATE',
        ofp.OFPMMFC_BAD_BURST: 'OFPMMFC_BAD_BURST',
        ofp.OFPMMFC_BAD_BAND: 'OFPMMFC_BAD_BAND',
        ofp.OFPMMFC_BAD_BAND_VALUE: 'OFPMMFC_BAD_BAND_VALUE',
        ofp.OFPMMFC_OUT_OF_METERS: 'OFPMMFC_OUT_OF_METERS',
        ofp.OFPMMFC_OUT_OF_BANDS: 'OFPMMFC_OUT_OF_BANDS'}),
    13: ('OFPET_TABLE_FEATURES_FAILED', {
        ofp.OFPTFFC_BAD_TABLE: 'OFPTFFC_BAD_TABLE',
        ofp.OFPTFFC_BAD_METADATA: 'OFPTFFC_BAD_METADATA',
        ofp.OFPTFFC_BAD_TYPE: 'OFPTFFC_BAD_TYPE',
        ofp.OFPTFFC_BAD_LEN: 'OFPTFFC_BAD_LEN',
        ofp.OFPTFFC_BAD_ARGUMENT: 'OFPTFFC_BAD_ARGUMENT',
        ofp.OFPTFFC_EPERM: 'OFPTFFC_EPERM'}),
    65535: ('OFPET_EXPERIMENTER', {}),
}
'''

def ignore_port(port_num):
    """Return True if FAUCET should ignore this port.

    Args:
        port_num (int): switch port.
    Returns:
        bool: True if FAUCET should ignore this port.
    """
    # special case OFPP_LOCAL to allow FAUCET to manage switch admin interface.
    if port_num == 'LOCAL' or port_num == ofp.OFPP_LOCAL:
        return False
    # 0xF0000000 and up are not physical ports.
    return isinstance(port_num, str) or port_num > 0xF0000000


def port_status_from_state(state):
    """Return True if OFPPS_LINK_DOWN is not set."""
    assert isinstance(state, (list, tuple)), repr(state)
    return 'LINK_DOWN' not in state


def is_table_features_req(ofmsg):
    """Return True if flow message is a TFM req.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a TFM req.
    """
    assert isinstance(ofmsg, dict), repr(ofmsg)
    return ofmsg['type'] == 'REQUEST.TABLE_FEATURES'


def is_flowmod(ofmsg):
    """Return True if flow message is a FlowMod.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a FlowMod
    """
    assert isinstance(ofmsg, dict), repr(ofmsg)
    return ofmsg['type'] == 'FLOW_MOD'


def is_groupmod(ofmsg):
    """Return True if OF message is a GroupMod.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a GroupMod
    """
    assert isinstance(ofmsg, dict), repr(ofmsg)
    return ofmsg['type'] == 'GROUP_MOD'


def is_metermod(ofmsg):
    """Return True if OF message is a MeterMod.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a MeterMod
    """
    assert isinstance(ofmsg, dict), repr(ofmsg)
    return ofmsg['type'] == 'METER_MOD'


def is_packetout(ofmsg):
    """Return True if OF message is a PacketOut

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a PacketOut
    """
    assert isinstance(ofmsg, dict), repr(ofmsg)
    return ofmsg['type'] == 'PACKET_OUT'


def is_flowdel(ofmsg):
    """Return True if flow message is a FlowMod and a delete.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a FlowMod delete/strict.
    """
    return is_flowmod(ofmsg) and ofmsg['msg']['command'] in ('DELETE', 'DELETE_STRICT')


def is_groupdel(ofmsg):
    """Return True if OF message is a GroupMod and command is delete.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a GroupMod delete
    """
    return is_groupmod(ofmsg) and ofmsg['msg']['command'] == 'DELETE'


def is_meterdel(ofmsg):
    """Return True if OF message is a MeterMod and command is delete.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a MeterMod delete
    """
    return is_metermod(ofmsg) and ofmsg['msg']['command'] == 'DELETE'


def is_groupadd(ofmsg):
    """Return True if OF message is a GroupMod and command is add.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a GroupMod add
    """
    return is_groupmod(ofmsg) and ofmsg['msg']['command'] == 'ADD'


def is_meteradd(ofmsg):
    """Return True if OF message is a MeterMod and command is add.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a MeterMod add
    """
    return is_metermod(ofmsg) and ofmsg['msg']['command'] == 'ADD'


def is_apply_actions(instruction):
    """Return True if an apply action.

    Args:
        instruction: OpenFlow instruction.
    Returns:
        bool: True if an apply action.
    """
    return instruction['instruction'] == 'APPLY_ACTIONS'


def is_meter(instruction):
    """Return True if a meter.

    Args:
        instruction: OpenFlow instruction.
    Returns:
        bool: True if a meter.
    """
    return instruction['instruction'] == 'METER'


def is_set_field(action):
    return action['action'] == 'SET_FIELD'


def apply_meter(meter_id):
    """Return instruction to apply a meter."""
    return {'instruction': 'METER', 'meter_id': meter_id}


def apply_actions(actions):
    """Return instruction that applies action list.

    Args:
        actions (list): list of OpenFlow actions.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPInstruction: instruction of actions.
    """
    return {'instruction': 'APPLY_ACTIONS', 'actions': actions}


def goto_table(table):
    """Return instruction to goto table.

    Args:
        table (ValveTable): table to goto.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPInstruction: goto instruction.
    """
    return {'instruction': 'GOTO_TABLE', 'table_id': table.table_id}

def metadata_goto_table(metadata, mask, table):
    """Return instructions to write metadata and goto table.

    Args:
        metadata (int): metadata to write to packet
        maks (int): mask to apply to metadata
        table (ValveTable): table to goto.
    Returns:
        list of OFPInstructions"""
    return [
        {'instruction': 'WRITE_METADATA', 'metadata': metadata, 'mask': mask},
        goto_table(table)
        ]

def set_field(**kwds):
    """Return action to set any field.

    Args:
        kwds (dict): exactly one field to set
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionSetField: set field action.
    """
    assert len(kwds) == 1
    field, value = list(kwds.items())[0]
    test_config_condition(field not in MATCH_FIELDS, 'Unknown field name')
    return {'action':'SET_FIELD', 'field': field.upper(), 'value': value}


def vid_present(vid):
    """Return VLAN VID with VID_PRESENT flag set.

    Args:
        vid (int): VLAN VID
    Returns:
        int: VLAN VID with VID_PRESENT.
    """
    return vid | ofp.OFPVID_PRESENT


def devid_present(vid):
    """Return VLAN VID without VID_PRESENT flag set.

    Args:
        vid (int): VLAN VID with VID_PRESENT.
    Returns:
        int: VLAN VID.
    """
    return vid ^ ofp.OFPVID_PRESENT


def push_vlan_act(table, vlan_vid, eth_type=ether.ETH_TYPE_8021Q):
    """Return OpenFlow action list to push Ethernet 802.1Q header with VLAN VID.

    Args:
        vid (int): VLAN VID
    Returns:
        list: actions to push 802.1Q header with VLAN VID set.
    """
    return [
        {'action':'PUSH_VLAN', 'ethertype':eth_type},
        table.set_vlan_vid(vlan_vid),
    ]


def dec_ip_ttl():
    """Return OpenFlow action to decrement IP TTL.

    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionDecNwTtl: decrement IP TTL.
    """
    return {'action':'DEC_NW_TTL'}


def pop_vlan():
    """Return OpenFlow action to pop outermost Ethernet 802.1Q VLAN header.

    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionPopVlan: Pop VLAN.
    """
    return {'action':'POP_VLAN'}


def output_port(port_num, max_len=0):
    """Return OpenFlow action to output to a port.

    Args:
        port_num (int): port to output to.
        max_len (int): maximum length of packet to output (default no maximum).
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: output to port action.
    """
    return {'action':'OUTPUT', 'port_no':port_num, 'max_len':max_len}


def dedupe_output_port_acts(output_port_acts):
    """Deduplicate parser.OFPActionOutputs (because Ryu doesn't define __eq__).

    Args:
        list of ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: output to port actions.
    Returns:
        list of ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: output to port actions.
    """
    output_ports = {output_port_act['port_no'] for output_port_act in output_port_acts}
    return [output_port(port) for port in sorted(output_ports)]


def output_in_port():
    """Return OpenFlow action to output out input port.

    Returns:
       ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput.
    """
    return output_port(OFP_IN_PORT)


def output_controller(max_len=MAX_PACKET_IN_BYTES):
    """Return OpenFlow action to packet in to the controller.

    Args:
        max_len (int): max number of bytes from packet to output.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: packet in action.
    """
    return output_port('CONTROLLER', max_len)

def packetouts(port_nums, data):
    """Return OpenFlow action to mulltiply packet out to dataplane from controller.

    Args:
        port_num (list): ints, ports to output to.
        data (str): raw packet to output.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: packet out action.
    """
    random.shuffle(port_nums)
    return {
        'type': 'PACKET_OUT',
        'msg': {
            'buffer_id': 'NO_BUFFER',
            'in_port': 'CONTROLLER',
            'actions': [output_port(port_num) for port_num in port_nums],
            'data': b'',
            'pkt': data
        }
    }


def packetout(port_num, data):
    """Return OpenFlow action to packet out to dataplane from controller.

    Args:
        port_num (int): port to output to.
        data (str): raw packet to output.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: packet out action.
    """
    return packetouts([port_num], data)


def barrier():
    """Return OpenFlow barrier request.

    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPBarrierRequest: barrier request.
    """
    return {'type': 'BARRIER_REQUEST'}


def table_features(body):
    return {'type':'REQUEST.TABLE_FEATURES', 'msg':body}


def match(match_fields):
    """Return OpenFlow matches from dict.

    Args:
        match_fields (dict): match fields and values.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPMatch: matches.
    """
    return pktview_to_list(match_fields)


def match_from_dict(match_dict):
    try:
        return pktview_to_list(pktview_from_ofctl(match_dict, validate=True))
    except ValueError as ex:
        raise InvalidConfigError(str(ex))


def _match_ip_masked(ipa):
    if isinstance(ipa, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return (str(ipa.network_address), str(ipa.netmask))
    return (str(ipa.ip), str(ipa.netmask))


def build_match_dict(in_port=None, vlan=None, eth_type=None, eth_src=None,
                     eth_dst=None, eth_dst_mask=None, icmpv6_type=None,
                     nw_proto=None, nw_dst=None, metadata=None,
                     metadata_mask=None):
    match_dict = {}
    if in_port is not None:
        match_dict['in_port'] = in_port
    if vlan is not None:
        if vlan.vid == ofp.OFPVID_NONE:
            match_dict['vlan_vid'] = int(ofp.OFPVID_NONE)
        elif vlan.vid == ofp.OFPVID_PRESENT:
            match_dict['vlan_vid'] = (ofp.OFPVID_PRESENT, ofp.OFPVID_PRESENT)
        else:
            match_dict['vlan_vid'] = vid_present(vlan.vid)
    if eth_src is not None:
        match_dict['eth_src'] = eth_src
    if eth_dst is not None:
        if eth_dst_mask is not None:
            match_dict['eth_dst'] = (eth_dst, eth_dst_mask)
        else:
            match_dict['eth_dst'] = eth_dst
    if nw_proto is not None:
        match_dict['ip_proto'] = nw_proto
    if icmpv6_type is not None:
        match_dict['icmpv6_type'] = icmpv6_type
    if nw_dst is not None:
        nw_dst_masked = _match_ip_masked(nw_dst)
        if eth_type == ether.ETH_TYPE_ARP:
            match_dict['arp_tpa'] = str(nw_dst.ip)
        elif eth_type == ether.ETH_TYPE_IP:
            match_dict['ipv4_dst'] = nw_dst_masked
        else:
            match_dict['ipv6_dst'] = nw_dst_masked
    if eth_type is not None:
        match_dict['eth_type'] = eth_type
    if metadata is not None:
        if metadata_mask is not None:
            match_dict['metadata'] = (metadata, metadata_mask)
        else:
            match_dict['metadata'] = metadata
    return match_dict


def flowmod(cookie, command, table_id, priority, out_port, out_group,
            match_fields, inst, hard_timeout, idle_timeout, flags=0):
    """Return a FlowMod message."""
    return {
        'type': 'FLOW_MOD',
        'msg': {
            'cookie': cookie,
            'command': command,
            'table_id': table_id,
            'priority': priority,
            'out_port': out_port,
            'out_group': out_group,
            'match': match_fields,
            'instructions': inst,
            'hard_timeout': int(hard_timeout),
            'idle_timeout': int(idle_timeout),
            'flags': [flags]
        }
    }


def group_act(group_id):
    """Return an action to run a group."""
    return {'action':'GROUP', 'group_id': group_id}


def bucket(weight=0, watch_port=ofp.OFPP_ANY,
           watch_group=ofp.OFPG_ANY, actions=None):
    """Return a group action bucket with provided actions."""
    return {
        'weight': weight,
        'watch_port': watch_port,
        'watch_group': watch_group,
        'actions': actions
    }


def groupmod(datapath=None, type_=ofp.OFPGT_ALL, group_id=0, buckets=None):
    """Modify a group."""
    assert datapath is None
    return {
        'type': 'GROUP_MOD',
        'msg': {
            'command': ofp.OFPGC_MODIFY,
            'type': type_,
            'group_id': group_id,
            'buckets': buckets
        }
    }


def groupmod_ff(datapath=None, group_id=0, buckets=None):
    """Modify a fast failover group."""
    assert datapath is None
    return groupmod(datapath, type_=ofp.OFPGT_FF, group_id=group_id, buckets=buckets)


def groupadd(datapath=None, type_=ofp.OFPGT_ALL, group_id=0, buckets=None):
    """Add a group."""
    assert datapath is None
    return {
        'type': 'GROUP_MOD',
        'msg': {
            'command': ofp.OFPGC_ADD,
            'type': type_,
            'group_id': group_id,
            'buckets': buckets
        }
    }


def groupadd_ff(datapath=None, group_id=0, buckets=None):
    """Add a fast failover group."""
    assert datapath is None
    return groupadd(datapath, type_=ofp.OFPGT_FF, group_id=group_id, buckets=buckets)


def groupdel(datapath=None, group_id=ofp.OFPG_ALL):
    """Delete a group (default all groups)."""
    assert datapath is None
    return {
        'type': 'GROUP_MOD',
        'msg': {
            'command': ofp.OFPGC_DELETE,
            'type': 0,
            'group_id': group_id,
            'buckets': None
        }
    }


def meterdel(datapath=None, meter_id=ofp.OFPM_ALL):
    """Delete a meter (default all meters)."""
    assert datapath is None
    return {
        'type': 'METER_MOD',
        'msg': {
            'command': ofp.OFPMC_DELETE,
            'flags': [],
            'meter_id': meter_id,
            'bands': []
        }
    }


def meteradd(meter_conf):
    """Add a meter based on YAML configuration."""
    flags = meter_conf['flags']
    if not isinstance(flags, (list, tuple)):
        flags = [flags]
    return {
        'type': 'METER_MOD',
        'msg': {
            'command': 'ADD',
            'flags': flags,
            'meter_id': meter_conf['meter_id'],
            'bands': meter_conf['bands']
        }
    }


def controller_pps_meteradd(datapath=None, pps=0):
    """Add a PPS meter towards controller."""
    assert datapath is None
    return {
        'type': 'METER_MOD',
        'msg': {
            'command': ofp.OFPMC_ADD,
            'flags': ['PKTPS'],
            'meter_id': 'CONTROLLER',
            'bands': [{'type': 'DROP', 'rate': pps, 'burst_size': 0}]
        }
    }


def controller_pps_meterdel(datapath=None):
    """Delete a PPS meter towards controller."""
    assert datapath is None
    return {
        'type': 'METER_MOD',
        'msg': {
            'command': ofp.OFPMC_DELETE,
            'flags': ['PKTPS'],
            'meter_id': 'CONTROLLER'
        }
    }


def is_delete(ofmsg):
    return is_flowdel(ofmsg) or is_groupdel(ofmsg) or is_meterdel(ofmsg)


_MSG_KINDS = (
    ('packetout', is_packetout),
    ('delete', is_delete),
    ('tfm', is_table_features_req),
    ('groupadd', is_groupadd),
    ('meteradd', is_meteradd),
)


def _msg_kind(ofmsg):
    for kind, kind_func in _MSG_KINDS:
        if kind_func(ofmsg):
            return kind
    return 'other'


def _partition_ofmsgs(input_ofmsgs):
    """Partition input ofmsgs by kind."""
    by_kind = {}
    for ofmsg in input_ofmsgs:
        by_kind.setdefault(_msg_kind(ofmsg), []).append(ofmsg)
    return by_kind


def dedupe_ofmsgs(input_ofmsgs):
    """Return deduplicated ofmsg list."""
    # Built in comparison doesn't work until serialized() called
    deduped_input_ofmsgs = []
    input_ofmsgs_hashes = set()
    for ofmsg in input_ofmsgs:
        # Can't use dict or json comparison as may be nested
        ofmsg_str = _HashThing(ofmsg)
        if ofmsg_str in input_ofmsgs_hashes:
            continue
        deduped_input_ofmsgs.append(ofmsg)
        input_ofmsgs_hashes.add(ofmsg_str)
    return deduped_input_ofmsgs


# kind, random_order, suggest_barrier
_OFMSG_ORDER = (
    ('delete', False, True),
    ('tfm', False, True),
    ('groupadd', False, True),
    ('meteradd', False, True),
    ('other', False, False),
    ('packetout', True, False),
)


def _has_priority(ofmsg):
    msg = ofmsg.get('msg')
    if msg:
        return 'priority' in msg
    return False


def valve_flowreorder(input_ofmsgs, use_barriers=True):
    """Reorder flows for better OFA performance."""
    # Move all deletes to be first, and add one barrier,
    # while optionally randomizing order. Platforms that do
    # parallel delete will perform better and platforms that
    # don't will have at most only one barrier to deal with.
    output_ofmsgs = []
    by_kind = _partition_ofmsgs(dedupe_ofmsgs(input_ofmsgs))
    for kind, random_order, suggest_barrier in _OFMSG_ORDER:
        ofmsgs = by_kind.get(kind, [])
        if ofmsgs:
            if random_order:
                random.shuffle(ofmsgs)
            else:
                print(ofmsgs)
                with_priorities = [ofmsg for ofmsg in ofmsgs if _has_priority(ofmsg)]
                # If priority present, send highest priority first.
                if with_priorities:
                    with_priorities.sort(key=lambda ofmsg: ofmsg['msg']['priority'], reverse=True)
                    without_priorities = [ofmsg for ofmsg in ofmsgs if not _has_priority(ofmsg)]
                    ofmsgs = without_priorities + with_priorities
            output_ofmsgs.extend(ofmsgs)
            if use_barriers and suggest_barrier:
                output_ofmsgs.append(barrier())
    return output_ofmsgs


def group_flood_buckets(ports, untagged):
    buckets = []
    for port in ports:
        out_actions = []
        if untagged:
            out_actions.append(pop_vlan())
        out_actions.append(output_port(port.number))
        buckets.append(bucket(actions=out_actions))
    return buckets


def flood_tagged_port_outputs(ports, in_port=None, exclude_ports=None):
    """Return list of actions necessary to flood to list of tagged ports."""
    flood_acts = []
    if ports:
        for port in ports:
            if in_port is not None and port == in_port:
                if port.hairpin:
                    flood_acts.append(output_in_port())
                continue
            if exclude_ports and port in exclude_ports:
                continue
            flood_acts.append(output_port(port.number))
            flood_acts.extend(port.mirror_actions())
    return dedupe_output_port_acts(flood_acts)


def flood_untagged_port_outputs(ports, in_port=None, exclude_ports=None):
    """Return list of actions necessary to flood to list of untagged ports."""
    flood_acts = flood_tagged_port_outputs(
        ports, in_port=in_port, exclude_ports=exclude_ports)
    if flood_acts:
        flood_acts = [pop_vlan()] + flood_acts
    return flood_acts


def flood_port_outputs(tagged_ports, untagged_ports, in_port=None, exclude_ports=None):
    """Return actions for both tagged and untagged ports."""
    return (
        flood_tagged_port_outputs(tagged_ports, in_port, exclude_ports) +
        flood_untagged_port_outputs(untagged_ports, in_port, exclude_ports))


def faucet_config(datapath=None):  # pylint: disable=unused-argument
    """Return switch config for FAUCET."""
    return {
        'type': 'SET_CONFIG',
        'msg': {
            'flags': ['FRAG_NORMAL'],
            'miss_send_len': 0
        }
    }


def faucet_async(datapath=None, notify_flow_removed=False, packet_in=True, port_status=True):  # pylint: disable=unused-argument
    """Return async message config for FAUCET."""
    packet_in_mask = []
    if packet_in:
        packet_in_mask = ['APPLY_ACTION']
    port_status_mask = []
    if port_status:
        port_status_mask = ['ADD', 'DELETE', 'MODIFY']
    flow_removed_mask = []
    if notify_flow_removed:
        flow_removed_mask = ['IDLE_TIMEOUT', 'HARD_TIMEOUT']
    return {
        'type': 'SET_ASYNC',
        'msg': {
            'packet_in_master': packet_in_mask,
            'packet_in_slave': packet_in_mask,
            'port_status_master': port_status_mask,
            'port_status_slave': port_status_mask,
            'flow_removed_master': flow_removed_mask,
            'flow_removed_slave': flow_removed_mask
        }
    }


def desc_stats_request(datapath=None):
    """Query switch description."""
    assert datapath is None
    return {
        'type': 'REQUEST.DESC'
    }


# Support for hashing dictionaries.

def _hash_wrap(value):
    """Hash a dictionary recursively.

    Value is independent of iteration order for dicts, lists or tuples.
    """
    if isinstance(value, (dict, PktView)):
        return sum(hash(k) * 11 + _hash_wrap(v) * 7 for k, v in list(value.items()))
    if isinstance(value, (list, tuple)):
        return sum(_hash_wrap(v) * 7 for v in value)
    return hash(value)

class _HashThing(object):
    """Wraps unhashable dictionary/lists so they can be added to a set/dict."""

    def __init__(self, value):
        self.value = value
        self.hash = _hash_wrap(value)

    def __hash__(self):
        return self.hash

    def __eq__(self, other):
        return self.value == other.value

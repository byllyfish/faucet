# This file is an adaption of "faucet.py" to the "zof" framework. Much
# of the code is copied/adapted from faucet.py which is under an Apache 2.0
# license. This file retains the same license as "faucet.py".

import os
import asyncio
import argparse
import random

import zof
from zof.api_args import file_contents_type

try:
    from config_parser import dp_parser
    from config_parser_util import config_changed
    from valve_util import get_sys_prefix, get_logger, dpid_log
    from valve import valve_factory, SUPPORTED_HARDWARE
    import faucet_metrics
    import valve_of
except ImportError:
    from faucet.config_parser import dp_parser
    from faucet.config_parser_util import config_changed
    from faucet.valve_util import get_sys_prefix, get_logger, dpid_log
    from faucet.valve import valve_factory, SUPPORTED_HARDWARE
    from faucet import faucet_metrics
    from faucet import valve_of


APP = zof.Application('faucet', exception_fatal='faucet.exception')
APP.logname = 'faucet'
APP.config_file = None
APP.valves = None
APP.config_hashes = None
APP.metrics = faucet_metrics.FaucetMetrics()


def to_dpid(dpid):
    "Convert dpid to integer."""
    return int(dpid.replace(':', ''), 16)

def _load_configs(new_config_file):
    APP.config_file = new_config_file
    APP.config_hashes, new_dps = dp_parser(
        new_config_file, APP.logname)
    if new_dps is None:
        APP.logger.error('new config bad - rejecting')
        return
    deleted_valve_dpids = (
        set(list(APP.valves.keys())) -
        set([valve.dp_id for valve in new_dps]))
    for new_dp in new_dps:
        dp_id = new_dp.dp_id
        if dp_id in APP.valves:
            valve = APP.valves[dp_id]
            cold_start, flowmods = valve.reload_config(new_dp)
            # pylint: disable=no-member
            if flowmods:
                _send_flow_msgs(new_dp.dp_id, flowmods)
                if cold_start:
                    APP.metrics.faucet_config_reload_cold.labels(
                        dp_id=hex(dp_id)).inc()
                else:
                    APP.metrics.faucet_config_reload_warm.labels(
                        dp_id=hex(dp_id)).inc()
        else:
            # pylint: disable=no-member
            valve_cl = valve_factory(new_dp)
            if valve_cl is None:
                self.logger.error(
                    '%s hardware %s must be one of %s',
                    new_dp.name,
                    new_dp.hardware,
                    sorted(list(SUPPORTED_HARDWARE.keys())))
                continue
            else:
                valve = valve_cl(new_dp, APP.logname)
                APP.valves[dp_id] = valve
            APP.logger.info('Add new datapath %s', dpid_log(dp_id))
        APP.metrics.reset_dpid(dp_id)
        valve.update_config_metrics(APP.metrics)
    for deleted_valve_dpid in deleted_valve_dpids:
        APP.logger.info(
            'Deleting de-configured %s', dpid_log(deleted_valve_dpid))
        del APP.valves[deleted_valve_dpid]
        zof_dp = zof.find_datapath(deleted_valve_dpid)
        if zof_dp:
            zof_dp.close()
    #APP._bgp.reset(self.valves, self.metrics)

@APP.event('start')
def start(_):
    sysprefix = get_sys_prefix()
    APP.config_file = os.getenv('FAUCET_CONFIG', sysprefix + '/etc/ryu/faucet/faucet.yaml')

    logfile = os.getenv('FAUCET_LOG', sysprefix + '/var/log/ryu/faucet/faucet.log')
    exc_logfile = os.getenv('FAUCET_EXCEPTION_LOG', sysprefix + '/var/log/ryu/faucet/faucet_exception.log')

    APP.logger = get_logger(APP.logname, logfile, 'DEBUG', 0)
    get_logger('%s.exception' % APP.logname, exc_logfile, 'DEBUG', 1)

    # Set up a valve object for each datapath
    APP.valves = {}
    # Configure all Valves
    _load_configs(APP.config_file)

    zof.ensure_future(_periodic_task(_resolve_gateways, 2))
    zof.ensure_future(_periodic_task(_host_expire, 5))
    zof.ensure_future(_periodic_task(_advertise, 5))


@APP.message('channel_up')
def channel_up(event):
    dp_id = to_dpid(event.datapath_id)
    if dp_id not in APP.valves:
        APP.logger.error('Unknown datapath %s', dp_id)
        event.datapath.close()
        return    

    APP.metrics.of_dp_connections.labels(dp_id=hex(dp_id)).inc()

    up_port_nums = [port.port_no for port in event.datapath if port.up]
    flowmods = APP.valves[dp_id].datapath_connect(dp_id, up_port_nums)
    _send_flow_msgs(dp_id, flowmods)

    APP.metrics.dp_status.labels(dp_id=hex(dp_id)).set(1)


@APP.message('channel_down')
def channel_down(event):
    dp_id = to_dpid(event.datapath_id)
    if dp_id not in APP.valves:
        APP.logger.error('Unknown datapath %s', dp_id)
        return    

    APP.metrics.of_dp_disconnections.labels(dp_id=hex(dp_id)).inc()
    APP.metrics.dp_status.labels(dp_id=hex(dp_id)).set(0)
    APP.valves[dp_id].datapath_disconnect(dp_id)


@APP.message('features_reply')
def features_reply(event):
    dp_id = to_dpid(event.datapath_id)
    if dp_id not in APP.valves:
        APP.logger.error('Unknown datapath %s', dp_id)
        return

    flowmods = APP.valves[dp_id].switch_features(dp_id, event.msg)
    _send_flow_msgs(dp_id, flowmods)

@APP.message('packet_in')
def packet_in(event):
    dp_id = to_dpid(event.datapath_id)
    if dp_id not in APP.valves:
        APP.logger.error('Unknown datapath %s', dp_id)
        return

    msg = event.msg

    valve = APP.valves[dp_id]
    valve.ofchannel_log([event])

    pkt = msg.pkt
    in_port = msg.in_port

    try:
        vlan_vid = pkt.vlan_vid & 0x0fff
    except AttributeError:
        APP.logger.error('Missing VLAN header %r', pkt)
        return

    pkt_meta = valve.parse_rcv_packet(in_port, vlan_vid, pkt.eth_type, msg.data, pkt, pkt)

    APP.metrics.of_packet_ins.labels(dp_id=hex(dp_id)).inc()
    flowmods = valve.rcv_packet(dp_id, APP.valves, pkt_meta)
    _send_flow_msgs(dp_id, flowmods)
    valve.update_metrics(APP.metrics)


@APP.message('port_status')
def port_status(event):
    dp_id = to_dpid(event.datapath_id)
    if dp_id not in APP.valves:
        APP.logger.warning('Unknown datapath %s', dp_id)
        return

    msg = event.msg
    port_no = msg.port_no
    reason = msg.reason
    link_up = 'LINK_DOWN' not in msg.state
    valve = APP.valves[dp_id]

    flowmods = valve.port_status_handler(dp_id, port_no, reason, link_up)
    _send_flow_msgs(dp_id, flowmods)
    APP.metrics.port_status.labels(dp_id=hex(dp_id), port=port_no).set(link_up)


@APP.message('error')
def error(event):
    dp_id = to_dpid(event.datapath_id)
    if dp_id not in APP.valves:
        APP.logger.warning('Unknown datapath %s', dp_id)
        return

    msg = event.msg
    APP.metrics.of_errors.labels(dp_id=hex(dp_id)).inc()
    APP.valves[dp_id].ofchannel_log([event])
    APP.logger.error('OFPErrorMsg: %r', msg)


@APP.message('flow_removed')
def flow_removed(event):
    dp_id = to_dpid(event.datapath_id)
    if dp_id not in APP.valves:
        APP.logger.warning('Unknown datapath %s', dp_id)
        return

    msg = event.msg
    valve = APP.valves[dp_id]

    valve.ofchannel_log([event])
    if msg.reason == 'IDLE_TIMEOUT':
        flowmods = valve.flow_timeout(msg.table_id, msg.match)
        _send_flow_msgs(dp_id, flowmods)


@APP.event('signal', signal='SIGHUP')
def sig_hup(event):
    APP.logger.info('Signal event: %r', event)
    # Don't exit because of this signal.
    event.exit = False
    # Reload configuration.
    APP.logger.info('request to reload configuration')
    new_config_file = os.getenv('FAUCET_CONFIG', APP.config_file)
    if config_changed(APP.config_file, new_config_file, APP.config_hashes):
        APP.logger.info('configuration changed')
        _load_configs(new_config_file)
    else:
        APP.logger.info('configuration is unchanged, not reloading')
    # pylint: disable=no-member
    APP.metrics.faucet_config_reload_requests.inc()


async def _periodic_task(func, period, jitter=2):
    while True:
        func()
        await asyncio.sleep(period + random.randint(0, jitter))


def _resolve_gateways():
    for dp_id, valve in list(APP.valves.items()):
        flowmods = valve.resolve_gateways()
        if flowmods:
            _send_flow_msgs(dp_id, flowmods)


def _host_expire():
    for valve in list(APP.valves.values()):
        valve.host_expire()
        valve.update_metrics(APP.metrics)


def _advertise():
    """Handle a request to advertise services."""
    for dp_id, valve in list(APP.valves.items()):
        flowmods = valve.advertise()
        if flowmods:
            _send_flow_msgs(dp_id, flowmods)


def _send_flow_msgs(dp_id, flow_msgs):
    if dp_id not in APP.valves:
        APP.logger.error('send_flow_msgs: unknown %s', dpid_log(dp_id))
        return
    valve = APP.valves[dp_id]
    reordered_flow_msgs = valve_of.valve_flowreorder(flow_msgs)
    valve.ofchannel_log(reordered_flow_msgs)
    if not reordered_flow_msgs:
        return
    last = reordered_flow_msgs[-1]
    for msg in reordered_flow_msgs:
        APP.metrics.of_flowmsgs_sent.labels(dp_id=hex(dp_id)).inc()
        if msg is not last:
            msg['flags'] = ['NO_FLUSH']
        zof.compile(msg).send(datapath_id=hex(dp_id))


def main():
    args = parse_args()
    if args.wsapi_port:
        from zof.demo.rest_api import APP as rest_app
        rest_app.http_endpoint = '%s:%d' % (args.wsapi_host or '', args.wsapi_port)

    # Map ryu arguments to framework's argument names.
    args.listen_endpoints = ['%s:%d' % (args.ofp_listen_host, args.ofp_tcp_listen_port)]
    args.listen_cert = args.ctl_cert
    args.listen_cacert = args.ca_certs
    args.listen_privkey = args.ctl_privkey
    args.listen_versions = [4]
    args.pidfile = args.pid_file
    zof.run(args=args)


def parse_args():
    # Add RYU compatible arguments.
    import zof.demo.metrics
    args = argparse.ArgumentParser(parents=[zof.common_args()])
    args.add_argument('--verbose', action='store_true')
    args.add_argument('--use-stderr', action='store_true')
    args.add_argument('--wsapi-host')
    args.add_argument('--wsapi-port', type=int)
    args.add_argument('--ofp-listen-host', default='')
    args.add_argument('--ofp-tcp-listen-port', type=int, default=6653)
    args.add_argument('--ctl-privkey', type=file_contents_type)
    args.add_argument('--ctl-cert', type=file_contents_type)
    args.add_argument('--ca-certs', type=file_contents_type)
    args.add_argument('--pid-file')
    metrics_endpoint = '%s:%s' % (os.getenv('FAUCET_PROMETHEUS_ADDR', ''), os.getenv('FAUCET_PROMETHEUS_PORT', '9302'))
    args.set_defaults(metrics_endpoint=metrics_endpoint)
    return args.parse_args()


if __name__ == '__main__':
    main()

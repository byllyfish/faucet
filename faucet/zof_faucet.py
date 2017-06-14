# This file is an adaption of "faucet.py" to the "zof" framework. Much
# of the code is copied/adapted from faucet.py which is under an Apache 2.0
# license. This file retains the same license as "faucet.py".

import os
import asyncio
import argparse
import random
import zof
from zof.api_args import file_contents_type

from valve_util import get_sys_prefix, get_logger, dpid_log
from config_parser import dp_parser
from config_parser_util import config_file_hash, config_changed
from valve import valve_factory
from faucet_metrics import FaucetMetrics


app = zof.Application('faucet', exception_fatal='faucet.exception')
app.logname = 'faucet'
app.config_file = None
app.valves = None
app.config_hashes = None
app.metrics = FaucetMetrics(0, '')


def to_dpid(dpid):
    "Convert dpid to integer."""
    return int(dpid.replace(':', ''), 16)

def _load_configs(new_config_file):
    app.config_file = new_config_file
    app.config_hashes, new_dps = dp_parser(
        new_config_file, app.logname)
    if new_dps is None:
        app.logger.error('new config bad - rejecting')
        return
    deleted_valve_dpids = (
        set(list(app.valves.keys())) -
        set([valve.dp_id for valve in new_dps]))
    for new_dp in new_dps:
        dp_id = new_dp.dp_id
        if dp_id in app.valves:
            valve = app.valves[dp_id]
            cold_start, flowmods = valve.reload_config(new_dp)
            # pylint: disable=no-member
            if flowmods:
                _send_flow_msgs(new_dp.dp_id, flowmods)
                if cold_start:
                    app.metrics.faucet_config_reload_cold.labels(
                        dpid=hex(dp_id)).inc()
                else:
                    app.metrics.faucet_config_reload_warm.labels(
                        dpid=hex(dp_id)).inc()
        else:
            # pylint: disable=no-member
            valve_cl = valve_factory(new_dp)
            if valve_cl is None:
                app.logger.fatal('Could not configure %s', new_dp.name)
            else:
                valve = valve_cl(new_dp, app.logname)
                app.valves[dp_id] = valve
            app.logger.info('Add new datapath %s', dpid_log(dp_id))
        valve.update_config_metrics(app.metrics)
    for deleted_valve_dpid in deleted_valve_dpids:
        app.logger.info(
            'Deleting de-configured %s', dpid_log(deleted_valve_dpid))
        del app.valves[deleted_valve_dpid]
        zof_dp = zof.find_datapath(deleted_valve_dpid)
        if zof_dp:
            zof_dp.close()
    #app._bgp.reset(self.valves, self.metrics)

@app.event('start')
def start(_):
    sysprefix = get_sys_prefix()
    app.config_file = os.getenv('FAUCET_CONFIG', sysprefix + '/etc/ryu/faucet/faucet.yaml')

    logfile = os.getenv('FAUCET_LOG', sysprefix + '/var/log/ryu/faucet/faucet.log')
    exc_logfile = os.getenv('FAUCET_EXCEPTION_LOG', sysprefix + '/var/log/ryu/faucet/faucet_exception.log')

    app.logger = get_logger(app.logname, logfile, 'DEBUG', 0)
    get_logger('%s.exception' % app.logname, exc_logfile, 'DEBUG', 1)

    # Set up a valve object for each datapath
    app.valves = {}
    # Configure all Valves
    _load_configs(app.config_file)

    zof.ensure_future(_periodic_task(_resolve_gateways, 2))
    zof.ensure_future(_periodic_task(_host_expire, 5))
    zof.ensure_future(_periodic_task(_advertise, 5))


@app.message('channel_up')
def channel_up(event):
    dp_id = to_dpid(event.datapath_id)
    if not dp_id in app.valves:
        app.logger.error('Unknown datapath %s', dp_id)
        event.datapath.close()
        return    

    app.metrics.of_dp_connections.labels(dpid=hex(dp_id)).inc()

    up_port_nums = [port.port_no for port in event.datapath if port.up]
    flowmods = app.valves[dp_id].datapath_connect(dp_id, up_port_nums)
    _send_flow_msgs(dp_id, flowmods)

    app.metrics.dp_status.labels(dpid=hex(dp_id)).set(1)


@app.message('channel_down')
def channel_down(event):
    dp_id = to_dpid(event.datapath_id)
    if not dp_id in app.valves:
        app.logger.error('Unknown datapath %s', dp_id)
        return    

    app.metrics.of_dp_disconnections.labels(dpid=hex(dp_id)).inc()
    app.metrics.dp_status.labels(dpid=hex(dp_id)).set(0)
    app.valves[dp_id].datapath_disconnect(dp_id)


@app.message('features_reply')
def features_reply(event):
    dp_id = to_dpid(event.datapath_id)
    if not dp_id in app.valves:
        app.logger.error('Unknown datapath %s', dp_id)
        return

    flowmods = app.valves[dp_id].switch_features(dp_id, event.msg)
    _send_flow_msgs(dp_id, flowmods)

@app.message('packet_in')
def packet_in(event):
    dp_id = to_dpid(event.datapath_id)
    if not dp_id in app.valves:
        app.logger.error('Unknown datapath %s', dp_id)
        return

    msg = event.msg

    valve = app.valves[dp_id]
    valve.ofchannel_log([event])

    pkt = msg.pkt
    in_port = msg.in_port

    try:
        vlan_vid = pkt.vlan_vid & 0x0fff
    except AttributeError:
        app.logger.error('Missing VLAN header %r', pkt)
        return

    pkt_meta = valve.parse_rcv_packet(in_port, vlan_vid, msg.data, pkt)

    app.metrics.of_packet_ins.labels(dpid=hex(dp_id)).inc()
    flowmods = valve.rcv_packet(dp_id, app.valves, pkt_meta)
    _send_flow_msgs(dp_id, flowmods)
    valve.update_metrics(app.metrics)


@app.message('port_status')
def port_status(event):
    dp_id = to_dpid(event.datapath_id)
    if not dp_id in app.valves:
        app.logger.warning('Unknown datapath %s', dp_id)
        return

    msg = event.msg
    port_no = msg.port_no
    reason = msg.reason
    link_up = 'LINK_DOWN' not in msg.state
    valve = app.valves[dp_id]

    flowmods = valve.port_status_handler(dp_id, port_no, reason, link_up)
    _send_flow_msgs(dp_id, flowmods)
    app.metrics.port_status.labels(dpid=hex(dp_id), port=port_no).set(link_up)


@app.message('error')
def error(event):
    dp_id = to_dpid(event.datapath_id)
    if not dp_id in app.valves:
        app.logger.warning('Unknown datapath %s', dp_id)
        return

    msg = event.msg
    app.metrics.of_errors.labels(dpid=hex(dp_id)).inc()
    app.valves[dp_id].ofchannel_log([msg])
    app.logger.error('OFPErrorMsg: %r', msg)

@app.event('signal', signal='SIGHUP')
def sig_hup(event):
    app.logger.info('Signal event: %r', event)
    # Don't exit because of this signal.
    event.exit = False
    # Reload configuration.
    app.logger.info('request to reload configuration')
    new_config_file = os.getenv('FAUCET_CONFIG', app.config_file)
    if config_changed(app.config_file, new_config_file, app.config_hashes):
        app.logger.info('configuration changed')
        _load_configs(new_config_file)
    else:
        app.logger.info('configuration is unchanged, not reloading')
    # pylint: disable=no-member
    app.metrics.faucet_config_reload_requests.inc()


async def _periodic_task(func, period, jitter=2):
    while True:
        func()
        await asyncio.sleep(period + random.randint(0, jitter))


def _resolve_gateways():
    for dp_id, valve in list(app.valves.items()):
        flowmods = valve.resolve_gateways()
        if flowmods:
            _send_flow_msgs(dp_id, flowmods)


def _host_expire():
    for valve in list(app.valves.values()):
        valve.host_expire()
        valve.update_metrics(app.metrics)


def _advertise():
    """Handle a request to advertise services."""
    for dp_id, valve in list(app.valves.items()):
        flowmods = valve.advertise()
        if flowmods:
            _send_flow_msgs(dp_id, flowmods)


def _send_flow_msgs(dp_id, flow_msgs):
    if dp_id not in app.valves:
        app.logger.error('send_flow_msgs: unknown %s', dp_id)
        return
    valve = app.valves[dp_id]
    flow_msgs = valve.valve_flowreorder(flow_msgs)
    valve.ofchannel_log(flow_msgs)
    #app.logger.info('_send_flow_msgs: %s %r', dp_id, flow_msgs)
    for msg in flow_msgs:
        app.metrics.of_flowmsgs_sent.labels(dpid=hex(dp_id)).inc()
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
    metrics_endpoint = '%s:%s' % (os.getenv('FAUCET_PROMETHEUS_ADDR', ''), os.getenv('FAUCET_PROMETHEUS_PORT', '9244'))
    args.set_defaults(metrics_endpoint=metrics_endpoint)
    return args.parse_args()


if __name__ == '__main__':
    main()

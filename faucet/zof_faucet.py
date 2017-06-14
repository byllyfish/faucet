# This file is an adaption of "faucet.py" to the "zof" framework. Much
# of the code is copied/adapted from faucet.py which is under an Apache 2.0
# license. This file retains the same license as "faucet.py".

import asyncio
import argparse
import random
import time

import zof
from zof.api_args import file_contents_type

from faucet.conf import InvalidConfigError
from faucet.config_parser import dp_parser, get_config_for_api
from faucet.config_parser_util import config_changed
from faucet.valve_util import get_setting, get_bool_setting, get_logger, dpid_log
from faucet.valve import valve_factory, SUPPORTED_HARDWARE
from faucet import faucet_metrics
from faucet import valve_of
from faucet import valve_util
from faucet import faucet_experimental_api

APP = zof.Application('faucet', exception_fatal='faucet.exception')
APP.logname = 'faucet'
APP.config_file = None
APP.stat_reload = False
APP.valves = None
APP.config_hashes = None
APP.config_file_stats = None
APP.metrics = faucet_metrics.FaucetMetrics()
APP.api = faucet_experimental_api.FaucetExperimentalAPI()


def to_dpid(dpid):
    "Convert dpid to integer."""
    return int(dpid.replace(':', ''), 16)


def _apply_configs(new_dps):
    """Actually apply configs."""
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
                        **valve.base_prom_labels).inc()
                else:
                    APP.metrics.faucet_config_reload_warm.labels(
                        **valve.base_prom_labels).inc()
        else:
            # pylint: disable=no-member
            valve_cl = valve_factory(new_dp)
            if valve_cl is None:
                APP.logger.error(
                    '%s hardware %s must be one of %s',
                    new_dp.name,
                    new_dp.hardware,
                    sorted(list(SUPPORTED_HARDWARE.keys())))
                continue
            else:
                valve = valve_cl(new_dp, APP.logname)
                APP.valves[dp_id] = valve
            APP.logger.info('Add new datapath %s', dpid_log(dp_id))
        APP.metrics.reset_dpid(valve.base_prom_labels)
        valve.update_config_metrics(APP.metrics)
    for deleted_valve_dpid in deleted_valve_dpids:
        APP.logger.info(
            'Deleting de-configured %s', dpid_log(deleted_valve_dpid))
        del APP.valves[deleted_valve_dpid]
        zof_dp = zof.find_datapath(datapath_id=deleted_valve_dpid)
        if zof_dp:
            zof_dp.close()
    #APP._bgp.reset(self.valves, self.metrics)


def _load_configs(new_config_file):
    try:
        new_config_hashes, new_dps = dp_parser(new_config_file, APP.logname)
        APP.config_file = new_config_file
        APP.config_hashes = new_config_hashes
        _apply_configs(new_dps)

    except InvalidConfigError as err:
        APP.logger.error('New config bad (%s) - rejecting' % err)
        return


@APP.event('start')
def start(_):
    APP.config_file = get_setting('FAUCET_CONFIG')
    logfile = get_setting('FAUCET_LOG')
    loglevel = get_setting('FAUCET_LOG_LEVEL')
    exc_logfile = get_setting('FAUCET_EXCEPTION_LOG')
    APP.stat_reload = get_bool_setting('FAUCET_CONFIG_STAT_RELOAD')

    # Setup logging
    APP.logger = get_logger(APP.logname, logfile, loglevel, 0)
    # Set up separate logging for exceptions
    get_logger('%s.exception' % APP.logname, exc_logfile, 'DEBUG', 1)

    # Set up a valve object for each datapath
    APP.valves = {}
    # Configure all Valves
    _load_configs(APP.config_file)

    zof.ensure_future(_periodic_task(_resolve_gateways, 2))
    zof.ensure_future(_periodic_task(_state_expire, 5))
    zof.ensure_future(_periodic_task(_metric_update, 5))
    zof.ensure_future(_periodic_task(_advertise, 5))
    zof.ensure_future(_periodic_task(_config_file_stat, 3))

    # Register to API
    APP.reload_config = _reload_config
    APP.get_config = _get_config
    APP.get_tables = _get_tables
    APP.api._register(APP)
    zof.post_event({'event': 'FAUCET_API_READY', 'faucet_api': APP.api})


@APP.message('channel_up')
def channel_up(event):
    dp_id = to_dpid(event['datapath_id'])
    datapath = event['datapath']
    if dp_id not in APP.valves:
        APP.logger.error('Unknown datapath %s', dp_id)
        datapath.close()
        return

    valve = APP.valves[dp_id]
    up_port_nums = [port.port_no for port in datapath if port.up]
    flowmods = valve.datapath_connect(up_port_nums)
    _send_flow_msgs(dp_id, flowmods)

    APP.metrics.of_dp_connections.labels(**valve.base_prom_labels).inc()
    APP.metrics.dp_status.labels(**valve.base_prom_labels).set(1)


@APP.message('channel_down')
def channel_down(event):
    dp_id = to_dpid(event['datapath_id'])
    if dp_id not in APP.valves:
        APP.logger.error('Unknown datapath %s', dp_id)
        return    

    valve = APP.valves[dp_id]
    APP.metrics.of_dp_disconnections.labels(**valve.base_prom_labels).inc()
    APP.metrics.dp_status.labels(**valve.base_prom_labels).set(0)
    valve.datapath_disconnect()


@APP.message('features_reply')
def features_reply(event):
    dp_id = to_dpid(event['datapath_id'])
    if dp_id not in APP.valves:
        APP.logger.error('Unknown datapath %s', dp_id)
        return

    flowmods = APP.valves[dp_id].switch_features(event['msg'])
    _send_flow_msgs(dp_id, flowmods)

@APP.message('packet_in')
def packet_in(event):
    dp_id = to_dpid(event['datapath_id'])
    if dp_id not in APP.valves:
        APP.logger.error('Unknown datapath %s', dp_id)
        return

    valve = APP.valves[dp_id]
    assert valve.dp.running
    valve.ofchannel_log([event])

    msg = event['msg']
    pkt = msg['pkt']
    in_port = msg['in_port']
    if valve_of.ignore_port(in_port):
        return

    data = msg['data']
    total_len = msg['total_len']

    if 'vlan_vid' not in pkt:
        APP.logger.error('Missing VLAN header %r', pkt)
        return        
    vlan_vid = pkt.vlan_vid & 0x0fff
    if vlan_vid not in valve.dp.vlans:
        APP.logger.info('packet for unknown VLAN %u from %s', vlan_vid, dpid_log(dp_id))
        return

    pkt_meta = valve.parse_rcv_packet(in_port, vlan_vid, pkt.eth_type, data, total_len, pkt, pkt)
    other_valves = [other_valve for other_valve in list(APP.valves.values()) if valve != other_valve]

    APP.metrics.of_packet_ins.labels(**valve.base_prom_labels).inc()
    packet_in_start = time.time()
    flowmods = valve.rcv_packet(other_valves, pkt_meta)
    packet_in_stop = time.time()
    APP.metrics.faucet_packet_in_secs.labels(**valve.base_prom_labels).observe(packet_in_stop - packet_in_start)
    _send_flow_msgs(dp_id, flowmods)
    valve.update_metrics(APP.metrics)


@APP.message('reply.desc')
def desc_stats_reply_handler(event):
    dp_id = to_dpid(event['datapath_id'])
    if dp_id not in APP.valves:
        APP.logger.warning('Unknown datapath %s', dp_id)
        return

    msg = event['msg']
    valve = APP.valves[dp_id]
    APP.metrics.of_dp_desc_stats.labels( # pylint: disable=no-member
        **dict(valve.base_prom_labels,
               mfr_desc=msg['mfr_desc'],
               hw_desc=msg['hw_desc'],
               sw_desc=msg['sw_desc'],
               serial_num=msg['serial_num'],
               dp_desc=msg['dp_desc'])).set(dp_id)


@APP.message('port_status')
def port_status(event):
    dp_id = to_dpid(event['datapath_id'])
    if dp_id not in APP.valves:
        APP.logger.warning('Unknown datapath %s', dp_id)
        return

    msg = event['msg']
    port_no = msg['port_no']
    reason = msg['reason']
    link_up = 'LINK_DOWN' not in msg['state']
    valve = APP.valves[dp_id]
    assert valve.dp.running

    flowmods = valve.port_status_handler(port_no, reason, link_up)
    _send_flow_msgs(dp_id, flowmods)
    port_labels = dict(valve.base_prom_labels, port=port_no)
    APP.metrics.port_status.labels(**port_labels).set(link_up)


@APP.message('error')
def error(event):
    dp_id = to_dpid(event['datapath_id'])
    if dp_id not in APP.valves:
        APP.logger.warning('Unknown datapath %s', dp_id)
        return

    valve = APP.valves[dp_id]
    msg = event['msg']
    APP.metrics.of_errors.labels(**valve.base_prom_labels).inc()
    valve.ofchannel_log([event])
    APP.logger.error('OFPErrorMsg: %r', msg)


@APP.message('flow_removed')
def flow_removed(event):
    dp_id = to_dpid(event['datapath_id'])
    if dp_id not in APP.valves:
        APP.logger.warning('Unknown datapath %s', dp_id)
        return

    msg = event['msg']
    valve = APP.valves[dp_id]
    assert valve.dp.running

    valve.ofchannel_log([event])
    if msg.reason == 'IDLE_TIMEOUT':
        flowmods = valve.flow_timeout(msg['table_id'], msg['match'])
        _send_flow_msgs(dp_id, flowmods)


@APP.event('signal', signal='SIGHUP')
def sig_hup(event):
    APP.logger.info('Signal event: %r', event)
    # Don't exit because of this signal.
    event['exit'] = False
    _reload_config(None)


# This function is called by the FaucetExperimentalAPI.
def _reload_config(_ignore):
    APP.logger.info('request to reload configuration')
    new_config_file = APP.config_file
    if config_changed(APP.config_file, new_config_file, APP.config_hashes):
        APP.logger.info('configuration changed')
        _load_configs(new_config_file)
    else:
        APP.logger.info('configuration is unchanged, not reloading')
    # pylint: disable=no-member
    APP.metrics.faucet_config_reload_requests.inc()


# This function is called by the FaucetExperimentalAPI.
def _get_config():
    """FAUCET experimental API: return config for all Valves."""
    return get_config_for_api(APP.valves)


# This function is called by the FaucetExperimentalAPI.
def _get_tables(dp_id):
    """FAUCET experimental API: return config tables for one Valve."""
    return APP.valves[dp_id].dp.get_tables()


async def _periodic_task(func, period, jitter=2):
    while True:
        func()
        await asyncio.sleep(period + random.randint(0, jitter))


def _resolve_gateways():
    for dp_id, valve in list(APP.valves.items()):
        flowmods = valve.resolve_gateways()
        if flowmods:
            _send_flow_msgs(dp_id, flowmods)


def _state_expire():
    for dp_id, valve in list(APP.valves.items()):
        flowmods = valve.state_expire()
        if flowmods:
            _send_flow_msgs(dp_id, flowmods)
        valve.update_metrics(APP.metrics)


def _metric_update():
    """Handle a request to update metrics in the controller."""
    #self._bgp.update_metrics()
    for valve in list(APP.valves.values()):
        valve.update_metrics(APP.metrics)


def _advertise():
    """Handle a request to advertise services."""
    for dp_id, valve in list(APP.valves.items()):
        flowmods = valve.advertise()
        if flowmods:
            _send_flow_msgs(dp_id, flowmods)


def _config_file_stat():
    """Periodically stat config files for any changes."""
    if APP.config_hashes:
        new_config_file_stats = valve_util.stat_config_files(APP.config_hashes)
        if APP.config_file_stats:
            if new_config_file_stats != APP.config_file_stats:
                APP.logger.info('config file(s) changed on disk')
                if APP.stat_reload:
                    _reload_config(None)
        APP.config_file_stats = new_config_file_stats


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
        APP.metrics.of_flowmsgs_sent.labels(**valve.base_prom_labels).inc()
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
    args = argparse.ArgumentParser(parents=[zof.common_args(include_x_modules=True)])
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
    args.add_argument('--config-file')
    metrics_endpoint = '%s:%s' % (get_setting('FAUCET_PROMETHEUS_ADDR'), get_setting('FAUCET_PROMETHEUS_PORT'))
    args.set_defaults(metrics_endpoint=metrics_endpoint)
    return args.parse_args()


if __name__ == '__main__':
    main()

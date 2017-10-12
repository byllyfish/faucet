import time
import os
import argparse

import zof

try:
    from config_parser import watcher_parser
    from gauge_prom import GaugePrometheusClient
    from valve_util import dpid_log, get_sys_prefix, get_logger
    from watcher import watcher_factory
except ImportError:
    from faucet.config_parser import watcher_parser
    from faucet.gauge_prom import GaugePrometheusClient
    from faucet.valve_util import dpid_log, get_sys_prefix, get_logger
    from faucet.watcher import watcher_factory


def to_dpid(dpid):
    """Convert long form dpid to integer.
    """
    return int(dpid.replace(':', ''), 16)


APP = zof.Application('gauge', exception_fatal='gauge.exception')
APP.logname = 'gauge'
APP.watchers = None
APP.prom_client = GaugePrometheusClient()
APP.config_file = None


@APP.event('start')
def start(event):
    sysprefix = get_sys_prefix()
    APP.config_file = os.getenv('GAUGE_CONFIG', sysprefix + '/etc/ryu/faucet/gauge.yaml')

    exc_logfile = os.getenv('GAUGE_EXCEPTION_LOG', sysprefix + '/var/log/ryu/faucet/gauge_exception.log')
    if exc_logfile:
        get_logger('%s.exception' % APP.logname, exc_logfile, 'DEBUG', 0)
    logfile = os.getenv('GAUGE_LOG', sysprefix + '/var/log/ryu/faucet/gauge.log')
    if logfile:
        APP.logger = get_logger(APP.logname, logfile, 'DEBUG', 1)

    APP.watchers = {}
    _load_config()


def _load_config():
    """Load Gauge config."""
    APP.config_file = os.getenv('GAUGE_CONFIG', APP.config_file)
    new_confs = watcher_parser(APP.config_file, APP.logname, APP.prom_client)
    new_watchers = {}

    for conf in new_confs:
        watcher = watcher_factory(conf)(conf, APP.logname, APP.prom_client)
        watcher_dpid = watcher.dp.dp_id

        datapath = zof.find_datapath(datapath_id=watcher_dpid)
        watcher_type = watcher.conf.type
        watcher_msg = '%s %s watcher' % (dpid_log(watcher_dpid), watcher_type)

        if watcher_dpid not in new_watchers:
            new_watchers[watcher_dpid] = {}

        if (watcher_dpid in APP.watchers and
                watcher_type in APP.watchers[watcher_dpid]):
            old_watcher = APP.watchers[watcher_dpid][watcher_type]
            if old_watcher.running():
                APP.logger.info('%s stopped', watcher_msg)
                old_watcher.stop()
            del APP.watchers[watcher_dpid][watcher_type]

        new_watchers[watcher_dpid][watcher_type] = watcher
        if datapath is None:
            APP.logger.info('%s added but DP currently down', watcher_msg)
        else:
            new_watchers[watcher_dpid][watcher_type].start(watcher_dpid)
            APP.logger.info('%s started', watcher_msg)

    for watcher_dpid, leftover_watchers in list(APP.watchers.items()):
        for watcher_type, watcher in list(leftover_watchers.items()):
            if watcher.running():
                APP.logger.info(
                    '%s %s deconfigured', dpid_log(watcher_dpid), watcher_type)
                watcher.stop()

    APP.watchers = new_watchers
    APP.logger.info('config complete')


@APP.event('signal', signal='SIGHUP')
def sig_hup(event):
    # Don't exit because of this signal.
    event['exit'] = False
    APP.logger.warning('reload config requested')
    _load_config()


@APP.message('channel_up')
def channel_up(event):
    dp_id = to_dpid(event['datapath_id'])
    if dp_id not in APP.watchers:
        APP.logger.info('%s up, unknown', dpid_log(dp_id))
        return

    APP.logger.info('%s up', dpid_log(dp_id))
    APP.prom_client.dp_status.labels(dp_id=hex(dp_id)).set(1)
    for watcher in list(APP.watchers[dp_id].values()):
        APP.logger.info('%s %s watcher starting', dpid_log(dp_id), watcher.conf.type)
        watcher.start(dp_id)


@APP.message('channel_down')
def channel_down(event):
    dp_id = to_dpid(event['datapath_id'])
    if dp_id not in APP.watchers:
        APP.logger.info('%s down, unknown', dpid_log(dp_id))
        return

    APP.logger.info('%s down', dpid_log(dp_id))
    APP.prom_client.dp_status.labels(dp_id=hex(dp_id)).set(0)
    for watcher in list(APP.watchers[dp_id].values()):
        APP.logger.info('%s %s watcher stopping', dpid_log(dp_id), watcher.conf.type)
        watcher.stop()


def update_watcher(dp_id, name, msg):
    rcv_time = time.time()
    if dp_id in APP.watchers:
        if name in APP.watchers[dp_id]:
            APP.watchers[dp_id][name].update(rcv_time, dp_id, msg)
    else:
        APP.logger.info('%s event, unknown', dpid_log(dp_id))


@APP.message('port_status')
def port_status_handler(event):
    update_watcher(to_dpid(event['datapath_id']), 'port_state', event['msg'])


@APP.message('reply.port_stats')
def port_stats_reply_handler(event):
    update_watcher(to_dpid(event['datapath_id']), 'port_stats', event['msg'])


@APP.message('reply.flow')
def flow_stats_reply_handler(event):
    update_watcher(to_dpid(event['datapath_id']), 'flow_table', event['msg'])


def main():
    args = parse_args()
    args.listen_endpoints = ['%s:%d' % (args.ofp_listen_host, args.ofp_tcp_listen_port)]
    args.pidfile = args.pid_file
    zof.run(args=args)


def parse_args():
    args = argparse.ArgumentParser(parents=[zof.common_args()])
    args.add_argument('--verbose', action='store_true')
    args.add_argument('--use-stderr', action='store_true')
    args.add_argument('--ofp-listen-host', default='')
    args.add_argument('--ofp-tcp-listen-port', type=int, default=6653)
    args.add_argument('--pid-file')
    return args.parse_args()


if __name__ == '__main__':
    main()

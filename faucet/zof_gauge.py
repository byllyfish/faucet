# This file is an adaption of "gauge.py" to the "zof" framework. Much
# of the code is copied/adapted from gauge.py which is under an Apache 2.0
# license. This file retains the same license as "gauge.py".

import time
import argparse
import random
import asyncio

import zof

from faucet import valve_of
from faucet.config_parser import watcher_parser
from faucet.gauge_prom import GaugePrometheusClient
from faucet.valve_util import dpid_log, get_setting, get_logger, stat_config_files
from faucet.watcher import watcher_factory


def to_dpid(dpid):
    """Convert long form dpid to integer.
    """
    return int(dpid.replace(':', ''), 16)


APP = zof.Application('gauge', exception_fatal='gauge.exception')
APP.logname = 'gauge'
APP.watchers = {}
APP.prom_client = GaugePrometheusClient()
APP.config_file = None
APP.stat_reload = False
APP.config_file_stats = None


@APP.event('start')
def start(event):
    APP.config_file = get_setting('GAUGE_CONFIG')
    loglevel = get_setting('GAUGE_LOG_LEVEL')
    logfile = get_setting('GAUGE_LOG')
    exc_logfile = get_setting('GAUGE_EXCEPTION_LOG')
    APP.stat_reload = get_setting('GAUGE_CONFIG_STAT_RELOAD')

    if logfile:
        APP.logger = get_logger(APP.logname, logfile, 'DEBUG', 1)
    if exc_logfile:
        get_logger('%s.exception' % APP.logname, exc_logfile, loglevel, 0)

    zof.ensure_future(_config_file_stat())
    _load_config()


def _load_config():
    """Load Gauge config."""
    new_confs = watcher_parser(APP.config_file, APP.logname, APP.prom_client)
    new_watchers = {}

    for conf in new_confs:
        watcher = watcher_factory(conf)(conf, APP.logname, APP.prom_client)
        watcher_dpid = watcher.dp.dp_id
        ryu_dp = zof.find_datapath(datapath_id=watcher_dpid)
        watcher_type = watcher.conf.type
        watcher_msg = '%s %s watcher' % (dpid_log(watcher_dpid), watcher_type)

        if watcher_dpid not in new_watchers:
            new_watchers[watcher_dpid] = {}

        if watcher_type not in new_watchers[watcher_dpid]:

            # remove old watchers for this stat
            if (watcher_dpid in APP.watchers and
                    watcher_type in APP.watchers[watcher_dpid]):
                old_watchers = APP.watchers[watcher_dpid][watcher_type]
                for old_watcher in old_watchers:
                    if old_watcher.running():
                        APP.logger.info('%s stopped', watcher_msg)
                        old_watcher.stop()
                del APP.watchers[watcher_dpid][watcher_type]

            # start new watcher
            new_watchers[watcher_dpid][watcher_type] = [watcher]
            if ryu_dp is None:
                watcher.report_dp_status(0)
                APP.logger.info('%s added but DP currently down', watcher_msg)
            else:
                watcher.report_dp_status(1)
                watcher.start(ryu_dp, True)
                APP.logger.info('%s started', watcher_msg)
        else:
            new_watchers[watcher_dpid][watcher_type].append(watcher)
            watcher.start(ryu_dp, False)

    for watcher_dpid, leftover_watchers in list(APP.watchers.items()):
        for watcher_type, watcher in list(leftover_watchers.items()):
            watcher.report_dp_status(0)
            if watcher.running():
                APP.logger.info(
                    '%s %s deconfigured', dpid_log(watcher_dpid), watcher_type)
                watcher.stop()

    APP.watchers = new_watchers
    APP.logger.info('config complete')


async def _config_file_stat():
    """Periodically stat config files for any changes."""
    # TODO: Better to use an inotify method that doesn't conflict with eventlets.
    while True:
        # TODO: also stat FAUCET config.
        if APP.config_file:
            config_hashes = {APP.config_file: None}
            new_config_file_stats = stat_config_files(config_hashes)
            if APP.config_file_stats:
                if new_config_file_stats != APP.config_file_stats:
                    if APP.stat_reload:
                        _load_config()
                    APP.logger.info('config file(s) changed on disk')
            APP.config_file_stats = new_config_file_stats
        await asyncio.sleep(3 + random.randint(0, 2))


@APP.event('signal', signal='SIGHUP')
def sig_hup(event):
    # Don't exit because of this signal.
    event['exit'] = False
    APP.logger.warning('reload config requested')
    _load_config()


@APP.message('channel_up')
def channel_up(event):
    dp_id = to_dpid(event['datapath_id'])
    if dp_id in APP.watchers:
        APP.logger.info('%s up', dpid_log(dp_id))
        for watchers in list(APP.watchers[dp_id].values()):
            is_active = True
            for watcher in watchers:
                watcher.report_dp_status(1)
                watcher.start(dp_id, is_active)
                if is_active:
                    APP.logger.info(
                        '%s %s watcher starting',
                        dpid_log(dp_id),
                        watcher.conf.type
                        )
                    is_active = False
        zof.compile(valve_of.faucet_config()).send()
        zof.compile(valve_of.gauge_async()).send()
    else:
        APP.logger.info('%s up, unknown', dpid_log(dp_id))


@APP.message('channel_down')
def channel_down(event):
    dp_id = to_dpid(event['datapath_id'])
    if dp_id in APP.watchers:
        APP.logger.info('%s down', dpid_log(dp_id))
        for watchers in list(APP.watchers[dp_id].values()):
            for watcher in watchers:
                watcher.report_dp_status(0)
                if watcher.is_active():
                    APP.logger.info(
                        '%s %s watcher stopping',
                        dpid_log(dp_id),
                        watcher.conf.type
                        )
                watcher.stop()
    else:
        APP.logger.info('%s down, unknown', dpid_log(dp_id))


def update_watcher(dp_id, name, msg):
    rcv_time = time.time()
    if dp_id in APP.watchers and name in APP.watchers[dp_id]:
        for watcher in APP.watchers[dp_id][name]:
            watcher.update(rcv_time, dp_id, msg)
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
    args.listen_versions = [4]
    args.pidfile = args.pid_file
    zof.run(args=args)


def parse_args():
    args = argparse.ArgumentParser(parents=[zof.common_args()])
    args.add_argument('--verbose', action='store_true')
    args.add_argument('--use-stderr', action='store_true')
    args.add_argument('--ofp-listen-host', default='')
    args.add_argument('--ofp-tcp-listen-port', type=int, default=6653)
    args.add_argument('--pid-file')
    args.add_argument('--config-file')
    return args.parse_args()


if __name__ == '__main__':
    main()

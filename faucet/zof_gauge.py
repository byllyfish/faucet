import zof
from config_parser import watcher_parser
from watcher import watcher_factory
from valve_util import get_sys_prefix, get_logger
import time
import random
import asyncio
import os
import argparse


def to_dpid(dpid):
    """Convert long form dpid to integer.
    """
    return int(dpid.replace(':', ''), 16)


app = zof.Application('gauge', exception_fatal='gauge.exception')
app.logname = 'gauge'
app.watchers = None
app.config_file = None


@app.event('start')
def start(event):
    sysprefix = get_sys_prefix()
    app.config_file = os.getenv('GAUGE_CONFIG', sysprefix + '/etc/ryu/faucet/gauge.yaml')

    exc_logfile = os.getenv('GAUGE_EXCEPTION_LOG', sysprefix + '/var/log/ryu/faucet/gauge_exception.log')
    if exc_logfile:
        get_logger('%s.exception' % app.logname, exc_logfile, 'DEBUG', 0)
    logfile = os.getenv('GAUGE_LOG', sysprefix + '/var/log/ryu/faucet/gauge.log')
    if logfile:
        get_logger(app.logname, logfile, 'DEBUG', 1)

    app.watchers = {}
    confs = watcher_parser(app.config_file, app.logname)
    for conf in confs:
        watcher = watcher_factory(conf)(conf, app.logname)
        app.watchers.setdefault(watcher.dp.dp_id, {})
        app.watchers[watcher.dp.dp_id][watcher.conf.type] = watcher


@app.message('channel_up')
def channel_up(event):
    dp_id = to_dpid(event.datapath_id)
    if dp_id not in app.watchers:
        app.logger.info('no watcher configured for %s', dp_id)
        return

    app.logger.info('%s up', dp_id)
    for watcher in list(app.watchers[dp_id].values()):
        zof.ensure_future(watcher.run(dp_id))


@app.message('channel_down')
def channel_down(event):
    dp_id = to_dpid(event.datapath_id)
    if dp_id not in app.watchers:
        return

    for watcher in list(app.watchers[dp_id].values()):
        watcher.cancel()
        del app.watchers[dp_id]
    app.logger.info('%s down', dp_id)


def update_watcher(dp_id, name, msg):
    rcv_time = time.time()
    if dp_id in app.watchers and name in app.watchers[dp_id]:
        app.watchers[dp_id][name].update(rcv_time, dp_id, msg)


@app.message('port_status')
def port_status_handler(event):
    update_watcher(to_dpid(event.datapath_id), 'port_state', event.msg)


@app.message('reply.port_stats')
def port_stats_reply_handler(event):
    update_watcher(to_dpid(event.datapath_id), 'port_stats', event.msg)


@app.message('reply.flow')
def flow_stats_reply_handler(event):
    update_watcher(to_dpid(event.datapath_id), 'flow_table', event.msg)


def main():
    args = parse_args()
    args.listen_endpoints = ['%s:%d' % (args.ofp_listen_host, args.ofp_tcp_listen_port)]
    zof.run(args=args)


def parse_args():
    args = argparse.ArgumentParser(parents=[zof.common_args()])
    args.add_argument('--verbose', action='store_true')
    args.add_argument('--use-stderr', action='store_true')
    args.add_argument('--ofp-listen-host', default='')
    args.add_argument('--ofp-tcp-listen-port', type=int, default=6653)
    return args.parse_args()


if __name__ == '__main__':
    main()

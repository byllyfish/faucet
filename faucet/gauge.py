"""RyuApp shim between Ryu and Gauge."""

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
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import zof

from faucet import valve_of
from faucet.conf import InvalidConfigError
from faucet.config_parser import watcher_parser
from faucet.gauge_prom import GaugePrometheusClient
from faucet.valves_manager import ConfigWatcher
from faucet.valve_ryuapp import RyuAppBase
from faucet.valve_util import dpid_log, kill_on_exception
from faucet.watcher import watcher_factory

APP = zof.Application('gauge')

@APP.bind()
class Gauge(RyuAppBase):
    """Ryu app for polling Faucet controlled datapaths for stats/state.

    It can poll multiple datapaths. The configuration files for each datapath
    should be listed, one per line, in the file set as the environment variable
    GAUGE_CONFIG. It logs to the file set as the environment variable
    GAUGE_LOG,
    """
    logname = 'gauge'
    exc_logname = logname + '.exception'
    prom_client = None

    def __init__(self, *args, **kwargs):
        super(Gauge, self).__init__(*args, **kwargs)
        self.watchers = {}
        self.config_watcher = ConfigWatcher()
        self.prom_client = GaugePrometheusClient(reg=self._reg)

    def _get_watchers(self, ryu_event):
        """Get Watchers instances to response to an event.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): DP event.
        Returns:
        """
        return self._get_datapath_obj(self.watchers, ryu_event)

    @kill_on_exception(exc_logname)
    def _load_config(self):
        """Load Gauge config."""
        try:
            new_confs = watcher_parser(self.config_file, self.logname, self.prom_client)
        except InvalidConfigError as err:
            self.logger.error('invalid config: %s', err)
            return

        for old_watchers in list(self.watchers.values()):
            self._stop_watchers(old_watchers)

        new_watchers = {}

        for conf in new_confs:
            watcher = watcher_factory(conf)(conf, self.logname, self.prom_client)
            watcher_dpid = watcher.dp.dp_id
            watcher_type = watcher.conf.type
            if watcher_dpid not in new_watchers:
                new_watchers[watcher_dpid] = {}
            if watcher_type not in new_watchers[watcher_dpid]:
                new_watchers[watcher_dpid][watcher_type] = []
            new_watchers[watcher_dpid][watcher_type].append(watcher)

        for watcher_dpid, watchers in list(new_watchers.items()):
            ryu_dp = self.dpset.get(watcher_dpid)
            if ryu_dp:
                self._start_watchers(ryu_dp, watchers)

        self.watchers = new_watchers
        self.config_watcher.update(self.config_file)
        self.logger.info('config complete')

    @kill_on_exception(exc_logname)
    def _update_watcher(self, name, ryu_event):
        """Call watcher with event data."""
        watchers, ryu_dp, msg = self._get_watchers(ryu_event)
        if watchers is None:
            return
        if name in watchers:
            for watcher in watchers[name]:
                watcher.update(float(ryu_event['time']), ryu_dp.id, msg)

    def _config_files_changed(self):
        return self.config_watcher.files_changed()

    @APP.event('RECONFIGURE')
    def reload_config(self, ryu_event):
        """Handle request for Gauge config reload."""
        super(Gauge, self).reload_config(ryu_event)
        self._load_config()

    def _start_watchers(self, ryu_dp, watchers):
        """Start watchers for DP if active."""
        for watchers_by_name in list(watchers.values()):
            for i, watcher in enumerate(watchers_by_name):
                is_active = i == 0
                watcher.report_dp_status(1)
                watcher.start(ryu_dp, is_active)

    @kill_on_exception(exc_logname)
    def _datapath_connect(self, ryu_event):
        """Handle DP up.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): DP event.
        """
        watchers, ryu_dp, _ = self._get_watchers(ryu_event)
        if watchers is None:
            return
        self.logger.info('%s up', dpid_log(ryu_dp.id))
        ryu_dp.send_msg(valve_of.faucet_config(datapath=ryu_dp))
        ryu_dp.send_msg(valve_of.faucet_async(datapath=ryu_dp, packet_in=False))
        self._start_watchers(ryu_dp, watchers)

    def _stop_watchers(self, watchers):
        """Stop watchers for DP."""
        for watchers_by_name in list(watchers.values()):
            for watcher in watchers_by_name:
                watcher.report_dp_status(0)
                if watcher.is_active():
                    watcher.stop()

    @kill_on_exception(exc_logname)
    def _datapath_disconnect(self, ryu_event):
        """Handle DP down.

        Args:
           ryu_event (ryu.controller.event.EventReplyBase): DP event.
        """
        watchers, ryu_dp, _ = self._get_watchers(ryu_event)
        if watchers is None:
            return
        self.logger.info('%s down', dpid_log(ryu_dp.id))
        self._stop_watchers(watchers)

    _WATCHER_HANDLERS = {
        'PORT_STATUS': 'port_state',
        'REPLY.PORT_STATS': 'port_stats',
        'REPLY.FLOW': 'flow_table',
    }

    @APP.message('PORT_STATUS')
    @APP.message('REPLY.PORT_STATS')
    @APP.message('REPLY.FLOW')
    @kill_on_exception(exc_logname)
    def update_watcher_handler(self, ryu_event):
        """Handle port status change event.

        Args:
           ryu_event (ryu.controller.event.EventReplyBase): port status change event.
        """
        self._update_watcher(self._WATCHER_HANDLERS[ryu_event['type']], ryu_event)

    # Add zof handlers for base class.
    APP.event('START')(RyuAppBase.start)
    APP.message('CHANNEL_UP')(RyuAppBase.connect_or_disconnect_handler)
    APP.message('CHANNEL_DOWN')(RyuAppBase.connect_or_disconnect_handler)
    APP.event('SIGNAL')(RyuAppBase.signal_handler)

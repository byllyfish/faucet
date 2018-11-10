"""RyuApp base class for FAUCET/Gauge."""

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
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import logging
import random
import signal

import zof

from faucet import valve_of
from faucet.valve_util import dpid_log, get_logger, get_setting


class RyuAppBase:
    """RyuApp base class for FAUCET/Gauge."""

    logname = ''
    exc_logname = ''

    def __init__(self):
        self._reg = None
        self.config_file = self.get_setting('CONFIG', True)
        self.stat_reload = self.get_setting('CONFIG_STAT_RELOAD')
        loglevel = self.get_setting('LOG_LEVEL')
        logfile = self.get_setting('LOG')
        exc_logfile = self.get_setting('EXCEPTION_LOG')
        self.logger = get_logger(
            self.logname, logfile, loglevel, 0)
        self.exc_logger = get_logger(
            self.exc_logname, exc_logfile, logging.DEBUG, 1)

    @staticmethod
    async def _thread_jitter(period, jitter=2):
        """Reschedule another thread with a random jitter."""
        await asyncio.sleep(period + random.randint(0, jitter))

    async def _thread_reschedule(self, ryu_event, period, jitter=2):
        """Trigger Ryu events periodically with a jitter.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): event to trigger.
            period (int): how often to trigger.
        """
        while True:
            ryu_event()
            await self._thread_jitter(period, jitter)

    def get_setting(self, setting, path_eval=False):
        """Return config setting prefaced with logname."""
        return get_setting('_'.join((self.logname.upper(), setting)), path_eval)

    def handle_sighup(self):
        """Handle signals.

        Args:
            sigid (int): signal received.
        """
        zof.post_event({'type': 'RELOAD_CONFIG'})

    @staticmethod
    def _config_files_changed():
        """Return True if config files changed."""
        raise NotImplementedError # pragma: no cover

    async def _config_file_stat(self):
        """Periodically stat config files for any changes."""
        while True:
            if self._config_files_changed():
                if self.stat_reload:
                    self.handle_sighup()
            await self._thread_jitter(3)

    async def on_start(self):
        """Start controller."""

        if self.stat_reload:
            self.logger.info('will automatically reload new config on changes')
        self.on_reload_config(None, None)
        zof.create_task(self._config_file_stat())
        asyncio.get_event_loop().add_signal_handler(signal.SIGHUP, self.handle_sighup)

    def on_stop(self):
        asyncio.get_event_loop().remove_signal_handler(signal.SIGHUP)

    def on_reload_config(self, _dp, _event):
        """Handle reloading configuration."""
        self.logger.info('Reloading configuration')

    def _get_datapath_obj(self, datapath_objs, ryu_dp, ryu_event):
        """Get datapath object to response to an event.

        Args:
            datapath_objs (dict): datapath objects indexed by DP ID.
            ryu_event (ryu.controller.event.Event): event.
        Returns:
            valve, ryu_dp, msg: Nones, or datapath object, Ryu datapath, and Ryu msg (if any).
        """
        datapath_obj = None
        msg = ryu_event.get('msg', ryu_event)
        dp_id = ryu_dp.id
        if dp_id in datapath_objs:
            datapath_obj = datapath_objs[dp_id]
        else:
            ryu_dp.close(force=True)
            self.logger.error('%s: unknown datapath %s', str(ryu_event), dpid_log(dp_id))
        return (datapath_obj, ryu_dp, msg)

    def on_channel_up(self, dp, event):
        raise NotImplementedError # pragma: no cover

    def on_channel_down(self, dp, event):
        raise NotImplementedError # pragma: no cover

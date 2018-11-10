"""RyuApp shim between Ryu and Valve."""

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

import time

from functools import partial

import zof

from faucet.config_parser import get_config_for_api
from faucet.valve_ryuapp import RyuAppBase
from faucet.valve_util import dpid_log, kill_on_exception
from faucet import faucet_experimental_api
from faucet import faucet_experimental_event
from faucet import faucet_bgp
from faucet import faucet_dot1x
from faucet import valves_manager
from faucet import faucet_metrics
from faucet import valve_of


class Faucet(RyuAppBase):
    """A RyuApp that implements an L2/L3 learning VLAN switch.

    Valve provides the switch implementation; this is a shim for the Ryu
    event handling framework to interface with Valve.
    """
    logname = 'faucet'
    exc_logname = logname + '.exception'
    bgp = None
    metrics = None
    notifier = None
    valves_manager = None

    def __init__(self):
        super().__init__()
        self.api = faucet_experimental_api.FaucetExperimentalAPI()
        self.metrics = faucet_metrics.FaucetMetrics(reg=self._reg)
        self.bgp = faucet_bgp.FaucetBgp(
            self.logger, self.exc_logname, self.metrics, self._send_flow_msgs)
        self.dot1x = faucet_dot1x.FaucetDot1x(
            self.logger, self.metrics, self._send_flow_msgs)
        self.notifier = faucet_experimental_event.FaucetExperimentalEventNotifier(
            self.get_setting('EVENT_SOCK'), self.metrics, self.logger)
        self.valves_manager = valves_manager.ValvesManager(
            self.logname, self.logger, self.metrics, self.notifier, self.bgp,
            self.dot1x, self._send_flow_msgs)

    @kill_on_exception(exc_logname)
    async def on_start(self):
        await super().on_start()

        # Start Prometheus
        prom_port = int(self.get_setting('PROMETHEUS_PORT'))
        prom_addr = self.get_setting('PROMETHEUS_ADDR')
        self.metrics.start(prom_port, prom_addr)

        # Start event notifier
        await self.notifier.start()

        # Start all threads
        for service, period in (
                (self.metric_update, 5),
                ('resolve_gateways', 2),
                ('state_expire', 5),
                ('fast_state_expire', 2),
                ('advertise', 15),
                ('fast_advertise', 5)):
            if isinstance(service, str):
                func = partial(self._valve_flow_services, service)
            else:
                func = partial(service, None)
            zof.create_task(self._thread_reschedule(func, period))

        # Register to API
        self.api._register(self)
        zof.post_event({'type': 'FAUCET_API_READY', 'faucet_api': self.api})

    @kill_on_exception(exc_logname)
    def on_stop(self):
        """Called when app stops."""
        super().on_stop()
        self.notifier.stop()

    def _delete_deconfigured_dp(self, deleted_dpid):
        self.logger.info(
            'Deleting de-configured %s', dpid_log(deleted_dpid))
        ryu_dp = zof.find_datapath(deleted_dpid)
        if ryu_dp is not None:
            ryu_dp.close()

    @kill_on_exception(exc_logname)
    def on_reload_config(self, dp, event):
        """Handle a request to reload configuration."""
        super().on_reload_config(dp, event)
        self.valves_manager.request_reload_configs(
            time.time(), self.config_file, delete_dp=self._delete_deconfigured_dp)

    @kill_on_exception(exc_logname)
    def _send_flow_msgs(self, valve, flow_msgs, ryu_dp=None):
        """Send OpenFlow messages to a connected datapath.

        Args:
            Valve instance or None.
            flow_msgs (list): OpenFlow messages to send.
            ryu_dp: Override datapath from DPSet.
        """
        if ryu_dp is None:
            ryu_dp = zof.find_datapath(valve.dp.dp_id)
        if not ryu_dp:
            valve.logger.error('send_flow_msgs: DP not up')
            return
        valve.send_flows(ryu_dp, flow_msgs)

    def _get_valve(self, ryu_dp, ryu_event, require_running=False):
        """Get Valve instance to response to an event.

        Args:
            ryu_event (ryu.controller.event.Event): event
            require_running (bool): require DP to be running.
        Returns:
            valve, ryu_dp, msg: tuple of Nones, or datapath object, Ryu datapath, and msg (if any)
        """
        valve, ryu_dp, msg = self._get_datapath_obj(
            self.valves_manager.valves, ryu_dp, ryu_event)
        if valve:
            if msg:
                valve.ofchannel_log([msg])
            if require_running and not valve.dp.dyn_running:
                valve = None
        return (valve, ryu_dp, msg)

    def _config_files_changed(self):
        return self.valves_manager.config_watcher.files_changed()

    @kill_on_exception(exc_logname)
    def metric_update(self, _event):
        """Handle a request to update metrics in the controller."""
        self.valves_manager.update_metrics(time.time())

    @kill_on_exception(exc_logname)
    def _valve_flow_services(self, service):
        """Call a method on all Valves and send any resulting flows."""
        self.valves_manager.valve_flow_services(time.time(), service)

    def get_config(self):
        """FAUCET experimental API: return config for all Valves."""
        return get_config_for_api(self.valves_manager.valves)

    def get_tables(self, dp_id):
        """FAUCET experimental API: return config tables for one Valve."""
        if dp_id in self.valves_manager.valves:
            return self.valves_manager.valves[dp_id].dp.get_tables()
        return {}

    @kill_on_exception(exc_logname)
    def on_packet_in(self, dp, ryu_event):
        """Handle a packet in event from the dataplane.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): packet in message.
        """
        valve, _, msg = self._get_valve(dp, ryu_event, require_running=True)
        if valve is None:
            return
        timestamp = float(ryu_event['time'])
        self.valves_manager.valve_packet_in(timestamp, valve, msg)

    @kill_on_exception(exc_logname)
    def on_error(self, dp, ryu_event):
        """Handle an OFPError from a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPErrorMsg): trigger
        """
        valve, _, msg = self._get_valve(dp, ryu_event)
        if valve is None:
            return
        valve.oferror(ryu_event)

    @kill_on_exception(exc_logname)
    def on_channel_up(self, dp, ryu_event):
        """Handle any/all re/connection of a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.Event)
        """
        now = time.time()
        valve, ryu_dp, msg = self._get_valve(dp, ryu_event)
        if valve is None:
            return
        flowmods = valve.switch_features(msg['features'])
        self._send_flow_msgs(valve, flowmods)
        # Handle remaining "connect" messages.
        discovered_up_ports = [
            port['port_no'] for port in msg['features']['ports']
            if (valve_of.port_status_from_state(port['state']) and
                not valve_of.ignore_port(port['port_no']))]
        self._send_flow_msgs(valve, valve.datapath_connect(now, discovered_up_ports))

    @kill_on_exception(exc_logname)
    def on_channel_down(self, dp, ryu_event):
        """Handle any/all disconnection of a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.Event)
        """
        valve, _, _ = self._get_valve(dp, ryu_event)
        if valve is None:
            return
        valve.datapath_disconnect()

    @kill_on_exception(exc_logname)
    def on_desc_reply(self, dp, ryu_event):
        """Handle OFPDescStatsReply from datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPDescStatsReply): trigger.
        """
        valve, _, msg = self._get_valve(dp, ryu_event)
        if valve is None:
            return
        valve.ofdescstats_handler(msg)

    @kill_on_exception(exc_logname)
    def on_port_status(self, dp, ryu_event):
        """Handle a port status change event.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPPortStatus): trigger.
        """
        valve, _, msg = self._get_valve(dp, ryu_event, require_running=True)
        if valve is None:
            return
        self._send_flow_msgs(valve, valve.port_status_handler(
            msg['port_no'], msg['reason'], msg['state']))

    @kill_on_exception(exc_logname)
    def on_flow_removed(self, dp, ryu_event):
        """Handle a flow removed event.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPFlowRemoved): trigger.
        """
        valve, ryu_dp, msg = self._get_valve(dp, ryu_event, require_running=True)
        if valve is None:
            return
        if msg['reason'] == valve_of.ofp.OFPRR_IDLE_TIMEOUT:
            self._send_flow_msgs(valve, valve.flow_timeout(time.time(), msg['table_id'], msg['match']))

    #@kill_on_exception(exc_logname)
    #def on_channel_alert(self, _dp, event):
    #    """Handle a channel alert event."""
    #    message = event['msg']['message']
    #    if message.startswith('YAML:'):
    #        # There was a problem with something we sent.
    #        raise RuntimeError('CHANNEL_ALERT: %s' % message)

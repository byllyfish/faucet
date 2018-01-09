"""RyuApp shim between Ryu and Valve."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
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

from functools import partial

import zof

from faucet.config_parser import get_config_for_api
from faucet.valve_ryuapp import RyuAppBase
from faucet.valve_util import dpid_log, kill_on_exception
from faucet import faucet_experimental_api
from faucet import faucet_experimental_event
#from faucet import faucet_bgp
from faucet import valves_manager
from faucet import faucet_metrics
from faucet import valve_of


APP = zof.Application('faucet')

@APP.bind()
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

    def __init__(self, *args, **kwargs):
        super(Faucet, self).__init__(*args, **kwargs)
        self.api = faucet_experimental_api.FaucetExperimentalAPI()
        self.metrics = faucet_metrics.FaucetMetrics(reg=self._reg)
        self.bgp = None   #faucet_bgp.FaucetBgp(self.logger, self.metrics, self._send_flow_msgs)
        self.notifier = faucet_experimental_event.FaucetExperimentalEventNotifier(
            self.get_setting('EVENT_SOCK'), self.metrics, self.logger)
        self.valves_manager = valves_manager.ValvesManager(
            self.logname, self.logger, self.metrics, self.notifier, self.bgp, self._send_flow_msgs)

    @APP.event('START')
    @kill_on_exception(exc_logname)
    async def start(self, _event):
        await super().start(_event)

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
                ('advertise', 5),
                ('send_lldp_beacons', 5)):
            if isinstance(service, str):
                func = partial(self._valve_flow_services, service)
            else:
                func = service
            zof.ensure_future(self._thread_reschedule(func, period))

        # Register to API
        self.api._register(self)
        zof.post_event({'event': 'FAUCET_API_READY', 'faucet_api': self.api})

    @APP.event('STOP')
    @kill_on_exception(exc_logname)
    def stop(self, _):
        self.notifier.stop()

    def _delete_deconfigured_dp(self, deleted_dpid):
        self.logger.info(
            'Deleting de-configured %s', dpid_log(deleted_dpid))
        ryu_dp = self.dpset.get(deleted_dpid)
        if ryu_dp is not None:
            ryu_dp.close()

    @APP.event('RECONFIGURE')
    @kill_on_exception(exc_logname)
    def reload_config(self, ryu_event):
        """Handle a request to reload configuration."""
        super(Faucet, self).reload_config(ryu_event)
        self.valves_manager.request_reload_configs(
            self.config_file, delete_dp=self._delete_deconfigured_dp)

    @kill_on_exception(exc_logname)
    def _send_flow_msgs(self, valve, flow_msgs, ryu_dp=None):
        """Send OpenFlow messages to a connected datapath.

        Args:
            Valve instance or None.
            flow_msgs (list): OpenFlow messages to send.
            ryu_dp: Override datapath from DPSet.
        """
        if ryu_dp is None:
            ryu_dp = self.dpset.get(valve.dp.dp_id)
        if not ryu_dp:
            valve.logger.error('send_flow_msgs: DP not up')
            return
        valve.send_flows(ryu_dp, flow_msgs)

    def _get_valve(self, ryu_event, require_running=False):
        """Get Valve instance to response to an event.

        Args:
            ryu_event (ryu.controller.event.Event): event
            require_running (bool): require DP to be running.
        Returns:
            valve, ryu_dp, msg: tuple of Nones, or datapath object, Ryu datapath, and Ryu msg (if any)
        """
        valve, ryu_dp, msg = self._get_datapath_obj(
            self.valves_manager.valves, ryu_event)
        if valve:
            if msg:
                valve.ofchannel_log([msg])
            if require_running and not valve.dp.running:
                valve = None
        return (valve, ryu_dp, msg)

    def _config_files_changed(self):
        return self.valves_manager.config_watcher.files_changed()

    @kill_on_exception(exc_logname)    
    def metric_update(self):    
        """Handle a request to update metrics in the controller."""    
        self.valves_manager.update_metrics()   

    @kill_on_exception(exc_logname)
    def _valve_flow_services(self, service):
        """Call a method on all Valves and send any resulting flows."""
        self.valves_manager.valve_flow_services(service)

    def get_config(self):
        """FAUCET experimental API: return config for all Valves."""
        return get_config_for_api(self.valves_manager.valves)

    def get_tables(self, dp_id):
        """FAUCET experimental API: return config tables for one Valve."""
        if dp_id in self.valves_manager.valves:
            return self.valves_manager.valves[dp_id].dp.get_tables()
        return {}

    @APP.message('PACKET_IN')
    @kill_on_exception(exc_logname)
    def packet_in_handler(self, ryu_event):
        """Handle a packet in event from the dataplane.

        Args:
            ryu_event (ryu.controller.event.EventReplyBase): packet in message.
        """
        valve, _, msg = self._get_valve(ryu_event, require_running=True)
        if valve is None:
            return
        if valve.rate_limit_packet_ins():
            return
        pkt_meta = valve.parse_pkt_meta(msg)
        if pkt_meta is None:
            return
        self.valves_manager.valve_packet_in(valve, pkt_meta)

    @APP.message('ERROR')
    @kill_on_exception(exc_logname)
    def error_handler(self, ryu_event):
        """Handle an OFPError from a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPErrorMsg): trigger
        """
        valve, _, msg = self._get_valve(ryu_event)
        if valve is None:
            return
        valve.oferror(ryu_event)

    # UNUSED IN ZOF
    @kill_on_exception(exc_logname)
    def features_handler(self, ryu_event):
        """Handle receiving a switch features message from a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPStateChange): trigger.
        """
        valve, ryu_dp, msg = self._get_valve(ryu_event)
        if valve is None:
            return
        self._send_flow_msgs(valve, valve.switch_features(msg), ryu_dp=ryu_dp)

    @kill_on_exception(exc_logname)
    def _datapath_connect(self, ryu_event):
        """Handle any/all re/connection of a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.Event)
        """
        valve, ryu_dp, _ = self._get_valve(ryu_event)
        if valve is None:
            return
        # Obtain FEATURES_REPLY from zof.Datapath object.
        flowmods = valve.switch_features(ryu_dp.features)
        self._send_flow_msgs(valve, flowmods)
        # Handle remaining "connect" messages.
        discovered_ports = [
            port for port in list(ryu_dp.ports.values()) if not valve_of.ignore_port(port.port_no)]
        self._send_flow_msgs(valve, valve.datapath_connect(discovered_ports))

    @kill_on_exception(exc_logname)
    def _datapath_disconnect(self, ryu_event):
        """Handle any/all disconnection of a datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.Event)
        """
        valve, _, _ = self._get_valve( ryu_event)
        if valve is None:
            return
        valve.datapath_disconnect()

    @APP.message('REPLY.DESC')
    @kill_on_exception(exc_logname)
    def desc_stats_reply_handler(self, ryu_event):
        """Handle OFPDescStatsReply from datapath.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPDescStatsReply): trigger.
        """
        valve, _, msg = self._get_valve(ryu_event)
        if valve is None:
            return
        valve.ofdescstats_handler(msg)

    @APP.message('PORT_STATUS')
    @kill_on_exception(exc_logname)
    def port_status_handler(self, ryu_event):
        """Handle a port status change event.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPPortStatus): trigger.
        """
        valve, _, msg = self._get_valve(ryu_event, require_running=True)
        if valve is None:
            return
        self._send_flow_msgs(valve, valve.port_status_handler(
            msg['port_no'], msg['reason'], msg['state']))

    @APP.message('FLOW_REMOVED')
    @kill_on_exception(exc_logname)
    def flowremoved_handler(self, ryu_event):
        """Handle a flow removed event.

        Args:
            ryu_event (ryu.controller.ofp_event.EventOFPFlowRemoved): trigger.
        """
        valve, ryu_dp, msg = self._get_valve(ryu_event, require_running=True)
        if valve is None:
            return
        if msg['reason'] == valve_of.ofp.OFPRR_IDLE_TIMEOUT:
            self._send_flow_msgs(valve, valve.flow_timeout(msg['table_id'], msg['match']))

    # Attach zof handlers to base class methods.
    APP.message('CHANNEL_UP')(RyuAppBase.connect_or_disconnect_handler)
    APP.message('CHANNEL_DOWN')(RyuAppBase.connect_or_disconnect_handler)
    APP.event('SIGNAL')(RyuAppBase.signal_handler)

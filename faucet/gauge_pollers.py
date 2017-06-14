"""Library for polling dataplanes for statistics."""

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

import logging
import random

#from ryu.lib import hub

from faucet.valve_util import dpid_log

import asyncio
import zof
import zof.exception as _exc


class GaugePoller(object):
    """Abstraction for a poller for statistics."""

    def __init__(self, conf, logname, prom_client):
        self.dp = conf.dp # pylint: disable=invalid-name
        self.conf = conf
        self.prom_client = prom_client
        self.reply_pending = False
        self.logger = logging.getLogger(
            logname + '.{0}'.format(self.conf.type)
            )

    @staticmethod
    def start(_ryudp):
        """Start the poller."""
        return

    @staticmethod
    def stop():
        """Stop the poller."""
        return

    @staticmethod
    def running():
        """Return True if the poller is running."""
        return True

    @staticmethod
    def send_req():
        """Send a stats request to a datapath."""
        raise NotImplementedError

    @staticmethod
    def no_response():
        """Called when a polling cycle passes without receiving a response."""
        raise NotImplementedError

    def update(self, rcv_time, dp_id, msg):
        """Handle the responses to requests.

        Called when a reply to a stats request sent by this object is received
        by the controller.

        It should acknowledge the receipt by setting self.reply_pending to
        false.

        Arguments:
        rcv_time -- the time the response was received
        dp_id -- DP ID
        msg -- the stats reply message
        """
        # TODO: it may be worth while verifying this is the correct stats
        # response before doing this
        self.reply_pending = False

    def _stat_port_name(self, msg, stat, dp_id):
        """Return port name as string based on port number."""
        port_no = stat['port_no']
        if port_no == 'CONTROLLER':
            return 'CONTROLLER'
        elif port_no == 'LOCAL':
            return 'LOCAL'
        elif port_no in self.dp.ports:
            return self.dp.ports[port_no].name
        self.logger.info('%s stats for unknown port %u',
                         dpid_log(dp_id), port_no)
        return None

    @staticmethod
    def _format_port_stats(delim, stat):
        formatted_port_stats = []
        for stat_name_list, stat_val in (
                (('packets', 'out'), stat['tx_packets']),
                (('packets', 'in'), stat['rx_packets']),
                (('bytes', 'out'), stat['tx_bytes']),
                (('bytes', 'in'), stat['rx_bytes']),
                (('dropped', 'out'), stat['tx_dropped']),
                (('dropped', 'in'), stat['rx_dropped']),
                (('errors', 'in'), stat['rx_errors'])):
            # For openvswitch, unsupported statistics are set to
            # all-1-bits (UINT64_MAX), skip reporting them
            if stat_val != 2**64-1:
                stat_name = delim.join(stat_name_list)
                formatted_port_stats.append((stat_name, stat_val))
        return formatted_port_stats


class GaugeThreadPoller(GaugePoller):
    """A ryu thread object for sending and receiving OpenFlow stats requests.

    The thread runs in a loop sending a request, sleeping then checking a
    response was received before sending another request.

    The methods send_req, update and no_response should be implemented by
    subclasses.
    """

    def __init__(self, conf, logname, prom_client):
        super(GaugeThreadPoller, self).__init__(conf, logname, prom_client)
        self.thread = None
        self.interval = self.conf.interval
        self.ryudp = None

    def start(self, dp_id):
        self.stop()
        self.thread = zof.ensure_future(self.run(dp_id))

    def stop(self):
        if self.running():
            self.thread.cancel()
            self.thread = None

    async def run(self, dp_id):
        await asyncio.sleep(random.randint(1, self.conf.interval))
        while True:
            ofmsg = zof.compile(self.send_req())
            try:
                response = await ofmsg.request(datapath_id=hex(dp_id))
                self.update(float(response['time']), dp_id, response['msg'])
            except _exc.ControllerException as ex:
                self.logger.warning('poll failed: %s', ex)
            await asyncio.sleep(self.conf.interval)

    def running(self):
        return self.thread is not None

    def __call__(self):
        """Send request loop.

        Delays the initial request for a random interval to reduce load.
        Then sends a request to the datapath, waits the specified interval and
        checks that a response has been received in a loop."""
        # TODO: this should use a deterministic method instead of random
        hub.sleep(random.randint(1, self.conf.interval))
        while True:
            self.send_req()
            self.reply_pending = True
            hub.sleep(self.conf.interval)
            if self.reply_pending:
                self.no_response()

    @staticmethod
    def send_req():
        """Send a stats request to a datapath."""
        raise NotImplementedError

    @staticmethod
    def no_response():
        """Called when a polling cycle passes without receiving a response."""
        raise NotImplementedError


class GaugePortStatsPoller(GaugeThreadPoller):
    """Periodically sends a port stats request to the datapath and parses
       and outputs the response.
    """

    def send_req(self):
        return {'type': 'REQUEST.PORT_STATS', 'msg':{'port_no': 'ANY'}}

    def no_response(self):
        self.logger.info(
            'port stats request timed out for %s', self.dp.name)


class GaugeFlowTablePoller(GaugeThreadPoller):
    """Periodically dumps the current datapath flow table as a yaml object.

    Includes a timestamp and a reference ($DATAPATHNAME-flowtables). The
    flow table is dumped as an OFFlowStatsReply message (in yaml format) that
    matches all flows.
    """

    def send_req(self):
        return {'type': 'REQUEST.FLOW', 'msg':{
            'table_id': 'ALL',
            'out_port': 'ANY',
            'out_group': 'ANY',
            'cookie': 0,
            'cookie_mask': 0,
            'match': []}}

    def no_response(self):
        self.logger.info(
            'flow dump request timed out for %s', self.dp.name)


class GaugePortStateBaseLogger(GaugePoller):
    """Abstraction for port state poller."""

    @staticmethod
    def send_req():
        """Send a stats request to a datapath."""
        raise NotImplementedError

    @staticmethod
    def no_response():
        """Called when a polling cycle passes without receiving a response."""
        raise NotImplementedError

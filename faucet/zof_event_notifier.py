"""Experimental FAUCET event notification."""

#### THIS API IS EXPERIMENTAL.
#### Discuss with faucet-dev list before relying on this API,
#### review http://www.hyrumslaw.com/.
#### It is subject to change without notice.

# TODO: events are currently schema-less. This is to facilitate rapid prototyping, and will change.
# TODO: not all cases where a notified client fails or could block, have been tested.

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
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import json
import asyncio
import os


class _NotifierProtocol(asyncio.Protocol):

    def __init__(self, notifier):
        self.notifier = notifier
        self.transport = None
        self.can_write = True

    def connection_made(self, transport):
        transport.set_write_buffer_limits(4096)
        self.transport = transport
        self.notifier.writers.append(self)

    def connection_lost(self, exc):
        try:
            self.notifier.writers.remove(self)
        except ValueError:
            pass
    
    def eof_received(self):
        """Override eof_received to support half-open (write-only) connection.

        By returning True, we are telling asyncio NOT to close the connection
        when the read side is closed.
        """
        return True

    def pause_writing(self):
        self.can_write = False

    def resume_writing(self):
        self.can_write = True

    def write(self, data):
        if self.can_write:
            self.transport.write(data)

    def close(self):
        self.transport.close()


class FaucetExperimentalEventNotifier(object):
    """Event notification, via Unix domain socket."""

    def __init__(self, socket_path, metrics, logger):
        self.metrics = metrics
        self.logger = logger
        self.event_id = 0
        self.server = None
        self.writers = []
        self.socket_path = self._check_socket_path(socket_path)

    async def start(self):
        """Start socket server."""
        if not self.socket_path:
            return
        loop = asyncio.get_event_loop()
        self.server = await loop.create_unix_server(lambda: _NotifierProtocol(self), self.socket_path)

    def stop(self):
        """Stop socket server."""
        if not self.socket_path:
            return
        self.server.close()
        for writer in self.writers:
            writer.close()
        self.writers = []

    def publish(self, data):
        for writer in self.writers:
            writer.write(data)

    def notify(self, dp_id, dp_name, event_dict):
        """Notify of an event."""
        assert isinstance(event_dict, dict)
        self.event_id += 1
        event = {
            'version': 1,
            'time': time.time(),
            'dp_id': dp_id,
            'dp_name': dp_name,
            'event_id': self.event_id,
        }
        assert not any(key in event_dict for key in event)
        event.update(event_dict)
        if self.socket_path:
            self.metrics.faucet_event_id.set(self.event_id)
            self.publish((json.dumps(event) + '\n').encode('UTF-8'))

    def _check_socket_path(self, socket_path):
        """Check that socket_path exists and has correct permissions.

        Asyncio will remove any existing, stale socket file.
        """
        if not socket_path:
            return None
        socket_dir = os.path.dirname(socket_path)
        if socket_dir:
            if not os.path.exists(socket_dir):
                try:
                    os.makedirs(socket_dir)
                except (PermissionError) as err: # pytype: disable=name-error
                    self.logger.error('Unable to create event socket directory: %s', err)
                    return None
            if not os.access(socket_dir, os.R_OK | os.W_OK | os.X_OK):
                self.logger.error('Incorrect permissions set on socket directory %s', socket_dir)
                return None
        return socket_path

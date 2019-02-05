#!/usr/bin/env python3.7

"""Launch forwarder script for Faucet/Gauge"""

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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import asyncio
import os
import sys
import logging
import contextlib

import zof

# Running the __main__.py python script *directly* inserts an entry in sys.path. 
# We need to delete this entry because it interferes with module importing
# when a package and module share the same name (e.g. "faucet").
if os.path.abspath(os.path.dirname(__file__)) == sys.path[0]:
    del sys.path[0]

from faucet.faucet import Faucet
from faucet.gauge import Gauge

RYU_OPTIONAL_ARGS = [
    ('ca-certs', 'CA certificates'),
    ('config-dir', """Path to a config directory to pull `*.conf` files
                      from. This file set is sorted, so as to provide a
                      predictable parse order if individual options are
                      over-ridden. The set is parsed after the file(s)
                      specified via previous --config-file, arguments hence
                      over-ridden options in the directory take precedence."""),
    ('config-file', """Path to a config file to use. Multiple config files
                       can be specified, with values in later files taking
                       precedence. Defaults to None.""", "/etc/faucet/ryu.conf"),
    ('ctl-cert', 'controller certificate'),
    ('ctl-privkey', 'controller private key'),
    ('default-log-level', 'default log level'),
    ('log-config-file', 'Path to a logging config file to use'),
    ('log-dir', 'log file directory'),
    ('log-file', 'log file name'),
    ('log-file-mode', 'default log file permission'),
    ('observe-links', 'observe link discovery events'),
    ('ofp-listen-host', 'openflow listen host (default 0.0.0.0)'),
    ('ofp-ssl-listen-port', 'openflow ssl listen port (default: 6653)'),
    ('ofp-switch-address-list', """list of IP address and port pairs (default empty).
                                   e.g., "127.0.0.1:6653,[::1]:6653"""),
    ('ofp-switch-connect-interval', 'interval in seconds to connect to switches (default 1)'),
    ('ofp-tcp-listen-port', 'openflow tcp listen port (default: 6653)'),
    ('pid-file', 'pid file name'),
    ('user-flags', 'Additional flags file for user applications'),
    ('wsapi-host', 'webapp listen host (default 0.0.0.0)'),
    ('wsapi-port', 'webapp listen port (default 8080)')
]


def parse_args(sys_args):
    """Parse Faucet/Gauge arguments.

    Returns:
        argparse.Namespace: command line arguments
    """

    args = argparse.ArgumentParser(
        prog='faucet', description='Faucet SDN Controller')
    args.add_argument('--gauge', action='store_true', help='run Gauge instead')
    args.add_argument(
        '-v', '--verbose', action='store_true', help='produce verbose output')
    args.add_argument(
        '-V', '--version', action='store_true', help='print version and exit')
    args.add_argument(
        '--use-stderr', action='store_true', help='log to standard error')
    args.add_argument(
        '--use-syslog', action='store_true', help='output to syslog')
    args.add_argument(
        '--ryu-app',
        action='append',
        help='add Ryu app (can be specified multiple times)',
        metavar='APP')

    for ryu_arg in RYU_OPTIONAL_ARGS:
        if len(ryu_arg) >= 3:
            args.add_argument(
                '--ryu-%s' % ryu_arg[0],
                help=ryu_arg[1],
                default=ryu_arg[2])
        else:
            args.add_argument(
                '--ryu-%s' % ryu_arg[0],
                help=ryu_arg[1])

    return args.parse_args(sys_args)


def print_version():
    """Print version number and exit."""
    from pbr.version import VersionInfo
    version = VersionInfo('faucet').semantic_version().release_string()
    message = 'Faucet %s' % version
    print(message)


def main():
    """Main program."""
    args = parse_args(sys.argv[1:])
    prog = os.path.basename(sys.argv[0])

    if args.version:
        print_version()
        return

    config = zof.Configuration()
    if args.ryu_ofp_tcp_listen_port:
        config.listen_endpoints = [(args.ryu_ofp_listen_host, args.ryu_ofp_tcp_listen_port)]

    apps = []
    if args.gauge or prog == 'gauge':
        apps.append(Gauge())
    else:
        apps.append(Faucet())

    if args.ryu_wsapi_port:
        from zof.extra.rest_api import RestApi
        rest_endpoint = (args.ryu_wsapi_host, args.ryu_wsapi_port)
        apps.append(RestApi(rest_endpoint))

    if args.ryu_app and 'experimental_api_test_app.py' in args.ryu_app:
        from tests.integration.experimental_api_test_app import TestFaucetExperimentalAPIViaRyu
        apps.append(TestFaucetExperimentalAPIViaRyu())

    with pid_file(args.ryu_pid_file):
        asyncio.run(zof.run_controller(apps, config=config))


@contextlib.contextmanager
def pid_file(pid_path):
    """Context manager for PID file."""
    if pid_path:
        with open(pid_path, 'w') as afile:
            afile.write(str(os.getpid()))
        yield
        os.unlink(pid_path)
    else:
        # Noop when pidfile is None/empty.
        yield


if __name__ == '__main__':
    main()

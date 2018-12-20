#!/usr/bin/env python3

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
import os
import sys

import zof
from zof.api_args import file_contents_type, _import_modules

# Running the __main__.py python script *directly* inserts an entry in sys.path. 
# We need to delete this entry because it interferes with module importing
# when a package and module share the same name (e.g. "faucet").
if os.path.abspath(os.path.dirname(__file__)) == sys.path[0]:
    del sys.path[0]

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


def build_ryu_args(argv):
    args = parse_args(argv[1:])

    # Checking version number?
    if args.version:
        print_version()
        return []

    prog = os.path.basename(argv[0])
    ryu_args = []

    # Handle log location
    if args.use_stderr:
        ryu_args.append('--use-stderr')
    if args.use_syslog:
        ryu_args.append('--use-syslog')

    # Verbose output?
    if args.verbose:
        ryu_args.append('--verbose')

    for arg, val in vars(args).items():
        if not val or not arg.startswith('ryu'):
            continue
        if arg == 'ryu_app':
            continue
        if arg == 'ryu_config_file' and not os.path.isfile(val):
            continue
        arg_name = arg.replace('ryu_', '').replace('_', '-')
        ryu_args.append('--%s=%s' % (arg_name, val))

    # Running Faucet or Gauge?
    apps = []
    if args.gauge or os.path.basename(prog) == 'gauge':
        apps.append('faucet.gauge')
    else:
        apps.append('faucet.faucet')

    # Check for additional Ryu apps.
    if args.ryu_app:
        apps.extend(args.ryu_app)

    if 'ryu.app.ofctl_rest' in apps:
        apps.remove('ryu.app.ofctl_rest')
    if 'experimental_api_test_app.py' in apps:
        apps.remove('experimental_api_test_app.py')
        apps.append('tests.integration.experimental_api_test_app')

    ryu_args.append('--x-modules=%s' % ','.join(apps))

    return ryu_args


def main():
    """Main program."""
    ryu_args = build_ryu_args(sys.argv)
    if ryu_args:
        run(ryu_args)


def run(ryu_args):
    """Run app."""
    args = parse_ryu_args(ryu_args)
    if args.wsapi_port:
        from zof.demo.rest_api import APP as rest_app
        rest_app.http_endpoint = '%s:%d' % (args.wsapi_host or '', args.wsapi_port)

    # Map ryu arguments to framework's argument names.
    args.listen_endpoints = ['%s:%d' % (args.ofp_listen_host, args.ofp_tcp_listen_port)]
    args.listen_cert = args.ctl_cert
    args.listen_cacert = args.ca_certs
    args.listen_privkey = args.ctl_privkey
    args.listen_versions = [4]
    args.pidfile = args.pid_file
    #args.x_oftr_args='--trace=rpc'
    #args.loglevel='debug'
    #print('args=%r' % args)
    _import_modules(args.x_modules)
    zof.run(args=args)


def parse_ryu_args(ryu_args):
    # Add RYU compatible arguments.
    #import zof.demo.metrics
    args = argparse.ArgumentParser(parents=[zof.common_args(include_x_modules=True)])
    args.add_argument('--verbose', action='store_true')
    args.add_argument('--use-stderr', action='store_true')
    args.add_argument('--wsapi-host')
    args.add_argument('--wsapi-port', type=int)
    args.add_argument('--ofp-listen-host', default='')
    args.add_argument('--ofp-tcp-listen-port', type=int, default=6653)
    args.add_argument('--ctl-privkey', type=file_contents_type())
    args.add_argument('--ctl-cert', type=file_contents_type())
    args.add_argument('--ca-certs', type=file_contents_type())
    args.add_argument('--pid-file')
    args.add_argument('--config-file')
    #metrics_endpoint = '%s:%s' % (get_setting('FAUCET_PROMETHEUS_ADDR'), get_setting('FAUCET_PROMETHEUS_PORT'))
    #args.set_defaults(metrics_endpoint=metrics_endpoint)
    return args.parse_args(ryu_args)


if __name__ == '__main__':
    main()

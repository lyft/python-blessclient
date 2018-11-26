#!/usr/local/bin/python

import subprocess
import argparse
import os
import sys
import six

from blessclient.client import bless, get_default_config_filename, get_region_from_code, get_regions
from blessclient.bless_config import BlessConfig


def main():
    parser = argparse.ArgumentParser(description='Bless SSH')
    parser.add_argument('host')
    parser.add_argument('cmd',nargs='*')
    parser.add_argument('--nocache', action='store_true')
    parser.add_argument('--config', default=None, help='Config file for blessclient. Default to ~/.aws/blessclient.cfg')
    parser.add_argument('-4', action='store_true', help='Forces ssh to use IPv4 addresses only.')
    parser.add_argument('-6', action='store_true', help='Forces ssh to use IPv6 addresses only.')
    parser.add_argument('-a', action='store_true', help='Disable forwarding of the authentication agent connection.')
    parser.add_argument('-X', action='store_true', help='Enables X11 forwarding.')
    parser.add_argument('-Y', action='store_true', help='Enables trusted X11 forwarding.')
    parser.add_argument('-l', default=None, help='Specifies the user to log in as on the remote machine. Defaults to IAM user')
    parser.add_argument('-p', default=22, help='Port to connect to on the remote host. Default 22')
    args = parser.parse_args()

    if 'AWS_PROFILE' not in os.environ:
        sys.stderr.write('AWS session not found. Try running get_session first?\n')
        sys.exit(1)

    ssh_options = []
    if vars(args)['4']:
        ssh_options.append('-4')
    if vars(args)['6']:
        if vars(args)['4']:
            sys.stderr.write('ERROR: -4 and -6 are mutually exclusive...\n')
            sys.exit(1)
        ssh_options.append('-6')
    if not args.a:
        ssh_options.append('-A')
    if args.X:
        ssh_options.append('-X')
    if args.Y:
        ssh_options.append('-Y')

    hostname = None
    username = None
    port = args.p

    host = args.host.split('@')
    if len(host) == 2:
        hostname = host[1]
        username = host[0]
    else:
        hostname = host[0]

    host = hostname.split(':')
    if len(host) == 2:
        hostname = host[0]
        port = host[1]

    ssh_options.append('-p')
    ssh_options.append(str(port))

    if args.l is not None:
        username = args.l

    blessclient_output = []
    bless_config = BlessConfig()
    if args.config is not None:
        config_filename = args.config
    else:
        config_filename = get_default_config_filename()
    try:
        with open(config_filename, 'r') as f:
            bless_config.set_config(bless_config.parse_config_file(f))
    except FileNotFoundError as e:
        sys.stderr.write('{}\n'.format(e))
        sys.exit(1)

    start_region = get_region_from_code(None, bless_config)
    for region in get_regions(start_region, bless_config):
        try:
            os.environ['BLESSQUIET'] = "1"
            blessclient_output = bless(region, args.nocache, False, hostname, bless_config, username)
            break
        except SystemExit:
            pass

    if 'username' in blessclient_output:
        ssh_options.append('-l')
        ssh_options.append(blessclient_output['username'])
    elif username != None:
        ssh_options.append('-l')
        ssh_options.append(username)

    if len(args.cmd) >= 1:
        for cmd in args.cmd:
            ssh_options.append(cmd)

    subprocess.run(['ssh', hostname]+ssh_options)
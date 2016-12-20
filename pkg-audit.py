#!/usr/bin/env python


import argparse
import json
import requests
import subprocess
import pycman
from pyalpm import vercmp


VERSION = 0.2
API_URL = 'https://security.archlinux.org'


def main(options):
    # Initialize pyalpm
    configpath = '/etc/pacman.conf'
    handle = pycman.config.init_with_config(configpath)
    db = handle.get_localdb()
    # Handle the situation where a user has enabled [testing]
    if len([syncdb for syncdb in handle.get_syncdbs() if syncdb.name == 'testing']):
        status = ['Testing', 'Fixed']
    else:
        status = ['Fixed']

    # Unfortunately pyalpm does not allow us to set the dbpath to a
    # 'fake' symlinked dbpath as 'checkupdates' does. Neither does it allow
    # use config.init_with_config_and_options since it expects an argparse obj.
    if options.sync:
        subprocess.check_output(["sudo", "pacman", "-Sy"])

    if options.file:
        data = json.load(options.file)
    else:
        # Fetch latest JSON API
        r = requests.get(API_URL + '/json')
        data = r.json()

    for avg in data:
        search_str = '^({})$'.format('|'.join(avg['packages']))
        pkgs = db.search(search_str)

        if not pkgs:
            continue

        # for every pkg, check if affected
        for pkg in pkgs:
            if avg['status'] == 'Vulnerable' and options.upgradable:
                    print('{}-{} is vulnerable to {}'.format(pkg.name, pkg.version, avg['type']))
                    print('No fixed package in the repositories.')
                    print('AVG: {}/{}'.format(API_URL, avg['name']))
                    print('')
            elif avg['status'] in status and options.vulnerable:
                if vercmp(pkg.version, avg['fixed']) < 0:
                    print('{}-{} is vulnerable to {}'.format(pkg.name, pkg.version, avg['type']))
                    print('Upgrade to {}'.format(avg['fixed']))
                    print('AVG: {}/{}'.format(API_URL, avg['name']))
                    for advisory in avg['advisories']:
                        print('Advisory: {}/{}/raw'.format(API_URL, advisory))
                    print('')


def parse_args():
    parser = argparse.ArgumentParser(description='audit installed packages against known vulnerabilities')
    parser.add_argument('-f', '--file', type=argparse.FileType('r'),
            help='Load advisories from a JSON file.')
    parser.add_argument('--upgradable', dest='upgradable', action='store_false',
            help='Filter on packages which vulernablilties are fixed by performing a system upgrade')
    parser.add_argument('--vulnerable', dest='vulnerable', action='store_false',
            help='Filter on packages which have no fixed version in the repositories yet')
    parser.add_argument('--sync', dest='sync', action='store_true',
            help='Sync the Pacman database before checking vulnerabilities (requires sudo)')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s (version {})'.format(VERSION))
    return parser


if __name__ == '__main__':
    parser = parse_args()
    main(parser.parse_args())

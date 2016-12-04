#!/usr/bin/env python


import argparse
import requests
import pycman
from pyalpm import vercmp


VERSION = 0.1
API_URL = 'http://45.32.158.89'


def main(options):
    # Initialize pyalpm
    configpath = '/etc/pacman.conf'
    handle = pycman.config.init_with_config(configpath)
    db = handle.get_localdb()

    # Fetch latest JSON API
    r = requests.get(API_URL + '/json')
    data = r.json()

    for avg in data:
        packages = "|".join(avg['packages'])
        pkgs = db.search('^({})$'.format(packages))

        if not pkgs:
            continue

        # for every pkg, check if affected
        for pkg in pkgs:
            if not avg['fixed'] and avg['status'] == 'Vulnerable':
                if not options.upgrade:
                    print('{}-{} is vulnerable to {}'.format(pkg.name, pkg.version, avg['type']))
                    print('No fixed package in the repositories.')
                    print('AVG: {}/{}'.format(API_URL, avg['name']))
                    print('')
            elif avg['fixed'] and vercmp(pkg.version, avg['fixed']) < 0:
                print('{}-{} is vulnerable to {}'.format(pkg.name, pkg.version, avg['type']))
                print('Upgrade to {}'.format(avg['fixed']))
                for advisory in avg['advisories']:
                    print('Advisory: {}/{}/generate/raw'.format(API_URL, advisory))
                print('')


def parse_args():
    parser = argparse.ArgumentParser(description='audit installed packages against known vulnerabilities')
    parser.add_argument('--upgrade', dest='upgrade', action='store_true',
            help='Filter on packages which vulernablilties are fixed by performing a system upgrade')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s (version {})'.format(VERSION))
    return parser.parse_args()


if __name__ == '__main__':
    main(parse_args())

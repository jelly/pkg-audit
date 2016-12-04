#!/usr/bin/env python

import argparse
import requests
import pycman
from pyalpm import vercmp


VERSION = 0.1


def main(options):
    # Initialize pyalpm
    configpath = '/etc/pacman.conf'
    handle = pycman.config.init_with_config(configpath)
    db = handle.get_localdb()

    # Fetch latest JSON API
    r = requests.get('http://45.32.158.89/json')
    data = r.json()

    for avg in data:
        packages = "|".join(avg['packages'])
        pkgs = db.search('^({})$'.format(packages))

        if not pkgs:
            continue

        # for every pkg, check if affected
        for pkg in pkgs:
            if not avg['fixed']:
                if not options.upgradeable:
                    print('Package {} is vulnerable to {}, check the tracker for workarounds for {}'.format(pkg.name, avg['type'], avg['name']))
            elif vercmp(pkg.version, avg['fixed']) < 0:
                print('Package {} is vulnerable to {}, upgrade to {}'.format(pkg.name, avg['type'], avg['fixed']))


def parse_args():
    parser = argparse.ArgumentParser(description='audit installed packages against known vulnerabilities')
    parser.add_argument('--upgradeable', dest='upgradeable', action='store_true', help='Filter on packages which vulernablilties are fixed by performing a system upgrade')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s (version {})'.format(VERSION))
    return parser.parse_args()


if __name__ == '__main__':
    main(parse_args())

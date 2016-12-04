#!/usr/bin/env python

import requests
import pycman
from pyalpm import vercmp


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
            print('Package {} is vulnerable to {}, check the tracker for workarounds for {}'.format(pkg.name, avg['type'], avg['name']))
        elif vercmp(pkg.version, avg['fixed']) < 0:
            print('Package {} is vulnerable to {}, upgrade to {}'.format(pkg.name, avg['type'], avg['fixed']))

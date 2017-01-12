# Arch Linux Package Audit [![Build Status](https://travis-ci.org/jelly/pkg-audit.svg?branch=master)](https://travis-ci.org/jelly/pkg-audit) [![License](https://img.shields.io/github/license/jelly/pkg-audit.svg)](https://github.com/jelly/pkg-audit/blob/master/LICENSE.txt)

Pkg audit uses the [Arch Linux Security Tracker](https://github.com/anthraxx/arch-security-tracker)
and [pyalpm](https://git.archlinux.org/users/remy/pyalpm.git/) to figure out which packages on your system are vulnerable and can be updated.

## Dependencies

* python >= 3.4
* python-requests
* pyalpm
* sudo (for --sync)

## Usage

$ python pkg-audit.py

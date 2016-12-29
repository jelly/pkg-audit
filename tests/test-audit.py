#!/usr/bin/env python

import sys
from io import StringIO
from unittest import TestCase

# Can't import pkg-audit with import, so the ugly way
exec(open('pkg-audit.py').read())
result = open('tests/output.txt').read()
result_quiet = open('tests/output-quiet.txt').read()
parser = parse_args()

class PkgAudit(TestCase):

    def execute(self, args = []):
        parsed = parser.parse_args(['--file', 'tests/avgs.json'] + args)
        
        # Hack capturing stdout.
        backup = sys.stdout
        sys.stdout = StringIO()
        main(parsed)
        out = sys.stdout.getvalue()

        sys.stdout.close()
        sys.stdout = backup

        return out

    def test_upgradable(self):
        output = self.execute(['--upgradable'])
        self.assertEqual(len(output), 0)

    def test_vulnerable(self):
        output = self.execute(['--vulnerable'])
        self.assertEqual(output, result)

    def test_quiet(self):
        output = self.execute(['--quiet'])
        self.assertEqual(output, result_quiet)

        
    def test_noargs(self):
        output = self.execute()
        self.assertTrue('openjpeg' in output)
        self.assertEqual(output, result)

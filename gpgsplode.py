#!/usr/bin/env python2
# Export/import GPG keyrings for backup/merge/sync.
# Copyright (C) 2013 Tony Garnock-Jones <tonygarnockjones@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import os
import subprocess
import re
import argparse
import json

class AppError(Exception): pass

###########################################################################
# Shelling out to the system flexibly.
#
# Generally, use qx if you want the output, and ssc or sc if you don't.
# Use ssc2 and sc2 if for some reason you want to capture stderr.
#
# qx: like backticks; returns stdout; uses the shell for command parsing
# ssc: like os.system; uses the shell for command parsing
# sc: like os.system; uses execvp directly
# ssc2: like backticks; returns (stdout, stderr); uses the shell
# sc2: like backticks; returns (stdout, stderr); uses execvp

def sc2internal(cmd, shell,
                input = None,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE,
                ignoreResult = False,
                stripResult = True):
    # print "Invoking", cmd
    p = subprocess.Popen(cmd,
                         stdin = subprocess.PIPE,
                         stdout = stdout,
                         stderr = stderr,
                         shell = shell,
                         close_fds = True)
    (output, errors) = p.communicate(input)
    if not output: output = ''
    if not errors: errors = ''
    if p.returncode and not ignoreResult:
        # print "stdout:", output.rstrip()
        # print "stderr:", errors.rstrip()
        raise subprocess.CalledProcessError(p.returncode, cmd)
    if stripResult:
        return (output.strip(), errors.strip())
    else:
        return (output, errors)

def sc2(cmd, **kwargs): return sc2internal(cmd, False, **kwargs)
def ssc2(cmd, **kwargs): return sc2internal(cmd, True, **kwargs)

def scinternal(cmd, shell, **kwargs):
    (output, errors) = sc2internal(cmd, shell, **kwargs)
    return output

def sc(cmd, **kwargs): scinternal(cmd, False, **kwargs)
def ssc(cmd, **kwargs): scinternal(cmd, True, **kwargs)
def qx(cmd, **kwargs): return scinternal(cmd, True, **kwargs)

###########################################################################

class Grouplines:
    def __init__(self, lines):
        self.groups = []
        self.group = []
        for line in lines:
            if not line:
                self.finish_group()
                continue
            self.group.append(line)
        self.finish_group()
    def finish_group(self):
        if self.group:
            self.groups.append(self.group)
            self.group = []

class Block:
    def __init__(self, description_lines):
        self.description_lines = description_lines
        (self.keytype, self.keyid) = self.parse_description()
        self._armor = None

    def parse_description(self):
        pieces = self.description_lines[0].split()
        keytype = pieces[0]
        pieces = pieces[1].split('/')
        keyid = pieces[1]
        return (keytype, keyid)

    def export_option(self):
        if self.keytype == 'pub': return "--export"
        if self.keytype == 'sec': return "--export-secret-keys"
        raise AppError("Cannot export key of unknown keytype '%s'" % (self.keytype,))

    def armor(self):
        if self._armor is None:
            self._armor = sc2(["gpg", "--armor", self.export_option(), self.keyid])[0]
        return self._armor

    def exportfilename(self):
        return self.keyid + '.' + self.keytype + '.asc'

    def exportstr(self):
        return '\n'.join(self.description_lines) + '\n\n' + self.armor()

class Keyring:
    def __init__(self, name, list_option):
        self.name = name
        lines = sc2(["gpg", list_option, "--keyid-format", "long"])[0].split('\n')
        if len(lines) < 2:
            self.blocks = []
        else:
            if lines[0][0] != '/':
                raise AppError("Could not detect keyring name at start of gpg output")
            if not re.match('-+', lines[1]): raise AppError("Could not understand gpg output")
            self.blocks = [Block(g) for g in Grouplines(lines[2:]).groups]

class Ownertrust:
    def __init__(self):
        pass

    def exportstr(self):
        lines = [l for l in sc2(["gpg", "--export-ownertrust"])[0].split('\n')
                 if not l.startswith('#')]
        lines.sort()
        return '\n'.join(lines)

###########################################################################

app_description="""Export/import GPG keyrings for backup/merge/sync.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""

class App:
    def __init__(self, argv):

        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=app_description)
        subparsers = parser.add_subparsers(
            title="Subcommands",
            description="gpgsplode can perform any one of a few related tasks.")

        parser.add_argument('-g', '--gnupg-home',
                            required=True,
                            metavar='DIRECTORY',
                            help="Location of keyrings to use. Your main keyrings are in ~/.gnupg/.")
        parser.add_argument('-d', '--directory',
                            required=True,
                            metavar='DIRECTORY',
                            help="File system directory to use when exporting/importing.")
        parser.add_argument('-p', '--include-public-keys',
                            action='store_true', default=True,
                            help="Include public keys when exporting/importing.")
        parser.add_argument('-s', '--include-secret-keys',
                            action='store_true', default=False,
                            help="Include secret keys when exporting/importing.")

        export_help = "Export keys from GPG's keyrings to a file system directory."
        p_export = subparsers.add_parser('export', description=export_help, help=export_help)
        p_export.set_defaults(action=self.export_action)

        import_help = "Import keys from a file system directory to GPG's keyrings."
        p_import = subparsers.add_parser('import', description=import_help, help=import_help)
        p_import.set_defaults(action=self.import_action)

        self.version = '1.0'
        self.config = parser.parse_args(argv)
        self._keyrings = None

        self.setup_gnupghome()

    def setup_gnupghome(self):
        if not os.path.isdir(self.config.gnupg_home):
            raise AppError('Selected $GNUPGHOME directory "%s" missing or not a directory.' %
                           (self.config.gnupg_home,))
        print 'Using $GNUPGHOME="%s".' % (self.config.gnupg_home,)
        os.environ['GNUPGHOME'] = self.config.gnupg_home

    def keyrings(self):
        if self._keyrings is None:
            self._keyrings = []
            if self.config.include_public_keys:
                self._keyrings.append(Keyring('pubring', '--list-keys'))
            if self.config.include_secret_keys:
                self._keyrings.append(Keyring('secring', '--list-secret-keys'))
        return self._keyrings

    def run(self):
        self.config.action()

    def dbfilename(self, relpath):
        return os.path.join(self.config.directory, relpath)

    def dbfile(self, relpath, mode):
        return open(self.dbfilename(relpath), mode)

    def safe_makedirs(self, path):
        if os.path.exists(path):
            if os.path.isdir(path):
                return
            raise AppError('Cannot create directory "%s", as there is something in the way' %
                           (path,))
        os.makedirs(path)

    def check_meta(self, require_meta):
        try:
            with self.dbfile('gpgsplode_meta', 'r') as f:
                meta = json.load(f)
        except IOError:
            if not require_meta:
                return
            raise AppError('Could not read %s' % (self.dbfilename('gpgsplode_meta'),))

        if meta['version'] != self.version:
            raise AppError('Database in %s claims version %s, but we are version %s' %
                           (self.config.directory, meta['version'], self.version))

    def write_meta(self):
        with self.dbfile('gpgsplode_meta', 'w') as f:
            json.dump({"version": self.version}, f, indent=2)

    def export_action(self):
        print 'Exporting GPG keyring(s).'
        self.safe_makedirs(self.config.directory)

        self.check_meta(False)
        ## ^ We don't require that a metafile is there, but if there
        ## is one, we must be able to comprehend it, because we're
        ## about to stomp all over its database. Exports are
        ## idempotent under current versions; if this changes, then
        ## this check will need to be improved.

        self.write_meta()
        for ring in self.keyrings():
            print 'Keyring %s...' % (ring.name,)
            self.safe_makedirs(self.dbfilename(ring.name))
            for b in ring.blocks:
                print '  key', b.exportfilename()
                with self.dbfile(os.path.join(ring.name, b.exportfilename()), 'w') as f:
                    f.write(b.exportstr())

        print 'Exporting ownertrust.'
        with self.dbfile('ownertrust', 'w') as f:
            f.write(Ownertrust().exportstr())

        print 'Done!'

    def import_action(self):
        self.check_meta(True)

if __name__ == '__main__':
    try:
        App(sys.argv[1:]).run()
    except AppError, ae:
        print ae.message
        sys.exit(1)
    sys.exit(0)

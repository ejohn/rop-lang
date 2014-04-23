#!/usr/bin/env python

# Copyright (c) 2009, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

__revision__ = "$Id: setup.py 396 2009-08-31 01:01:26Z qvasimodo $"

import os
import sys
import string
import platform

from distutils.core import setup
from distutils.command.install_lib import install_lib

# Customized install_lib command to set the execution bit in some files
class custom_install_lib(install_lib):
    def install(self):
        outfiles = install_lib.install(self)
        for outfile in outfiles:
            if os.path.splitext(outfile)[1].lower() != '.py':
                print "setting mode 755 to %s" % outfile
                os.chmod(outfile, 0755)
        return outfile

def main():

    # Get the target platform
    arch    = platform.architecture()[0].lower()
    machine = platform.machine().lower()
    system  = platform.system().lower()
    if 'cygwin' in system:
        system = 'cygwin'
    elif 'darwin' in system:
        system = 'macosx'
    if machine.startswith('power'):
        machine = 'ppc'
    elif machine.endswith('86'):
        machine = 'x86'
    elif not machine:
        if system == 'macosx':
            if arch == '64bit':
                machine = 'x86_64'
            elif arch == '32bit':
                if sys.byteorder == 'little':
                    machine = 'x86'
                else:
                    machine = 'ppc'
        elif system == 'windows':
            if arch == '64bit':
                machine = 'amd64'
            else:
                machine = 'x86'
        else:
            if arch == '64bit':
                machine = 'x86_64'
            else:
                machine = 'x86'

    # Get the filename for the target platform
    if   system in ('windows', 'cygwin'):
        data = 'distorm64.dll'
    elif system == 'darwin':
        data = 'libdistorm64.dylib'
    else:
        data = 'libdistorm64.so'

    # Parse the package root directory
    cwd = os.path.split(__file__)[0]
    if not cwd:
        cwd = os.getcwd()
    root = '%s-%s' % (system, machine)
    root = os.path.join(cwd, root)

    # Check if the package root directory exists
    if not os.path.exists(root):
        print "Error: unsupported platform (%s-%s)" % (system, machine)
        return

    options = {

    # Setup instructions
    'requires'          : ['ctypes'],
    'provides'          : ['distorm'],
    'packages'          : ['distorm'],
    'package_data'      : { 'distorm' : [data] },
    'package_dir'       : { 'distorm' : root },
    'cmdclass'          : { 'install_lib' : custom_install_lib },

    # Metadata
    'name'              : 'distorm',
    'version'           : '1.7.30',
    'description'       : ':[diStorm64}:',
    'long_description'  : (
                        'The ultimate disassembler library (for AMD64, X86-64)\n'
                        'by Gil Dabah (arkon@ragestorm.net)\n'
                        '\n'
                        'Python bindings by Mario Vilas (mvilas@gmail.com)'
                        ),
    'author'            : 'Gil Dabah',
    'author_email'      : 'arkon'+chr(64)+'ragestorm'+chr(0x2e)+'net',
    'maintainer'        : 'Mario Vilas',
    'maintainer_email'  : 'mvilas'+chr(64)+'gmail'+chr(0x2e)+'com',
    'url'               : 'http://ragestorm.net/distorm/',
    'download_url'      : 'http://ragestorm.net/distorm/',
    'platforms'         : ['cygwin', 'win', 'linux', 'macosx'],
    'classifiers'       : [
                        'License :: OSI Approved :: BSD License',
                        'Development Status :: 5 - Production/Stable',
                        'Intended Audience :: Developers',
                        'Natural Language :: English',
                        'Operating System :: Microsoft :: Windows',
                        'Operating System :: MacOS :: MacOS X',
                        'Operating System :: POSIX :: Linux',
                        'Programming Language :: Python :: 2.4',
                        'Programming Language :: Python :: 2.5',
                        'Programming Language :: Python :: 2.6',
                        'Topic :: Software Development :: Disassemblers',
                        'Topic :: Software Development :: Libraries :: Python Modules',
                        ],
    }

    # Change the current directory
    curdir = os.path.split(__file__)[0]
    if curdir:
        os.chdir(curdir)

    # Call the setup function
    setup(**options)

if __name__ == '__main__':
    main()

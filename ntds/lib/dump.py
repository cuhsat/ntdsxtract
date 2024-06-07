# This file is part of ntdsxtract.
#
# ntdsxtract is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ntdsxtract is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ntdsxtract.  If not, see <http://www.gnu.org/licenses/>.

'''
@author:        Csaba Barta
@license:       GNU General Public License 2.0 or later
@contact:       csaba.barta@gmail.com
'''

# Original hex dump code from
# http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/142812


def dump(src, length=8, indent=0):
    f = bytes([(len(repr(chr(x))) == 3) and x or ord('.') for x in range(256)])
    n, result = 0, ''
    while src:
        b, src = src[:length], src[length:]
        hexa = ' '.join(["%02X" % x for x in b])
        b = b.translate(f)
        s = b.decode("unicode_escape")
        istr = ""
        if indent > 0:
            for i in range(indent):
                istr += " "
        result += istr + "%04X   %-*s   %s\n" % (n, length*3, hexa, s)
        n += length
    return result

#!/usr/bin/env python
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
import re

from ntds.version import *
from ntds.dsdatabase import *
from ntds.dsrecord import *
from ntds.dsobjects import *
from ntds.dslink import *
from ntds.dstime import *
from ntds.lib.fs import *
from ntds.lib.csvoutput import *


def usage():
    print("DSGroups v" + str(ntds.version.version))
    print("Extracts information related to group objects")
    print("usage: %s <datatable> <linktable> <work directory> [option]\n" % sys.argv[0])
    print("  datatable")
    print("    The path to the file called datatable extracted by esedbexport")
    print("  linktable")
    print("    The path to the file called linktable extracted by esedbexport")
    print("  work directory")
    print("    The path to the directory where ntdsxtract should store its")
    print("    cache files and output files. If the directory does not exist")
    print("    it will be created.\n")
    print("  options:")
    print("    --rid <group rid>")
    print("          Extracts only the group identified by <group id>")
    print("    --name <group name regexp>")
    print("          Extracts only the group identified by the regular expression")
    print("    --members")
    print("          Extracts the members of the group")
    print("    --csvoutfile <name of the CSV output file>")
    print("          The filename of the csv file to which ntdsxtract should write the")
    print("          output")
    print("    --debug")
    print("          Turn on detailed error messages and stack trace\n")


if len(sys.argv) < 4:
    usage()
    sys.exit(1)

print("[+] Started at: %s" % time.strftime(
                                        "%a, %d %b %Y %H:%M:%S UTC",
                                        time.gmtime()))
print("[+] Started with options:")
optid = 0
rid = ""
name = ""
grpdump = False
csvoutfile = ""
csvof = None
reName = None

for opt in sys.argv:
    if opt == "--rid":
        if len(sys.argv) < 5:
            usage()
            sys.exit(1)
        rid = int(sys.argv[optid + 1])
        print("\t[-] Group RID: %d" % rid)
    if opt == "--name":
        if len(sys.argv) < 5:
            usage()
            sys.exit(1)
        name = sys.argv[optid + 1]
        reName = re.compile(name)
        print("\t[-] Group name: %s" % name)
    if opt == "--members":
        grpdump = True
        print("\t[-] Extracting group members")
    if opt == "--csvoutfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        csvoutfile = sys.argv[optid + 1]
        print("\t[-] CSV output filename: " + sys.argv[optid + 1])
    optid += 1
print("")

# Setting up the environment
if not checkfile(sys.argv[1]):
    print("[!] Error! datatable cannot be found!")
    sys.exit(1)
if not checkfile(sys.argv[2]):
    print("[!] Error! linktable cannot be found!")
    sys.exit(1)
wd = ensure_dir(sys.argv[3])

if csvoutfile != "":
    init_csv(path.join(wd, csvoutfile))

# Initializing engine
db = dsInitDatabase(sys.argv[1], wd)
dl = dsInitLinks(sys.argv[2], wd)

gtype = dsGetTypeIdByTypeName(db, "Group")
utype = dsGetTypeIdByTypeName(db, "Person")
ctype = dsGetTypeIdByTypeName(db, "Computer")

users = []
if grpdump is True:
    print("[+] Extracting user objects...")
    for recordid in dsMapLineIdByRecordId:
        if (int(dsGetRecordType(db, recordid)) == utype or
            int(dsGetRecordType(db, recordid)) == ctype):
            try:
                user = dsUser(db, recordid)
            except:
                print("[!] Unable to instantiate user object (record id: %d)" % recordid)
                continue
            users.append(user)
            user = None
        
if csvoutfile != "":
    write_csv(["Record ID", "Group name", "GUID", "SID", "When created",
               "When changed", "Member object", "Member SAMAccountName", "Member object GUID",
               "Member object type", "Primary group of member",
               "Membership deletion time"
            ])
        
print("List of groups:")
print("===============")
for recordid in dsMapLineIdByRecordId:
    if int(dsGetRecordType(db, recordid)) == gtype:
        try:
            group = dsGroup(db, recordid)
        except:
            print("[!] Unable to instantiate group object (record id: %d)" % recordid)
            continue
        if rid != "" and group.SID.RID != int(rid):
            group = None
            continue
        if reName != None and not reName.search(group.Name):
            group = None
            continue
        
        print("Record ID:    %d" % group.RecordId)
        print("Group Name:   %s" % group.Name)
        print("GUID:         %s" % str(group.GUID))
        print("SID:          %s" % str(group.SID))
        print("When created: %s" % dsGetDSTimeStampStr(group.WhenCreated))
        print("When changed: %s" % dsGetDSTimeStampStr(group.WhenChanged))
        
        # The main group record
        if csvoutfile != "":
            write_csv([group.RecordId, group.Name, str(group.GUID),
                str(group.SID), "'" + dsGetDSTimeStampStr(group.WhenCreated),
                "'" + dsGetDSTimeStampStr(group.WhenChanged),
                "", "", ""])
        
        if grpdump is True:
            print("Members:")
            for u in users:
                if u.PrimaryGroupID != -1:
                    if u.PrimaryGroupID == group.SID.RID:
                        if csvoutfile != "":
                            write_csv([group.RecordId, group.Name, str(group.GUID),
                                    str(group.SID), "=\"" + dsGetDSTimeStampStr(group.WhenCreated) + "\"",
                                    "=\"" + dsGetDSTimeStampStr(group.WhenChanged) + "\"",
                                    u.Name, u.SAMAccountName, str(u.GUID), u.Type, "Y", ""
                                    ])
                        print("\t%s (%s) (%s) (P)" % (u.Name, str(u.GUID), u.Type))
            memberlist = group.getMembers()
            for memberdata in memberlist:
                (memberid, deltime) = memberdata
                try:
                    member = dsAccount(db, memberid)
                except:
                    continue
                if member is None:
                    continue
                if deltime == -1:
                    if csvoutfile != "":
                        write_csv([group.RecordId, group.Name, str(group.GUID),
                            str(group.SID), "=\"" + dsGetDSTimeStampStr(group.WhenCreated) + "\"",
                            "=\"" + dsGetDSTimeStampStr(group.WhenChanged) + "\"",
                            member.Name, member.SAMAccountName, str(member.GUID), member.Type, "N", ""
                            ])
                    print("\t%s (%s) (%s)" % (member.Name, str(member.GUID), member.Type))
                else:
                    if csvoutfile != "":
                        write_csv([group.RecordId, group.Name, str(group.GUID),
                            str(group.SID), "=\"" + dsGetDSTimeStampStr(group.WhenCreated) + "\"",
                            "=\"" + dsGetDSTimeStampStr(group.WhenChanged) + "\"",
                            member.Name, member.SAMAccountName, str(member.GUID), member.Type, "N", "=\"" + dsGetDSTimeStampStr(dsConvertToDSTimeStamp(deltime)) + "\""
                            ])
                    print("\t%s (%s) (%s) - Deleted: %s" % (member.Name,
                                                                         str(member.GUID), 
                                                                         member.Type, 
                                                                         dsGetDSTimeStampStr(dsConvertToDSTimeStamp(deltime))))
                member = None
        
        group = None
        print("")

if csvoutfile != "":
    close_csv()

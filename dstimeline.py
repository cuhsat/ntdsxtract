#!/usr/bin/env python
# This file is part of ntdsxtract.
#
# ntdsxtract is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ntdsdump is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ntdsdump.  If not, see <http://www.gnu.org/licenses/>.

'''
@author:        Csaba Barta
@license:       GNU General Public License 2.0 or later
@contact:       csaba.barta@gmail.com
'''
import sys
import time
from operator import *
from ntds.version import *
from ntds.dsdatabase import *
from ntds.dsobjects import *
from ntds.dstime import *
from ntds.dsrecord import *
from ntds.lib.fs import *
from ntds.lib.csvoutput import *

times = []
timeline = []

def usage():
    print("DSTimeline v" + str(ntds.version.version))
    print("Constructs timeline")
    print("usage: %s <datatable> <work directory> [option]\n" % sys.argv[0])
    print("  datatable")
    print("    The full path to the file called datatable extracted by esedbexport")
    print("  work directory")
    print("    The full path to the directory where ntdsxtract should store its")
    print("    cache files and output files. If the directory does not exist")
    print("    it will be created.")
    print("  options:")
    print("    --b")
    print("       Output timeline in mactime body format.")
    print("    --csv")
    print("       Output timeline in CSV format.")
    print("    --outfile <name of the output file>")
    print("          The filename of the output file to which ntdsxtract should write the")
    print("          output")
    print("    --debug")
    print("       Turn on detailed error messages and stack trace\n")
    print("Fields of the default output")
    print("    Timestamp|Action|Record ID|Obj. name|Obj. type\n")

if len(sys.argv) < 2:
    usage()
    sys.exit(1)

print("[+] Started at: %s" % time.strftime(
                                        "%a, %d %b %Y %H:%M:%S UTC",
                                        time.gmtime()))

bodyformat = False
csvformat = False
outfile = ""

print("[+] Started with options:")
optid = 0
for opt in sys.argv:
    if opt == "--b":
        if csvformat is True:
            print("[!] Error! CSV and body format cannot be defined at the same time!")
            sys.exit(1)
        bodyformat = True
        print("\t[-] Using mactime body format")
    if opt == "--csv":
        if bodyformat is True:
            print("[!] Error! CSV and body format cannot be defined at the same time!")
            sys.exit(1)
        csvformat = True
        print("\t[-] Using CSV format")
    if opt == "--outfile":
        if len(sys.argv) < optid + 2:
            usage()
            sys.exit(1)
        outfile = sys.argv[optid + 1]
        print("\t[-] Output filename: " + sys.argv[optid + 1])
    optid += 1

# Check the datatable
if not checkfile(sys.argv[1]):
    print("[!] Error! datatable cannot be found!")
    sys.exit(1)

# Check the workdir
wd = ensure_dir(sys.argv[2])

# Check the output file
if outfile != "" and csvformat == True:
    init_csv(path.join(wd, outfile))
    write_csv(["Timestamp", "Event", "Record ID", "Object name",
                   "Object type"
            ])

bof = None
if outfile != "" and bodyformat is True:
    bof = open(path.join(wd, outfile), "wb")

# Initialize engine
db = dsInitDatabase(sys.argv[1], wd)

i = 0
l = len(dsMapLineIdByRecordId)
for recordid in dsMapLineIdByRecordId:
    print("[+] Building timeline - %d%% -> %d records processed" % (
                                                                           i*100/l,
                                                                           i
                                                                           ))
    try:
        tmp = dsObject(db, recordid)
    except:
        continue
    
    if bodyformat == True:
        if tmp.WhenChanged != -1 or tmp.WhenCreated != -1:
            times.append((recordid, 
                          0 if tmp.WhenCreated == -1 else tmp.WhenCreated, 
                          0 if tmp.WhenChanged == -1 else tmp.WhenChanged, 
                          tmp.Name + " (" + str(tmp.GUID) + ")",
                          tmp.Type,
                          ""
                          ))
        
        if tmp.Type == "Person":
            user = dsAccount(db, recordid)
            if user.LastLogon != -1:
                times.append((recordid, 
                              0, 
                              user.LastLogon, 
                              user.Name + " (" + str(user.GUID) + ")",
                              user.Type, 
                              "Logged in"
                              ))
            if user.LastLogonTimeStamp != -1:
                times.append((recordid, 
                              0, 
                              user.LastLogonTimeStamp, 
                              user.Name + " (" + str(user.GUID) + ")",
                              user.Type, 
                              "Login timestamp sync"
                              ))
            if user.PasswordLastSet != -1:
                times.append((recordid, 
                              0, 
                              user.PasswordLastSet, 
                              user.Name + " (" + str(user.GUID) + ")", 
                              user.Type,
                              "Password changed"
                              ))
            user = None
    
    if csvformat == True:
        if dsVerifyDSTimeStamp(tmp.WhenCreated) != -1:
            times.append((recordid, tmp.WhenCreated, "Created", tmp.Name + " (" + str(tmp.GUID) + ")", tmp.Type))
        if dsVerifyDSTimeStamp(tmp.WhenChanged) != -1:
            times.append((recordid, tmp.WhenChanged, "Modified", tmp.Name + " (" + str(tmp.GUID) + ")", tmp.Type))
        
        if tmp.Type == "Person":
            user = dsAccount(db, recordid)
            if user.LastLogon != -1 and user.LastLogon != 0:
                times.append((recordid,
                              user.LastLogon, 
                              "Logged in", 
                              user.Name + " (" + str(user.GUID) + ")", 
                              user.Type
                              ))
                
            if user.LastLogonTimeStamp != -1 and user.LastLogonTimeStamp != 0:
                times.append((recordid, 
                              user.LastLogonTimeStamp, 
                              "Login timestamp sync", 
                              user.Name + " (" + str(user.GUID) + ")", 
                              user.Type
                              ))
                
            if user.PasswordLastSet != -1 and user.PasswordLastSet != 0:
                times.append((recordid, 
                              user.PasswordLastSet, 
                              "Password changed", 
                              user.Name + " (" + str(user.GUID) + ")", 
                              user.Type
                              ))
            user = None
    i += 1
print("")
        
timeline = sorted(times, key=itemgetter(1))
for item in timeline:
    if bodyformat == True:
        (id, ctimestamp, mtimestamp, name, type, actiontype) = item
        if actiontype != "":
            print("0|%s (%s) - (%s)|%d||0|0|0|0|%d|0|%d" % (
                                                     name, 
                                                     type,
                                                     actiontype, 
                                                     id,
                                                     dsGetPOSIXTimeStamp(mtimestamp),
                                                     dsGetPOSIXTimeStamp(ctimestamp)
                                                     ))
            if outfile != "":
                bof.write("0|%s (%s) - (%s)|%d||0|0|0|0|%d|0|%d\n" % (
                                                     name, 
                                                     type,
                                                     actiontype, 
                                                     id,
                                                     dsGetPOSIXTimeStamp(mtimestamp),
                                                     dsGetPOSIXTimeStamp(ctimestamp)
                                                     ))
        else:
            print("0|%s (%s)|%d||0|0|0|0|%d|0|%d" % (
                                                     name, 
                                                     type, 
                                                     id,
                                                     dsGetPOSIXTimeStamp(mtimestamp),
                                                     dsGetPOSIXTimeStamp(ctimestamp)
                                                     ))
            if outfile != "":
                bof.write("0|%s (%s)|%d||0|0|0|0|%d|0|%d\n" % (
                                                     name, 
                                                     type, 
                                                     id,
                                                     dsGetPOSIXTimeStamp(mtimestamp),
                                                     dsGetPOSIXTimeStamp(ctimestamp)
                                                     ))
    if csvformat == True:
        (id, timestamp, action, name, type) = item
        print("%s|%s|%d|%s (%s)" % (
                                       dsGetDSTimeStampStr(timestamp),
                                       action,
                                       id,
                                       name,
                                       type
                                       ))
        if outfile != "":
            write_csv(["=\"" + dsGetDSTimeStampStr(timestamp) + "\"", action, id, name,
                       type
                ])
        
print("")

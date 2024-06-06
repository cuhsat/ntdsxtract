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

import sys
import ntds.dsfielddictionary
from ntds.version import *
from ntds.dsdatabase import *
from ntds.dsobjects import *
from ntds.dsrecord import *
from ntds.dstime import *
from ntds.lib.fs import *
import time
from os import path

if len(sys.argv) < 3 or len(sys.argv) > 6:
    print("\nDSDeletedObjects v" + str(ntds.version.version))
    print("\nExtracts information related to deleted objects")
    print("\n\nusage: %s <datatable> <work directory> [option]" % sys.argv[0])
    print("\n\n  datatable")
    print("\n    The path to the file called datatable extracted by esedbexport")
    print("\n  work directory")
    print("\n    The path to the directory where ntdsxtract should store its")
    print("\n    cache files and output files. If the directory does not exist")
    print("\n    it will be created.")
    print("\n  options:")
    print("\n    --output <output file name>")
    print("\n        The record containing the object and the preserved attributes will be")
    print("\n        written to this file")
    print("\n    --useIsDeleted")
    print("\n        Extract deleted objects based on the IsDeleted flag")
    print("\n    --debug")
    print("\n        Turn on detailed error messages and stack trace")
    print("\n\nFields of the main output")
    print("\n    Rec. ID|Cr. time|Mod. time|Obj. name|Orig. container name\n")
    sys.exit(1)

of = ""
useID = False

optid = 0
for opt in sys.argv:
    if opt == "--output":
        if len(sys.argv) < 5:
            sys.exit(1)
        of = sys.argv[optid + 1]
    if opt == "--useIsDeleted":
        useID = True
    optid += 1

if not checkfile(sys.argv[1]):
    print("\n[!] Error! datatable cannot be found!\n")
    sys.exit(1)
wd = ensure_dir(sys.argv[2])

print("\n[+] Started at: %s" % time.strftime(
                                        "%a, %d %b %Y %H:%M:%S UTC",
                                        time.gmtime()))
print("\n[+] Started with options:")
if useID == True:
    print("\n\t[-] Using IsDeleted flag")
else:
    print("\n\t[-] Using Deleted Objects containers")
if of != "":
    print("\n\t[-] Output file: %s" % of)
print("\n")

    

delobjconts = []
delobjs = []

db = dsInitDatabase(sys.argv[1], wd)
ctypeid = dsGetTypeIdByTypeName(db, "Container")

l = len(dsMapLineIdByRecordId)
i = 0

if of != "":
    fdelobjs = open(path.join(wd, of), 'w')

if useID == False:
    for recid in dsMapLineIdByRecordId:
        print("\rExtracting deleted objects - %d%%" % (i*100/l))

        rec = dsGetRecordByLineId(db, dsMapLineIdByRecordId[recid])
        try:
            if (int(rec[ntds.dsfielddictionary.dsObjectTypeIdIndex]) == ctypeid and
                rec[ntds.dsfielddictionary.dsObjectName2Index] == "Deleted Objects"):
                
                delobjconts.append(recid)
        except:
            pass
        i += 1
    print("\n")
    
    if of != "":
        fdelobjs.writelines('\t'.join(ntds.dsfielddictionary.dsFieldNameRecord))
    
    for crecid in delobjconts:
        try:
            container = dsObject(db, crecid)
        except:
            print("\n[!] Unable to instantiate container object (record id: %d)" % crecdid)
            continue
        if container == None:
            continue
        childs = container.getChilds()
        for did in childs:
            try:
                dobj = dsObject(db, did)
            except:
                print("\n[!] Unable to instantiate object (record id: %d)" % did)
                continue
            if dobj == None:
                continue
            
            origcname = ""
            if ntds.dsrecord.dsGetRecordByRecordId(
                    db,
                    dobj.Record[ntds.dsfielddictionary.dsOrigContainerIdIndex]
                    ) != None:
                
                origcname = ntds.dsrecord.dsGetRecordByRecordId(
                                db,
                                dobj.Record[ntds.dsfielddictionary.dsOrigContainerIdIndex]
                                )[ntds.dsfielddictionary.dsObjectName2Index]
            
            print(
                             "%d|%s|%s|%s|%s\n" % (
                                           dobj.RecordId,
                                           dsGetDSTimeStampStr(dobj.WhenCreated),
                                           dsGetDSTimeStampStr(dobj.WhenChanged),
                                           dobj.Name,
                                           origcname
                                           )
                             )
            if of != "":
                fdelobjs.writelines('\t'.join(dobj.Record))
                
if useID == True:
    for recid in dsMapLineIdByRecordId:
        print("\rExtracting deleted objects - %d%%" % (i*100/l))

        rec = dsGetRecordByLineId(db, dsMapLineIdByRecordId[recid])
        try:
            if int(rec[ntds.dsfielddictionary.dsIsDeletedIndex]) == 1: 
                delobjs.append(recid)
        except:
            pass
        i += 1
    print("\n")
    
    if of != "":
        fdelobjs.writelines('\t'.join(ntds.dsfielddictionary.dsFieldNameRecord))
    
    for did in delobjs:
        try:
            dobj = dsObject(db, did)
        except:
            print("\n[!] Unable to instantiate object (record id: %d)" % did)
            continue
        if dobj == None:
            continue
        
        origcname = ""
        if ntds.dsrecord.dsGetRecordByRecordId(
                db,
                dobj.Record[ntds.dsfielddictionary.dsOrigContainerIdIndex]
                ) != None:
            
            origcname = ntds.dsrecord.dsGetRecordByRecordId(
                            db,
                            dobj.Record[ntds.dsfielddictionary.dsOrigContainerIdIndex]
                            )[ntds.dsfielddictionary.dsObjectName2Index]
        
        print(
                         "\n%d|%s|%s|%s|%s" % (
                                       dobj.RecordId,
                                       dsGetDSTimeStampStr(dobj.WhenCreated),
                                       dsGetDSTimeStampStr(dobj.WhenChanged),
                                       dobj.Name,
                                       origcname
                                       )
                         )
        if of != "":
            fdelobjs.writelines('\t'.join(dobj.Record))
            
if of != "":
    fdelobjs.close()

print("\n")
